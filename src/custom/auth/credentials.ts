import { randomUUID } from 'node:crypto'
import { constants, type Stats } from 'node:fs'
import { type FileHandle, lstat, mkdir, open, rename, unlink } from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, isAbsolute, join } from 'node:path'
import lockfile from 'proper-lockfile'

import type { OAuthSession } from './types.js'

const credentialService = 'com.dedalus.cli'
const credentialAccount = 'default'
const maxCredentialFileBytes = 512 * 1024
const maxCredentialMetadataLength = 4 * 1024
const maxCredentialScopeCount = 32
const maxCredentialScopeLength = 256
const maxCredentialTokenLength = 128 * 1024

export type CredentialStorageErrorCode =
  | 'ambiguous_credential'
  | 'insecure_permissions'
  | 'environment_mismatch'
  | 'invalid_configuration'
  | 'invalid_credential'
  | 'not_logged_in'
  | 'storage_unavailable'
  | 'unsupported_credential'

export class CredentialStorageError extends Error {
  readonly code: CredentialStorageErrorCode

  constructor(code: CredentialStorageErrorCode, options?: ErrorOptions) {
    super(code, options)
    this.name = 'CredentialStorageError'
    this.code = code
  }
}

export type CredentialStore = {
  readonly backend: 'file' | 'keyring'
  readonly read: () => Promise<OAuthSession | null>
  readonly write: (session: OAuthSession) => Promise<void>
  readonly remove: () => Promise<boolean>
  readonly withLifecycleLock: <T>(operation: () => Promise<T>) => Promise<T>
}

export type ResolvedCredential = {
  readonly value: string
  readonly source: 'environment' | 'flag' | 'oauth_session'
  readonly transport: 'bearer' | 'x-api-key'
}

export type CredentialResolutionOptions = {
  readonly flags: {
    readonly apiKey?: string
    readonly bearerAuth?: string
    readonly xApiKey?: string
  }
  readonly environment?: Readonly<Record<string, string | undefined>>
  readonly storedAccessToken: () => Promise<string | null>
}

export type DefaultCredentialStoreOptions = {
  readonly environment?: Readonly<Record<string, string | undefined>>
  readonly platform?: NodeJS.Platform
  readonly credentialPath?: string
}

type KeyringEntry = {
  readonly getPassword: () => Promise<string | null | undefined>
  readonly setPassword: (password: string) => Promise<void>
  readonly deleteCredential: () => Promise<boolean>
}

type KeyringEntryFactory = () => Promise<KeyringEntry>

const lifecycleLockOptions = {
  realpath: false,
  retries: { retries: 120, factor: 1, minTimeout: 250, maxTimeout: 250 },
  stale: 15 * 60 * 1000,
  update: 30 * 1000,
} as const

const withLifecycleLock = async <T>(path: string, operation: () => Promise<T>): Promise<T> => {
  let release: () => Promise<void>
  try {
    release = await lockfile.lock(path, lifecycleLockOptions)
  } catch (error) {
    throw storageError(error)
  }

  try {
    return await operation()
  } finally {
    try {
      await release()
    } catch (error) {
      throw storageError(error)
    }
  }
}

export const resolveCredential = async (
  options: CredentialResolutionOptions,
): Promise<ResolvedCredential | null> => {
  const environment = options.environment ?? process.env
  if (hasCredentialCustomHeader(environment.DEDALUS_CUSTOM_HEADERS)) {
    throw new CredentialStorageError('unsupported_credential')
  }
  const flag = oneCredential([
    candidate(options.flags.apiKey, 'flag', 'bearer'),
    candidate(options.flags.xApiKey, 'flag', 'x-api-key'),
  ])
  if (flag && options.flags.bearerAuth !== undefined) {
    throw new CredentialStorageError('ambiguous_credential')
  }
  if (options.flags.bearerAuth !== undefined) {
    throw new CredentialStorageError('unsupported_credential')
  }
  if (flag) return flag

  const environmentCredential = oneCredential([
    candidate(environment.DEDALUS_API_KEY, 'environment', 'bearer'),
    candidate(environment.DEDALUS_X_API_KEY, 'environment', 'x-api-key'),
  ])
  if (environmentCredential && environment.DEDALUS_BEARER_AUTH !== undefined) {
    throw new CredentialStorageError('ambiguous_credential')
  }
  if (environment.DEDALUS_BEARER_AUTH !== undefined) {
    throw new CredentialStorageError('unsupported_credential')
  }
  if (environmentCredential) return environmentCredential

  const stored = await options.storedAccessToken()
  if (stored === null) return null
  return {
    value: validToken(stored),
    source: 'oauth_session',
    transport: 'bearer',
  }
}

const hasCredentialCustomHeader = (value: string | undefined): boolean => {
  if (value === undefined) return false
  return value.split('\n').some((line) => {
    const separator = line.indexOf(':')
    if (separator < 0) return false
    const name = line.slice(0, separator).trim().toLowerCase()
    return name === 'authorization' || name === 'x-api-key'
  })
}

export const defaultCredentialStore = (
  options: DefaultCredentialStoreOptions = {},
): CredentialStore => {
  const environment = options.environment ?? process.env
  const platform = options.platform ?? process.platform
  const backend = platformCredentialBackend(platform, environment)

  if (backend === 'keyring') return keyringCredentialStore()
  if (platform === 'win32') throw new CredentialStorageError('invalid_configuration')
  return fileCredentialStore(options.credentialPath ?? defaultCredentialPath(environment))
}

export const keyringCredentialStore = (
  entryFactory: KeyringEntryFactory = nativeKeyringEntry,
): CredentialStore => {
  const readState = async (): Promise<OAuthSession | null> => {
    try {
      const stored = await (await entryFactory()).getPassword()
      return stored === undefined || stored === null ? null : decodeOAuthSession(stored)
    } catch (error) {
      throw storageError(error)
    }
  }
  const writeState = async (session: OAuthSession): Promise<void> => {
    try {
      await (await entryFactory()).setPassword(JSON.stringify(storedOAuthSession(session)))
    } catch (error) {
      throw storageError(error)
    }
  }
  return {
    backend: 'keyring',
    read: readState,
    write: writeState,
    remove: async () => {
      try {
        return await (await entryFactory()).deleteCredential()
      } catch (error) {
        throw storageError(error)
      }
    },
    withLifecycleLock: (operation) => withLifecycleLock(keyringLifecycleLockPath(), operation),
  }
}

export const fileCredentialStore = (credentialPath: string): CredentialStore => {
  if (!isAbsolute(credentialPath)) throw new CredentialStorageError('invalid_configuration')
  const directory = dirname(credentialPath)

  return {
    backend: 'file',
    read: async () => readCredentialFile(directory, credentialPath),
    write: async (session) => writeCredentialFile(directory, credentialPath, session),
    remove: async () => removeCredentialFile(directory, credentialPath),
    withLifecycleLock: async (operation) => {
      await requirePrivateDirectory(directory, true)
      return withLifecycleLock(credentialPath, operation)
    },
  }
}

const keyringLifecycleLockPath = (): string => join(homedir(), '.dedalus-cli-credentials')

const readCredentialFile = async (directory: string, credentialPath: string): Promise<OAuthSession | null> => {
  try {
    await requirePrivateDirectory(directory, false)
    const handle = await open(credentialPath, constants.O_RDONLY | noFollowFlag())
    try {
      const metadata = await handle.stat()
      requirePrivateFile(metadata)
      if (metadata.size > maxCredentialFileBytes) {
        throw new CredentialStorageError('invalid_credential')
      }
      return decodeOAuthSession(await readCredential(handle))
    } finally {
      await handle.close()
    }
  } catch (error) {
    if (isMissing(error)) return null
    throw storageError(error)
  }
}

const readCredential = async (handle: FileHandle): Promise<string> => {
  const buffer = Buffer.allocUnsafe(maxCredentialFileBytes + 1)
  let offset = 0
  while (offset < buffer.byteLength) {
    const { bytesRead } = await handle.read(buffer, offset, buffer.byteLength - offset, null)
    if (bytesRead === 0) break
    offset += bytesRead
  }
  if (offset > maxCredentialFileBytes) throw new CredentialStorageError('invalid_credential')
  return buffer.subarray(0, offset).toString('utf8')
}

const writeCredentialFile = async (
  directory: string,
  credentialPath: string,
  session: OAuthSession,
): Promise<void> => {
  const temporaryPath = `${credentialPath}.${process.pid}.${randomUUID()}.tmp`
  try {
    await requirePrivateDirectory(directory, true)
    const temporary = await open(temporaryPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600)
    try {
      await temporary.writeFile(JSON.stringify(storedOAuthSession(session)), 'utf8')
      await temporary.sync()
    } finally {
      await temporary.close()
    }
    await rename(temporaryPath, credentialPath)
    await syncDirectory(directory)
  } catch (error) {
    await removeTemporaryFile(temporaryPath)
    throw storageError(error)
  }
}

const removeCredentialFile = async (directory: string, credentialPath: string): Promise<boolean> => {
  try {
    await requirePrivateDirectory(directory, false)
    const metadata = await lstat(credentialPath)
    requireOwnedRegularFile(metadata)
    await unlink(credentialPath)
    await syncDirectory(directory)
    return true
  } catch (error) {
    if (isMissing(error)) return false
    throw storageError(error)
  }
}

const requirePrivateDirectory = async (directory: string, create: boolean): Promise<void> => {
  if (create) await mkdir(directory, { recursive: true, mode: 0o700 })
  const metadata = await lstat(directory)
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || metadata.mode & 0o077) {
    throw new CredentialStorageError('insecure_permissions')
  }
  requireCurrentUser(metadata.uid)
}

const requirePrivateFile = (metadata: Stats): void => {
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.mode & 0o077) {
    throw new CredentialStorageError('insecure_permissions')
  }
  requireCurrentUser(metadata.uid)
}

const requireOwnedRegularFile = (metadata: Stats): void => {
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new CredentialStorageError('insecure_permissions')
  }
  requireCurrentUser(metadata.uid)
}

const requireCurrentUser = (owner: number): void => {
  const currentUser = process.getuid?.()
  if (currentUser !== undefined && owner !== currentUser) {
    throw new CredentialStorageError('insecure_permissions')
  }
}

const syncDirectory = async (directory: string): Promise<void> => {
  const handle = await open(directory, constants.O_RDONLY)
  try {
    await handle.sync()
  } finally {
    await handle.close()
  }
}

const removeTemporaryFile = async (path: string): Promise<void> => {
  try {
    await unlink(path)
  } catch (error) {
    if (!isMissing(error)) throw error
  }
}

const platformCredentialBackend = (
  platform: NodeJS.Platform,
  environment: Readonly<Record<string, string | undefined>>,
): CredentialStore['backend'] => {
  if (platform === 'darwin' || platform === 'win32') return 'keyring'
  if (platform === 'linux' && environment.DBUS_SESSION_BUS_ADDRESS) return 'keyring'
  return 'file'
}

const defaultCredentialPath = (
  environment: Readonly<Record<string, string | undefined>>,
): string => {
  const configHome = environment.XDG_CONFIG_HOME || join(homedir(), '.config')
  if (!isAbsolute(configHome)) throw new CredentialStorageError('invalid_configuration')
  return join(configHome, 'dedalus', 'credentials')
}

const nativeKeyringEntry = async (): Promise<KeyringEntry> => {
  try {
    const { AsyncEntry } = await import('@napi-rs/keyring')
    return new AsyncEntry(credentialService, credentialAccount)
  } catch (error) {
    throw new CredentialStorageError('storage_unavailable', { cause: error })
  }
}

const candidate = (
  value: string | undefined,
  source: ResolvedCredential['source'],
  transport: ResolvedCredential['transport'],
): ResolvedCredential | null => value === undefined
  ? null
  : { value: validToken(value), source, transport }

const oneCredential = (
  candidates: readonly (ResolvedCredential | null)[],
): ResolvedCredential | null => {
  const available = candidates.filter((value): value is ResolvedCredential => value !== null)
  if (available.length > 1) throw new CredentialStorageError('ambiguous_credential')
  return available[0] ?? null
}

const validToken = (value: string): string => {
  if (value.length > maxCredentialTokenLength || !isVisibleASCII(value)) {
    throw new CredentialStorageError('invalid_credential')
  }
  return value
}

const isVisibleASCII = (value: string): boolean => {
  if (!value) return false
  for (const character of value) {
    const code = character.charCodeAt(0)
    if (code < 0x21 || code > 0x7e) return false
  }
  return true
}

const storedOAuthSession = (session: OAuthSession): Record<string, unknown> => ({
  version: 1,
  issuer: validStoredIssuer(session.issuer),
  client_id: validIdentifier(session.clientId),
  access_token: validToken(session.accessToken),
  access_token_expires_at: validExpiry(session.accessTokenExpiresAt),
  refresh_token: validToken(session.refreshToken),
  user_id: validIdentifier(session.userId),
  org_id: validIdentifier(session.organizationId),
  ...(session.organizationName === undefined
    ? {}
    : { org_display_name: validMetadata(session.organizationName) }),
  granted_scopes: validScopes(session.grantedScopes),
  ...(session.providerSessionId === undefined
    ? {}
    : { provider_session_id: validIdentifier(session.providerSessionId) }),
})

const decodeOAuthSession = (raw: string): OAuthSession => {
  try {
    if (Buffer.byteLength(raw, 'utf8') > maxCredentialFileBytes) {
      throw new CredentialStorageError('invalid_credential')
    }
    const value: unknown = JSON.parse(raw)
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new CredentialStorageError('invalid_credential')
    }
    const record = value as Record<string, unknown>
    if (
      record.version !== 1 ||
      typeof record.issuer !== 'string' ||
      typeof record.client_id !== 'string' ||
      typeof record.access_token !== 'string' ||
      typeof record.access_token_expires_at !== 'number' ||
      typeof record.refresh_token !== 'string' ||
      typeof record.user_id !== 'string' ||
      typeof record.org_id !== 'string' ||
      !Array.isArray(record.granted_scopes) ||
      (record.org_display_name !== undefined && typeof record.org_display_name !== 'string') ||
      (record.provider_session_id !== undefined && typeof record.provider_session_id !== 'string')
    ) {
      throw new CredentialStorageError('invalid_credential')
    }
    const organizationName = record.org_display_name as string | undefined
    const providerSessionId = record.provider_session_id as string | undefined
    return {
      version: 1,
      issuer: validStoredIssuer(record.issuer),
      clientId: validIdentifier(record.client_id),
      accessToken: validToken(record.access_token),
      accessTokenExpiresAt: validExpiry(record.access_token_expires_at),
      refreshToken: validToken(record.refresh_token),
      userId: validIdentifier(record.user_id),
      organizationId: validIdentifier(record.org_id),
      ...(organizationName === undefined ? {} : { organizationName: validMetadata(organizationName) }),
      grantedScopes: validScopes(record.granted_scopes),
      ...(providerSessionId === undefined ? {} : { providerSessionId: validIdentifier(providerSessionId) }),
    }
  } catch (error) {
    if (error instanceof CredentialStorageError) throw error
    throw new CredentialStorageError('invalid_credential', { cause: error })
  }
}

const validStoredIssuer = (value: string): string => {
  try {
    if (value.length > maxCredentialMetadataLength) {
      throw new CredentialStorageError('invalid_credential')
    }
    const issuer = new URL(value)
    if (
      issuer.protocol !== 'https:' ||
      issuer.username ||
      issuer.password ||
      issuer.search ||
      issuer.hash ||
      (issuer.pathname !== '/' && issuer.pathname !== '')
    ) {
      throw new CredentialStorageError('invalid_credential')
    }
    return issuer.origin
  } catch (error) {
    if (error instanceof CredentialStorageError) throw error
    throw new CredentialStorageError('invalid_credential', { cause: error })
  }
}

const validIdentifier = (value: string): string => {
  if (value.length > maxCredentialMetadataLength) {
    throw new CredentialStorageError('invalid_credential')
  }
  return validToken(value)
}

const validExpiry = (value: number): number => {
  if (
    !Number.isSafeInteger(value) ||
    value <= 0 ||
    Number.isNaN(new Date(value).getTime())
  ) {
    throw new CredentialStorageError('invalid_credential')
  }
  return value
}

const validMetadata = (value: string): string => {
  if (
    !value ||
    value.length > maxCredentialMetadataLength ||
    value !== value.trim() ||
    /[\u0000-\u001f\u007f-\u009f]/u.test(value)
  ) {
    throw new CredentialStorageError('invalid_credential')
  }
  return value
}

const validScopes = (value: readonly unknown[]): readonly string[] => {
  if (
    value.length === 0 ||
    value.length > maxCredentialScopeCount ||
    value.some((scope) => typeof scope !== 'string')
  ) {
    throw new CredentialStorageError('invalid_credential')
  }
  const scopes = value.map((scope) => {
    const candidate = scope as string
    if (candidate.length > maxCredentialScopeLength) {
      throw new CredentialStorageError('invalid_credential')
    }
    return validToken(candidate)
  })
  if (new Set(scopes).size !== scopes.length) throw new CredentialStorageError('invalid_credential')
  return scopes
}

const storageError = (error: unknown): CredentialStorageError => error instanceof CredentialStorageError
  ? error
  : isSymlink(error)
    ? new CredentialStorageError('insecure_permissions', { cause: error })
    : new CredentialStorageError('storage_unavailable', { cause: error })

const isMissing = (error: unknown): boolean => error instanceof Error
  && 'code' in error
  && error.code === 'ENOENT'

const isSymlink = (error: unknown): boolean => error instanceof Error
  && 'code' in error
  && error.code === 'ELOOP'

const noFollowFlag = (): number => {
  const flag: unknown = constants.O_NOFOLLOW
  if (typeof flag !== 'number') throw new CredentialStorageError('storage_unavailable')
  return flag
}
