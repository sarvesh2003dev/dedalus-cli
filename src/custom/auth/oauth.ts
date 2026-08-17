import { createHash, randomBytes as nodeRandomBytes, timingSafeEqual } from 'node:crypto'
import { createServer, type Server } from 'node:http'

import {
  AuthProviderError,
  type AuthProvider,
  type AuthProviderErrorStage,
  type OAuthSession,
} from './types.js'

const callbackPath = '/callback'
const defaultLoginTimeoutMs = 10 * 60 * 1000
const maxAuthorizationCodeLength = 8 * 1024
const maxAuthorizationURLLength = 4 * 1024
const maxOAuthDisplayLength = 4 * 1024
const maxOAuthIdentifierLength = 1024
const maxOAuthResponseBytes = 512 * 1024
const maxOAuthScopeCount = 32
const maxOAuthScopeLength = 256
const maxOAuthTokenLength = 128 * 1024
const requestTimeoutMs = 30 * 1000
const oauthScopes = ['offline_access', 'user:org:read'] as const

export type ClerkOAuthErrorCode = string
export type ClerkOAuthErrorStage = AuthProviderErrorStage

export class ClerkOAuthError extends AuthProviderError {
  constructor(
    code: ClerkOAuthErrorCode,
    options: ErrorOptions & {
      readonly stage?: ClerkOAuthErrorStage
      readonly status?: number
    } = {},
  ) {
    super(code, options)
    this.name = 'ClerkOAuthError'
  }
}

export type ClerkOAuthOptions = {
  readonly issuer: string
  readonly clientId: string
  readonly signInURL?: string
  readonly timeoutMs?: number
}

export type ClerkOAuthDependencies = {
  readonly fetch?: typeof globalThis.fetch
  readonly now?: () => number
  readonly openBrowser?: (url: string) => Promise<void>
  readonly randomBytes?: (size: number) => Uint8Array
}

export type ClerkOAuthAttempt = {
  readonly authorizationURL: string
  readonly redirectURI: string
  readonly complete: () => Promise<OAuthSession>
  readonly cancel: () => Promise<void>
}

type OAuthCallback = {
  readonly code: string
}

type TokenSet = {
  readonly accessToken: string
  readonly accessTokenExpiresAt: number
  readonly refreshToken: string
  readonly grantedScopes: readonly string[]
}

type UserInfo = {
  readonly userId: string
  readonly organizationId: string
  readonly organizationName?: string
}

type UserInfoResponse = UserInfo & {
  readonly responseStatus: number
}

export const clerkPKCEChallenge = (verifier: string): string =>
  createHash('sha256').update(verifier, 'ascii').digest('base64url')

const validIssuer = (raw: string): URL => {
  try {
    if (raw.length > maxOAuthDisplayLength || raw !== raw.trim()) {
      throw new ClerkOAuthError('invalid_configuration')
    }
    const issuer = new URL(raw)
    if (
      issuer.protocol !== 'https:' ||
      issuer.username ||
      issuer.password ||
      issuer.search ||
      issuer.hash ||
      (issuer.pathname !== '/' && issuer.pathname !== '')
    ) {
      throw new ClerkOAuthError('invalid_configuration')
    }
    return issuer
  } catch (error) {
    if (error instanceof ClerkOAuthError) throw error
    throw new ClerkOAuthError('invalid_configuration', { cause: error })
  }
}

const validSignInURL = (raw: string): URL => {
  try {
    if (raw.length > maxOAuthDisplayLength || raw !== raw.trim()) {
      throw new ClerkOAuthError('invalid_configuration')
    }
    const signInURL = new URL(raw)
    const loopbackHTTP = signInURL.protocol === 'http:' &&
      (signInURL.hostname === '127.0.0.1' || signInURL.hostname === 'localhost')
    if (
      (signInURL.protocol !== 'https:' && !loopbackHTTP) ||
      signInURL.username ||
      signInURL.password ||
      signInURL.search ||
      signInURL.hash ||
      signInURL.pathname !== '/cli/sign-in'
    ) {
      throw new ClerkOAuthError('invalid_configuration')
    }
    return signInURL
  } catch (error) {
    if (error instanceof ClerkOAuthError) throw error
    throw new ClerkOAuthError('invalid_configuration', { cause: error })
  }
}

const wrappedAuthorizationURL = (signInURL: URL, authorizationURL: URL): URL => {
  const browserURL = new URL(signInURL)
  // Fragments are not sent in HTTP requests, access logs, or Referer headers.
  browserURL.hash = new URLSearchParams({ authorization_url: authorizationURL.toString() }).toString()
  return browserURL
}

const validClientId = (raw: string): string => {
  if (!opaqueValue(raw, maxOAuthIdentifierLength)) throw new ClerkOAuthError('invalid_configuration')
  return raw
}

const randomValue = (randomBytes: (size: number) => Uint8Array): string => {
  const value = randomBytes(32)
  if (value.byteLength !== 32) throw new ClerkOAuthError('invalid_configuration')
  return Buffer.from(value).toString('base64url')
}

const equalSecret = (actual: string, expected: string): boolean => {
  const actualBytes = Buffer.from(actual)
  const expectedBytes = Buffer.from(expected)
  return actualBytes.length === expectedBytes.length && timingSafeEqual(actualBytes, expectedBytes)
}

const listenOnLoopback = (server: Server): Promise<void> =>
  new Promise((resolve, reject) => {
    const onError = (error: Error) => reject(error)
    server.once('error', onError)
    server.listen(0, '127.0.0.1', () => {
      server.off('error', onError)
      resolve()
    })
  })

const closeServer = (server: Server): Promise<void> =>
  new Promise((resolve, reject) => {
    if (!server.listening) {
      resolve()
      return
    }
    server.close((error) => error ? reject(error) : resolve())
  })

const writeCallbackResponse = (
  response: import('node:http').ServerResponse,
  status: number,
  message: string,
): void => {
  response.writeHead(status, {
    'Cache-Control': 'no-store',
    'Content-Type': 'text/plain; charset=utf-8',
  })
  response.end(message)
}

const finishCallback = (
  server: Server,
  response: import('node:http').ServerResponse,
  status: number,
  message: string,
  onFinished: () => void,
  onAborted: () => void,
): void => {
  let complete = false
  const settle = (action: () => void): void => {
    if (complete) return
    complete = true
    response.off('finish', onFinish)
    response.off('close', onClose)
    response.off('error', onError)
    action()
    server.close()
  }
  const onFinish = (): void => settle(onFinished)
  const onClose = (): void => settle(onAborted)
  const onError = (): void => settle(onAborted)
  response.once('finish', onFinish)
  response.once('close', onClose)
  response.once('error', onError)
  writeCallbackResponse(response, status, message)
}

const jsonObject = async (response: Response): Promise<Record<string, unknown>> => {
  try {
    const raw = await boundedResponseText(response, maxOAuthResponseBytes)
    if (raw === undefined) return {}
    const payload: unknown = JSON.parse(raw)
    return payload !== null && typeof payload === 'object' && !Array.isArray(payload)
      ? payload as Record<string, unknown>
      : {}
  } catch {
    return {}
  }
}

const boundedResponseText = async (
  response: Response,
  maximumBytes: number,
): Promise<string | undefined> => {
  const contentLength = response.headers.get('content-length')
  if (contentLength !== null) {
    const parsed = Number(contentLength)
    if (Number.isFinite(parsed) && parsed > maximumBytes) {
      await response.body?.cancel().catch(() => undefined)
      return undefined
    }
  }
  if (!response.body) return ''

  const reader = response.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      total += value.byteLength
      if (total > maximumBytes) {
        await reader.cancel().catch(() => undefined)
        return undefined
      }
      chunks.push(value)
    }
  } finally {
    reader.releaseLock()
  }

  const bytes = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
}

const oauthHTTPError = (status: number, payload: Readonly<Record<string, unknown>>): ClerkOAuthError =>
  new ClerkOAuthError(
    typeof payload.error === 'string' ? oauthErrorCode(payload.error) : 'oauth_error',
    { stage: 'provider', status },
  )

const oauthErrorCode = (value: string): ClerkOAuthErrorCode => {
  if (!value || value.length > 256) return 'oauth_error'
  for (const character of value) {
    const code = character.charCodeAt(0)
    if (!((code >= 0x20 && code <= 0x21) || (code >= 0x23 && code <= 0x5b) || (code >= 0x5d && code <= 0x7e))) {
      return 'oauth_error'
    }
  }
  return value
}

const opaqueValue = (value: unknown, maximumLength: number = maxOAuthTokenLength): string => {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximumLength) return ''
  for (const character of value) {
    const code = character.charCodeAt(0)
    if (code < 0x21 || code > 0x7e) return ''
  }
  return value
}

const displayValue = (value: unknown): string =>
  typeof value === 'string' &&
  value.length > 0 &&
  value.length <= maxOAuthDisplayLength &&
  value === value.trim() &&
  !/[\u0000-\u001f\u007f-\u009f]/u.test(value)
    ? value
    : ''

const uniqueScopes = (value: string, responseStatus: number): readonly string[] => {
  if (value.length > maxOAuthScopeCount * (maxOAuthScopeLength + 1)) {
    throw new ClerkOAuthError('invalid_scope', { status: responseStatus })
  }
  const scopes = [...new Set(value.split(/\s+/).filter(Boolean))]
  if (
    scopes.length > maxOAuthScopeCount ||
    scopes.some((scope) => !opaqueValue(scope, maxOAuthScopeLength))
  ) {
    throw new ClerkOAuthError('invalid_scope', { status: responseStatus })
  }
  return scopes
}

const validateAccessTokenClaims = (
  accessToken: string,
  issuer: string,
  user: UserInfo,
  responseStatus: number,
): void => {
  const parts = accessToken.split('.')
  if (parts.length !== 3) return
  const header = jwtObject(parts[0] ?? '')
  if (!header || typeof header.alg !== 'string') return
  try {
    const raw = parts[1]
    if (!raw) throw new ClerkOAuthError('invalid_token_response', { status: responseStatus })
    const value: unknown = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'))
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new ClerkOAuthError('invalid_token_response', { status: responseStatus })
    }
    const claims = value as Record<string, unknown>
    if (typeof claims.iss === 'string') {
      try {
        if (validIssuer(claims.iss).origin !== issuer) {
          throw new ClerkOAuthError('issuer_mismatch', { status: responseStatus })
        }
      } catch {
        throw new ClerkOAuthError('issuer_mismatch', { status: responseStatus })
      }
    }
    if (typeof claims.sub === 'string' && claims.sub !== user.userId) {
      throw new ClerkOAuthError('userinfo_mismatch', { status: responseStatus })
    }
    if (typeof claims.org_id === 'string' && claims.org_id !== user.organizationId) {
      throw new ClerkOAuthError('userinfo_mismatch', { status: responseStatus })
    }
  } catch (error) {
    if (error instanceof ClerkOAuthError) throw error
    throw new ClerkOAuthError('invalid_token_response', { cause: error, status: responseStatus })
  }
}

const jwtObject = (value: string): Record<string, unknown> | undefined => {
  try {
    const decoded: unknown = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'))
    return decoded !== null && typeof decoded === 'object' && !Array.isArray(decoded)
      ? decoded as Record<string, unknown>
      : undefined
  } catch {
    return undefined
  }
}

const defaultOpenBrowser = async (url: string): Promise<void> => {
  const { default: open } = await import('open')
  await open(url)
}

const deferred = <T>(): {
  readonly promise: Promise<T>
  readonly resolve: (value: T) => void
  readonly reject: (error: unknown) => void
} => {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((onResolve, onReject) => {
    resolve = onResolve
    reject = onReject
  })
  return { promise, resolve, reject }
}
