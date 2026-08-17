import { Command } from 'commander'

import {
  CredentialStorageError,
  defaultCredentialStore,
  hasCredentialCustomHeader,
  type CredentialStore,
} from './auth/credentials.js'
import { createClerkAuthProvider } from './auth/oauth.js'
import { AuthProviderError, type AuthProvider } from './auth/types.js'
import {
  accessTokenForCommand,
  type AuthStatus,
  CLIAuthWorkflowError,
  login,
  type LoginResult,
  logout,
  type LogoutResult,
  selectedCredential,
  status,
} from './auth/workflow.js'

const authCommandName = 'auth'
const completionCommandName = 'completion'
const defaultClerkIssuer = 'https://neat-gator-21.clerk.accounts.dev'
const defaultClerkClientID = 'W27FJtdP5VDfKMTv'
const defaultSignInURL = 'https://dev.dedaluslabs.ai/cli/sign-in'
const developmentGatewayURL = 'https://dev.admin.api.dedaluslabs.ai/dcs'

type CredentialSource = 'environment' | 'flag' | 'none' | 'oauth_session'
type SelectedCredential = {
  readonly source: CredentialSource
  readonly label?: 'DEDALUS_API_KEY' | 'DEDALUS_X_API_KEY'
}

const credentialSources = new WeakMap<Command, SelectedCredential>()

type AuthOperations = {
  readonly login: () => Promise<LoginResult>
  readonly status: (
    flags: { readonly apiKey?: string; readonly bearerAuth?: string; readonly xApiKey?: string },
    offline: boolean,
  ) => Promise<AuthStatus>
  readonly logout: () => Promise<LogoutResult>
}

export type DedalusCommandOptions = {
  readonly auth?: () => AuthOperations
  readonly authProvider?: () => AuthProvider
  readonly credentialStore?: () => CredentialStore
  readonly environment?: Readonly<Record<string, string | undefined>>
  readonly writeOutput?: (value: string) => void
  readonly writeError?: (value: string) => void
}

// addDedalusCommands is the boundary between generated resource commands and
// Dedalus-owned authentication behavior. Scalar regeneration must preserve it.
export const addDedalusCommands = (
  program: Command,
  options: DedalusCommandOptions = {},
): Command => {
  if (program.commands.some((command) => command.name() === authCommandName)) {
    throw new Error(`Scalar generated the reserved '${authCommandName}' command`)
  }

  const environment = options.environment ?? process.env
  let stored: CredentialStore | undefined
  const credentialStore = options.credentialStore ?? (() => {
    stored ??= defaultCredentialStore({ environment })
    return stored
  })
  let configuredProvider: AuthProvider | undefined
  const authProvider = options.authProvider ?? (() => {
    configuredProvider ??= defaultAuthProvider(environment)
    return configuredProvider
  })
  const operations = options.auth ?? (() => defaultAuthOperations(
    environment,
    credentialStore,
    authProvider,
  ))
  const writeOutput = options.writeOutput ?? ((value) => process.stdout.write(value))
  const writeError = options.writeError ?? ((value) => process.stderr.write(value))
  installJSONConvenience(program)
  const auth = new Command(authCommandName).description('Manage the stored Dedalus CLI login')

  auth.command('login')
    .description('Sign in through Clerk and store the OAuth session')
    .option('--json', 'Print structured JSON output')
    .action(async (_commandOptions: unknown, command: Command) => runAuthAction(
      async () => loginOutput(await operations().login()),
      'oauth_session',
      jsonRequested(command),
      writeOutput,
      writeError,
    ))

  auth.command('status')
    .description('Show the active credential source without revealing secrets')
    .option('--api-key <value>', 'Inspect an explicit Bearer API-key override')
    .option('--x-api-key <value>', 'Inspect an explicit X-API-Key override')
    .option('--offline', 'Read stored session metadata without contacting Clerk')
    .option('--json', 'Print structured JSON output')
    .action(async (
      commandOptions: { readonly json?: boolean; readonly offline?: boolean },
      command: Command,
    ) => {
      const flags = command.optsWithGlobals<{
        readonly apiKey?: string
        readonly bearerAuth?: string
        readonly xApiKey?: string
      }>()
      return runAuthAction(
        async () => statusOutput(await operations().status(flags, Boolean(commandOptions.offline))),
        intendedCredential(flags, environment).source,
        jsonRequested(command),
        writeOutput,
        writeError,
      )
    })

  auth.command('logout')
    .description('Revoke the provider token when possible and remove local tokens')
    .option('--json', 'Print structured JSON output')
    .action(async (_commandOptions: unknown, command: Command) => runAuthAction(
      async () => logoutOutput(await operations().logout()),
      'oauth_session',
      jsonRequested(command),
      writeOutput,
      writeError,
    ))

  auth.action(() => auth.help())
  program.addCommand(auth)
  installCredentialInjection(program, environment, credentialStore, authProvider)
  return program
}

const installJSONConvenience = (program: Command): void => {
  if (!program.options.some((option) => option.long === '--json')) {
    program.option('--json', 'Print structured JSON output')
  }
  const visit = (command: Command): void => {
    if (
      command.options.some((option) => option.long === '--format') &&
      !command.options.some((option) => option.long === '--json')
    ) {
      command.option('--json', 'Print structured JSON output')
    }
    for (const child of command.commands) visit(child)
  }
  for (const command of program.commands) visit(command)

  program.hook('preAction', async (_root, action) => {
    if (belongsTo(action, authCommandName) || !jsonRequested(action)) return
    setCommandOption(action, 'format', 'json')
    setCommandOption(action, 'formatError', 'json')
  })
}

const jsonRequested = (command: Command): boolean =>
  Boolean(command.optsWithGlobals<{ readonly json?: boolean }>().json)

const defaultAuthProvider = (
  environment: Readonly<Record<string, string | undefined>>,
): AuthProvider => createClerkAuthProvider(cliAuthConfiguration(environment))

const defaultAuthOperations = (
  environment: Readonly<Record<string, string | undefined>>,
  store: () => CredentialStore,
  provider: () => AuthProvider,
): AuthOperations => ({
  login: () => login({ provider: provider(), store: store() }),
  status: (flags, offline) => status({ flags, environment }, store, provider, offline),
  logout: () => logout(store(), provider),
})

export const cliAuthConfiguration = (
  environment: Readonly<Record<string, string | undefined>>,
): {
  readonly issuer: string
  readonly clientId: string
  readonly signInURL: string
} => {
  const issuerOverride = environment.DEDALUS_CLERK_ISSUER
  const clientIDOverride = environment.DEDALUS_CLERK_CLIENT_ID
  if (
    (issuerOverride !== undefined && issuerOverride !== defaultClerkIssuer) ||
    (clientIDOverride !== undefined && clientIDOverride !== defaultClerkClientID)
  ) {
    throw new AuthProviderError('invalid_configuration')
  }
  const signInURL = cliSignInURL(environment.DEDALUS_SIGN_IN_URL ?? defaultSignInURL)
  return {
    issuer: defaultClerkIssuer,
    clientId: defaultClerkClientID,
    signInURL,
  }
}

const cliSignInURL = (raw: string): string => {
  if (raw === defaultSignInURL) return raw
  try {
    const value = new URL(raw)
    if (
      value.protocol !== 'http:' ||
      (value.hostname !== '127.0.0.1' && value.hostname !== 'localhost') ||
      value.username ||
      value.password ||
      value.search ||
      value.hash ||
      value.pathname !== '/cli/sign-in'
    ) {
      throw new AuthProviderError('invalid_configuration')
    }
    return value.toString()
  } catch (error) {
    if (error instanceof AuthProviderError) throw error
    throw new AuthProviderError('invalid_configuration', { cause: error })
  }
}

const installCredentialInjection = (
  program: Command,
  environment: Readonly<Record<string, string | undefined>>,
  credentialStore: () => CredentialStore,
  authProvider: () => AuthProvider,
): void => {
  program.hook('preAction', async (_root, action) => {
    if (belongsTo(action, authCommandName) || belongsTo(action, completionCommandName)) return
    const flags = action.optsWithGlobals<{
      readonly apiKey?: string
      readonly baseUrl?: string
      readonly bearerAuth?: string
      readonly xApiKey?: string
    }>()
    const intended = intendedCredential(flags, environment)
    credentialSources.set(action, intended)
    setCredentialOptions(action, null, null, null)

    try {
      const selected = await selectedCredential({ flags, environment }, credentialStore)
      if (!selected) {
        credentialSources.set(action, { source: 'none' })
        setCredentialOptions(
          action,
          null,
          null,
          rejectedCredential(new CredentialStorageError('not_logged_in')),
        )
        return
      }
      credentialSources.set(action, {
        source: selected.source,
        ...(selected.source === 'environment'
          ? { label: selected.transport === 'bearer' ? 'DEDALUS_API_KEY' : 'DEDALUS_X_API_KEY' }
          : {}),
      })
      if (selected.source === 'oauth_session') {
        const gatewayURL = cliOAuthGatewayURL(environment, flags.baseUrl)
        const accessToken = await accessTokenForCommand(credentialStore(), authProvider())
        setCommandOption(action, 'baseUrl', gatewayURL)
        setCredentialOptions(action, null, null, accessToken)
      } else if (selected.transport === 'bearer') {
        setCredentialOptions(action, selected.value, null, null)
      } else {
        setCredentialOptions(action, null, selected.value, null)
      }
    } catch (error) {
      setCredentialOptions(action, null, null, rejectedCredential(error))
    }
  })
}

export const cliOAuthGatewayURL = (
  environment: Readonly<Record<string, string | undefined>>,
  flagValue?: string,
): string => {
  const issuer = new URL(createClerkAuthProvider(cliAuthConfiguration(environment)).issuer)
  const developmentIssuer = issuer.hostname.endsWith('.clerk.accounts.dev')
  if (!developmentIssuer) throw new CredentialStorageError('environment_mismatch')
  const raw = flagValue ?? environment.DEDALUS_BASE_URL ?? developmentGatewayURL
  const gatewayURL = validHTTPSBaseURL(raw)
  if (new URL(gatewayURL).pathname !== '/dcs') {
    throw new CredentialStorageError('environment_mismatch')
  }
  if (gatewayURL !== developmentGatewayURL) {
    throw new CredentialStorageError('environment_mismatch')
  }
  return gatewayURL
}

const validHTTPSBaseURL = (raw: string): string => {
  try {
    if (raw !== raw.trim()) throw new CredentialStorageError('environment_mismatch')
    const value = new URL(raw)
    if (
      value.protocol !== 'https:' ||
      value.username ||
      value.password ||
      value.search ||
      value.hash ||
      !/^\/(?:[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*)?\/?$/u.test(value.pathname)
    ) {
      throw new CredentialStorageError('environment_mismatch')
    }
    const path = value.pathname === '/' ? '' : value.pathname.replace(/\/$/u, '')
    return value.origin + path
  } catch (error) {
    if (error instanceof CredentialStorageError) throw error
    throw new CredentialStorageError('environment_mismatch', { cause: error })
  }
}

const intendedCredential = (
  flags: { readonly apiKey?: string; readonly bearerAuth?: string; readonly xApiKey?: string },
  environment: Readonly<Record<string, string | undefined>>,
): SelectedCredential => {
  if (flags.apiKey !== undefined || flags.xApiKey !== undefined || flags.bearerAuth !== undefined) {
    return { source: 'flag' }
  }
  if (
    hasCredentialCustomHeader(environment.DEDALUS_CUSTOM_HEADERS) ||
    environment.DEDALUS_API_KEY !== undefined ||
    environment.DEDALUS_X_API_KEY !== undefined ||
    environment.DEDALUS_BEARER_AUTH !== undefined
  ) {
    return { source: 'environment' }
  }
  return { source: 'oauth_session' }
}

const setCredentialOptions = (
  action: Command,
  apiKey: unknown,
  xApiKey: unknown,
  bearerAuth: unknown,
): void => {
  let current: Command | null = action
  while (current) {
    current.setOptionValueWithSource('apiKey', apiKey, 'cli')
    current.setOptionValueWithSource('xApiKey', xApiKey, 'cli')
    current.setOptionValueWithSource('bearerAuth', bearerAuth, 'cli')
    current = current.parent
  }
}

const setCommandOption = (action: Command, name: string, value: unknown): void => {
  let current: Command | null = action
  while (current) {
    current.setOptionValueWithSource(name, value, 'cli')
    current = current.parent
  }
}

const rejectedCredential = (error: unknown): (() => never) => () => { throw error }

export const formatDedalusError = (
  error: unknown,
  command: Command,
): Record<string, unknown> | undefined => {
  const selected = credentialSources.get(command)
  if (
    error instanceof AuthProviderError ||
    error instanceof CredentialStorageError ||
    error instanceof CLIAuthWorkflowError
  ) {
    const safe = safeAuthError(error, selected?.source ?? 'none')
    return { error: safe }
  }

  if (!selected || !isSDKError(error)) return undefined
  if (selected.source === 'none') {
    return authError('cli_no_credential', "Not logged in. Run 'dedalus auth login'.", false, undefined, 'none')
  }

  const status = validHTTPStatus(error.status)
  if (status === undefined) {
    return authError(
      'cli_network_error',
      'Dedalus could not be reached. Check your connection and try again.',
      true,
      undefined,
      selected.source,
    )
  }

  const remoteCode = serverErrorCode(error.error)
  const code = remoteCode ?? defaultHTTPCode(status)
  const remoteRetryable = serverRetryable(error.error)
  return authError(
    code,
    remoteCode ? safeServerMessage(status) : defaultHTTPMessage(status, selected),
    remoteRetryable ?? (status === 408 || status === 429 || status >= 500),
    status,
    selected.source,
  )
}

const isSDKError = (error: unknown): error is { readonly status?: unknown; readonly error?: unknown } =>
  Boolean(error && typeof error === 'object' && 'status' in error && 'error' in error)

const validHTTPStatus = (value: unknown): number | undefined =>
  typeof value === 'number' && Number.isInteger(value) && value >= 100 && value <= 599
    ? value
    : undefined

const authError = (
  code: string,
  message: string,
  retryable: boolean,
  httpStatus?: number,
  source?: CredentialSource,
): Record<string, unknown> => ({
  error: {
    code,
    message,
    retryable,
    ...(httpStatus === undefined ? {} : { http_status: httpStatus }),
    ...(source === undefined ? {} : { credential_source: source }),
  },
})

const defaultHTTPCode = (status: number): string => {
  if (status === 401) return 'invalid_token'
  if (status === 403) return 'insufficient_scope'
  if (status === 429) return 'rate_limited'
  if (status >= 500) return 'server_error'
  return 'http_error'
}

const defaultHTTPMessage = (status: number, selected: SelectedCredential): string => {
  if (status === 401) return rejectedCredentialMessage(selected)
  return safeServerMessage(status)
}

const safeServerMessage = (status: number): string => {
  if (status === 403) return 'This credential does not have permission for that operation.'
  if (status === 404) return 'The requested resource was not found.'
  if (status === 408) return 'The request timed out. Try again.'
  if (status === 429) return 'Too many requests. Try again later.'
  if (status >= 500) return 'Dedalus is temporarily unavailable. Try again.'
  return 'Dedalus rejected the request.'
}

const rejectedCredentialMessage = (selected: SelectedCredential): string => {
  switch (selected.source) {
    case 'flag': return 'API key supplied by command-line flag was rejected.'
    case 'environment': return `API key from ${selected.label ?? 'the environment'} was rejected.`
    case 'oauth_session': return "Stored OAuth session is no longer valid. Run 'dedalus auth logout', then 'dedalus auth login'."
    case 'none': return "Not logged in. Run 'dedalus auth login'."
  }
}

const serverErrorCode = (body: unknown): string | undefined => {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return undefined
  const record = body as Record<string, unknown>
  if (typeof record.error_code === 'string') return safeExternalErrorCode(record.error_code)
  if (typeof record.code === 'string') return safeExternalErrorCode(record.code)
  if (typeof record.error === 'string') return safeExternalErrorCode(record.error)
  if (!record.error || typeof record.error !== 'object' || Array.isArray(record.error)) return undefined
  const nested = (record.error as Record<string, unknown>).code
  return typeof nested === 'string' ? safeExternalErrorCode(nested) : undefined
}

const safeExternalErrorCode = (value: string): string | undefined => {
  if (!value || value.length > 256) return undefined
  for (const character of value) {
    const code = character.charCodeAt(0)
    if (code < 0x20 || code > 0x7e) return undefined
  }
  return value
}

const serverRetryable = (body: unknown): boolean | undefined => {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return undefined
  const record = body as Record<string, unknown>
  if (typeof record.retryable === 'boolean') return record.retryable
  if (!record.error || typeof record.error !== 'object' || Array.isArray(record.error)) return undefined
  const nested = (record.error as Record<string, unknown>).retryable
  return typeof nested === 'boolean' ? nested : undefined
}

const belongsTo = (command: Command, parentName: string): boolean => {
  let current: Command | null = command
  while (current) {
    if (current.name() === parentName) return true
    current = current.parent
  }
  return false
}

type AuthOutput = {
  readonly message: string
  readonly value: Readonly<Record<string, unknown>>
}

const loginOutput = (result: LoginResult): AuthOutput => ({
  message: result.status === 'logged_in'
    ? `Logged in to organization ${result.session.organizationId}.`
    : `Already signed in to organization ${result.session.organizationId}.`,
  value: {
    status: result.status,
    credential_source: 'oauth_session',
    ...sessionOutput(result.session),
  },
})

const statusOutput = (result: AuthStatus): AuthOutput => {
  if (result.source === 'none') {
    return {
      message: "Not logged in. Run 'dedalus auth login'.",
      value: { status: 'not_logged_in', credential_source: 'none' },
    }
  }
  const loggedIn = result.source === 'oauth_session'
  return {
    message: loggedIn
      ? `Active credential source: oauth_session. Issuer: ${result.session.issuer}. User: ${result.session.userId}. Organization: ${result.session.organizationId}.`
      : `Credential configured from ${result.source}.`,
    value: {
      status: loggedIn ? 'logged_in' : 'configured',
      credential_source: result.source,
      ...(loggedIn
        ? { offline: result.offline, ...sessionOutput(result.session) }
        : {}),
    },
  }
}

const sessionOutput = (session: LoginResult['session']): Record<string, unknown> => ({
  issuer: session.issuer,
  user_id: session.userId,
  organization: {
    id: session.organizationId,
    ...(session.organizationName === undefined ? {} : { name: session.organizationName }),
  },
  access_token_expires_at: new Date(session.accessTokenExpiresAt).toISOString(),
})

const logoutOutput = (result: LogoutResult): AuthOutput => result.status === 'logged_out'
  ? {
      message: result.revocationConfirmed
        ? 'Logged out and provider revocation was confirmed.'
        : 'Logged out locally; provider revocation could not be confirmed.',
      value: {
        status: 'logged_out',
        local_tokens_removed: true,
        revocation_confirmed: result.revocationConfirmed,
      },
    }
  : {
      message: 'No stored OAuth login found.',
      value: {
        status: 'not_logged_in',
        local_tokens_removed: false,
        revocation_confirmed: false,
      },
    }

const runAuthAction = async (
  action: () => Promise<AuthOutput>,
  source: CredentialSource,
  json: boolean,
  writeOutput: (value: string) => void,
  writeError: (value: string) => void,
): Promise<void> => {
  try {
    const output = await action()
    writeOutput(`${json ? JSON.stringify(output.value) : output.message}\n`)
  } catch (error) {
    const safe = safeAuthError(error, source)
    writeError(`${json ? JSON.stringify({ error: safe }) : `${String(safe.code)}: ${String(safe.message)}`}\n`)
    process.exitCode = 1
  }
}

const safeAuthError = (
  error: unknown,
  source: CredentialSource = 'none',
): Readonly<Record<string, unknown>> => {
  if (error instanceof AuthProviderError) {
    const providerCode = safeExternalErrorCode(error.code) ?? 'oauth_error'
    const status = validHTTPStatus(error.status)
    const code = error.stage === 'provider'
      ? providerCode
      : error.stage === 'network'
        ? 'cli_network_error'
        : localProviderCode(providerCode)
    return {
      code,
      message: providerMessage(providerCode),
      retryable: error.stage === 'network' ||
        (error.stage === 'provider' && providerRetryable(providerCode)) ||
        (status !== undefined && status >= 500),
      ...(status === undefined ? {} : { http_status: status }),
      credential_source: 'oauth_session',
    }
  }
  if (error instanceof CredentialStorageError) {
    return {
      code: credentialStorageCode(error.code),
      message: credentialStorageMessage(error.code),
      retryable: false,
      credential_source: source,
    }
  }
  if (error instanceof CLIAuthWorkflowError) {
    return {
      code: error.code,
      message: workflowMessage(error.code),
      retryable: error.code === 'cli_credential_store_failed',
      credential_source: 'oauth_session',
    }
  }
  return {
    code: 'cli_authentication_failed',
    message: 'CLI authentication failed.',
    retryable: false,
    credential_source: source,
  }
}

const localProviderCode = (code: AuthProviderError['code']): string => {
  switch (code) {
    case 'token_exchange_failed':
    case 'refresh_failed':
    case 'userinfo_failed':
      return 'cli_network_error'
    case 'browser_open_failed':
    case 'callback_unavailable':
    case 'callback_response_failed':
    case 'invalid_callback':
    case 'invalid_configuration':
    case 'invalid_token_response':
    case 'invalid_userinfo_response':
    case 'issuer_mismatch':
    case 'login_cancelled':
    case 'login_timeout':
    case 'session_provider_mismatch':
    case 'state_mismatch':
    case 'userinfo_mismatch':
      return `cli_${code}`
    default:
      return `cli_${code}`
  }
}

const providerMessage = (code: AuthProviderError['code']): string => {
  switch (code) {
    case 'access_denied': return 'Login was canceled or denied.'
    case 'browser_open_failed': return 'Unable to open the browser for login.'
    case 'callback_unavailable': return 'Unable to start the local login callback.'
    case 'invalid_client':
    case 'invalid_configuration': return 'CLI authentication configuration is invalid.'
    case 'invalid_grant': return "Login expired or could not be verified. Run 'dedalus auth logout', then 'dedalus auth login'."
    case 'invalid_scope': return 'CLI login requested unsupported permissions.'
    case 'issuer_mismatch':
    case 'state_mismatch':
    case 'userinfo_mismatch': return "Login response could not be verified. Run 'dedalus auth login' again."
    case 'login_timeout': return 'Login timed out. Run the command again.'
    case 'server_error':
    case 'temporarily_unavailable': return 'Authentication is temporarily unavailable. Try again.'
    case 'token_exchange_failed':
    case 'refresh_failed':
    case 'userinfo_failed': return 'Authentication service is temporarily unavailable. Try again.'
    default: return "Login could not be completed. Run 'dedalus auth login' again."
  }
}

const providerRetryable = (code: AuthProviderError['code']): boolean => {
  switch (code) {
    case 'refresh_failed':
    case 'server_error':
    case 'temporarily_unavailable':
    case 'token_exchange_failed':
    case 'userinfo_failed':
      return true
    default:
      return false
  }
}

const credentialStorageCode = (code: CredentialStorageError['code']): string => {
  switch (code) {
    case 'not_logged_in': return 'cli_no_credential'
    case 'ambiguous_credential': return 'cli_ambiguous_credential'
    case 'environment_mismatch': return 'cli_auth_environment_mismatch'
    case 'unsupported_credential': return 'cli_unsupported_credential'
    case 'insecure_permissions': return 'cli_insecure_credential_permissions'
    case 'storage_unavailable': return 'cli_credential_store_unavailable'
    case 'invalid_configuration': return 'cli_invalid_credential_configuration'
    case 'invalid_credential': return 'cli_invalid_stored_credential'
  }
}

const credentialStorageMessage = (code: CredentialStorageError['code']): string => {
  switch (code) {
    case 'not_logged_in': return "Not logged in. Run 'dedalus auth login'."
    case 'ambiguous_credential': return 'More than one credential was supplied at the same priority.'
    case 'environment_mismatch': return 'OAuth login requires a matching Admin API gateway URL ending in /dcs.'
    case 'unsupported_credential': return 'Direct Bearer-token overrides are not supported; use a workload API key or stored login.'
    case 'insecure_permissions': return 'Stored credential permissions are not private.'
    case 'invalid_configuration': return 'Credential storage configuration is invalid.'
    case 'invalid_credential': return "The stored OAuth session is invalid. Run 'dedalus auth logout', then sign in again."
    case 'storage_unavailable': return 'Protected credential storage is unavailable.'
  }
}

const workflowMessage = (code: CLIAuthWorkflowError['code']): string => {
  switch (code) {
    case 'cli_credential_store_failed': return 'Authentication succeeded, but the CLI could not update local token storage.'
    case 'cli_session_identity_changed': return "The refreshed login changed identity or organization. Run 'dedalus auth logout', then sign in again."
    case 'cli_session_provider_mismatch': return "The stored login belongs to a different authentication provider. Run 'dedalus auth logout', then sign in again."
  }
}
