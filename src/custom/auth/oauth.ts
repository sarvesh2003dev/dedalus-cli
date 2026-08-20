/**
 * Clerk OAuth 2.0 Authorization Code flow for the Dedalus command-line interface.
 *
 * The flow uses Proof Key for Code Exchange (PKCE) and a one-use loopback
 * callback. It returns a provider-neutral session for storage and refresh.
 */

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

export const clerkPKCEChallenge = (verifier: string): string =>
  createHash('sha256').update(verifier, 'ascii').digest('base64url')

export const createClerkAuthProvider = (
  options: ClerkOAuthOptions,
  dependencies: ClerkOAuthDependencies = {},
): AuthProvider => {
  const issuer = validIssuer(options.issuer).origin
  const clientId = validClientId(options.clientId)
  const request = dependencies.fetch ?? globalThis.fetch
  const now = dependencies.now ?? Date.now

  return {
    issuer,
    clientId,
    login: async () => {
      const attempt = await beginClerkOAuth({ ...options, issuer, clientId }, dependencies)
      try {
        const openBrowser = dependencies.openBrowser ?? defaultOpenBrowser
        await openBrowser(attempt.authorizationURL)
      } catch (error) {
        await attempt.cancel()
        throw new ClerkOAuthError('browser_open_failed', { cause: error })
      }
      return attempt.complete()
    },
    refresh: async (session) => {
      requireProviderSession(session, issuer, clientId)
      const tokens = await requestTokenSet(
        new URL(issuer),
        new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: clientId,
          refresh_token: session.refreshToken,
        }),
        request,
        now,
        session.refreshToken,
        'refresh_failed',
      )
      return {
        ...session,
        accessToken: tokens.accessToken,
        accessTokenExpiresAt: tokens.accessTokenExpiresAt,
        refreshToken: tokens.refreshToken,
        grantedScopes: tokens.grantedScopes,
      }
    },
    revoke: async (session) => {
      requireProviderSession(session, issuer, clientId)
      let response: Response
      try {
        response = await request(new URL('/oauth/token/revoke', issuer), {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            client_id: clientId,
            token: session.refreshToken,
            token_type_hint: 'refresh_token',
          }),
          redirect: 'manual',
          signal: AbortSignal.timeout(requestTimeoutMs),
        })
      } catch {
        return false
      }
      return response.ok
    },
  }
}

export const beginClerkOAuth = async (
  options: ClerkOAuthOptions,
  dependencies: ClerkOAuthDependencies = {},
): Promise<ClerkOAuthAttempt> => {
  const issuer = validIssuer(options.issuer)
  const clientId = validClientId(options.clientId)
  const signInURL = options.signInURL === undefined ? undefined : validSignInURL(options.signInURL)
  const timeoutMs = options.timeoutMs ?? defaultLoginTimeoutMs
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new ClerkOAuthError('invalid_configuration')
  }

  const randomBytes = dependencies.randomBytes ?? nodeRandomBytes
  const verifier = randomValue(randomBytes)
  const state = randomValue(randomBytes)
  const callback = deferred<OAuthCallback>()
  // The browser may return before complete() attaches its handler.
  void callback.promise.catch(() => undefined)

  let settled = false
  let timer: ReturnType<typeof setTimeout> | undefined
  const server = createServer((request, response) => {
    const finish = (status: number, message: string, onFinished: () => void): void => {
      finishCallback(server, response, status, message, onFinished, () => {
        callback.reject(new ClerkOAuthError('callback_response_failed'))
      })
    }
    let url: URL
    try {
      url = new URL(request.url ?? '/', 'http://127.0.0.1')
    } catch {
      response.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' })
      response.end('Invalid request')
      return
    }
    if (request.method !== 'GET' || url.pathname !== callbackPath) {
      response.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' })
      response.end('Not found')
      return
    }
    if (settled) {
      response.writeHead(410, { 'Content-Type': 'text/plain; charset=utf-8' })
      response.end('Login attempt is already complete')
      return
    }

    const returnedStates = url.searchParams.getAll('state')
    if (returnedStates.length !== 1 || !equalSecret(returnedStates[0] ?? '', state)) {
      writeCallbackResponse(response, 400, 'Login response could not be verified')
      return
    }

    const returnedIssuers = url.searchParams.getAll('iss')
    if (returnedIssuers.length !== 1 || returnedIssuers[0] !== issuer.origin) {
      settled = true
      if (timer !== undefined) clearTimeout(timer)
      finish(400, 'Login response could not be verified', () => {
        callback.reject(new ClerkOAuthError('issuer_mismatch'))
      })
      return
    }

    settled = true
    if (timer !== undefined) clearTimeout(timer)

    const providerErrors = url.searchParams.getAll('error')
    const codes = url.searchParams.getAll('code')
    if (providerErrors.length > 0 && codes.length > 0) {
      finish(400, 'Login response was incomplete', () => {
        callback.reject(new ClerkOAuthError('invalid_callback'))
      })
      return
    }
    if (providerErrors.length === 1) {
      finish(400, 'Login was not completed', () => {
        callback.reject(new ClerkOAuthError(
          oauthErrorCode(providerErrors[0] ?? ''),
          { stage: 'provider' },
        ))
      })
      return
    }

    const code = opaqueValue(codes[0], maxAuthorizationCodeLength)
    if (providerErrors.length > 1 || codes.length !== 1 || !code) {
      finish(400, 'Login response was incomplete', () => {
        callback.reject(new ClerkOAuthError('invalid_callback'))
      })
      return
    }

    finish(200, 'Dedalus CLI login received. You can close this window.', () => {
      callback.resolve({ code })
    })
  })

  try {
    await listenOnLoopback(server)
  } catch (error) {
    throw new ClerkOAuthError('callback_unavailable', { cause: error })
  }

  const address = server.address()
  if (!address || typeof address === 'string') {
    await closeServer(server)
    throw new ClerkOAuthError('callback_unavailable')
  }
  const redirectURI = `http://127.0.0.1:${address.port}${callbackPath}`
  const authorizationURL = new URL('/oauth/authorize', issuer)
  authorizationURL.search = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectURI,
    code_challenge: clerkPKCEChallenge(verifier),
    code_challenge_method: 'S256',
    state,
    scope: oauthScopes.join(' '),
  }).toString()
  if (authorizationURL.toString().length > maxAuthorizationURLLength) {
    await closeServer(server)
    throw new ClerkOAuthError('invalid_configuration')
  }
  const browserURL = signInURL === undefined
    ? authorizationURL
    : wrappedAuthorizationURL(signInURL, authorizationURL)

  timer = setTimeout(() => {
    if (settled) return
    settled = true
    callback.reject(new ClerkOAuthError('login_timeout'))
    void closeServer(server).catch(() => undefined)
  }, timeoutMs)
  timer.unref()

  let completion: Promise<OAuthSession> | undefined
  return {
    authorizationURL: browserURL.toString(),
    redirectURI,
    complete: () => {
      completion ??= callback.promise.then(async ({ code }) => {
        const request = dependencies.fetch ?? globalThis.fetch
        const tokens = await requestTokenSet(
          issuer,
          new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: clientId,
            code,
            redirect_uri: redirectURI,
            code_verifier: verifier,
          }),
          request,
          dependencies.now ?? Date.now,
          undefined,
          'token_exchange_failed',
        )
        const user = await fetchUserInfo(issuer, tokens.accessToken, request)
        return sessionFrom(issuer.origin, clientId, tokens, user)
      })
      return completion
    },
    cancel: async () => {
      if (!settled) {
        settled = true
        callback.reject(new ClerkOAuthError('login_cancelled'))
      }
      if (timer !== undefined) clearTimeout(timer)
      await closeServer(server)
    },
  }
}

const requestTokenSet = async (
  issuer: URL,
  body: URLSearchParams,
  request: typeof globalThis.fetch,
  now: () => number,
  previousRefreshToken: string | undefined,
  networkErrorCode: string,
): Promise<TokenSet> => {
  let response: Response
  try {
    response = await request(new URL('/oauth/token', issuer), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      redirect: 'manual',
      signal: AbortSignal.timeout(requestTimeoutMs),
    })
  } catch (error) {
    throw new ClerkOAuthError(networkErrorCode, { cause: error, stage: 'network' })
  }

  const payload = await jsonObject(response)
  if (!response.ok) throw oauthHTTPError(response.status, payload)

  const accessToken = opaqueValue(payload.access_token, maxOAuthTokenLength)
  const returnedRefreshToken = opaqueValue(payload.refresh_token, maxOAuthTokenLength)
  if (payload.refresh_token !== undefined && !returnedRefreshToken) {
    throw new ClerkOAuthError('invalid_token_response', { status: response.status })
  }
  const refreshToken = returnedRefreshToken || previousRefreshToken
  const tokenType = opaqueValue(payload.token_type, 32).toLowerCase()
  const expiresIn = payload.expires_in
  if (
    !accessToken ||
    !refreshToken ||
    tokenType !== 'bearer' ||
    typeof expiresIn !== 'number' ||
    !Number.isSafeInteger(expiresIn) ||
    expiresIn <= 0
  ) {
    throw new ClerkOAuthError('invalid_token_response', { status: response.status })
  }

  if (payload.scope !== undefined && typeof payload.scope !== 'string') {
    throw new ClerkOAuthError('invalid_scope', { status: response.status })
  }
  const grantedScopes = payload.scope === undefined
    ? [...oauthScopes]
    : uniqueScopes(payload.scope, response.status)
  if (
    grantedScopes.length !== oauthScopes.length ||
    oauthScopes.some((scope) => !grantedScopes.includes(scope))
  ) {
    throw new ClerkOAuthError('invalid_scope', { status: response.status })
  }
  const issuedAt = now()
  const accessTokenExpiresAt = issuedAt + expiresIn * 1000
  if (
    !Number.isSafeInteger(issuedAt) ||
    issuedAt < 0 ||
    !Number.isSafeInteger(accessTokenExpiresAt) ||
    accessTokenExpiresAt <= issuedAt ||
    Number.isNaN(new Date(accessTokenExpiresAt).getTime())
  ) {
    throw new ClerkOAuthError('invalid_token_response', { status: response.status })
  }
  return {
    accessToken,
    accessTokenExpiresAt,
    refreshToken,
    grantedScopes,
  }
}

const fetchUserInfo = async (
  issuer: URL,
  accessToken: string,
  request: typeof globalThis.fetch,
): Promise<UserInfo> => {
  let response: Response
  try {
    response = await request(new URL('/oauth/userinfo', issuer), {
      headers: { Authorization: `Bearer ${accessToken}` },
      redirect: 'manual',
      signal: AbortSignal.timeout(requestTimeoutMs),
    })
  } catch (error) {
    throw new ClerkOAuthError('userinfo_failed', { cause: error, stage: 'network' })
  }
  const payload = await jsonObject(response)
  if (!response.ok) throw oauthHTTPError(response.status, payload)

  const userId = opaqueValue(payload.sub, maxOAuthIdentifierLength)
  const organizationId = opaqueValue(payload.org_id, maxOAuthIdentifierLength)
  const organizationName = displayValue(payload.org_name)
  if (!userId || !organizationId) {
    throw new ClerkOAuthError('invalid_userinfo_response', { status: response.status })
  }
  return {
    userId,
    organizationId,
    ...(organizationName ? { organizationName } : {}),
  }
}

const sessionFrom = (
  issuer: string,
  clientId: string,
  tokens: TokenSet,
  user: UserInfo,
  providerSessionId?: string,
): OAuthSession => ({
  version: 1,
  issuer,
  clientId,
  accessToken: tokens.accessToken,
  accessTokenExpiresAt: tokens.accessTokenExpiresAt,
  refreshToken: tokens.refreshToken,
  userId: user.userId,
  organizationId: user.organizationId,
  ...(user.organizationName === undefined ? {} : { organizationName: user.organizationName }),
  grantedScopes: tokens.grantedScopes,
  ...(providerSessionId === undefined ? {} : { providerSessionId }),
})

const requireProviderSession = (session: OAuthSession, issuer: string, clientId: string): void => {
  if (session.issuer !== issuer || session.clientId !== clientId) {
    throw new ClerkOAuthError('session_provider_mismatch')
  }
}

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
