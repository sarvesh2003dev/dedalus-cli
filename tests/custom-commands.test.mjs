import assert from 'node:assert/strict'
import test from 'node:test'

import { Command } from 'commander'

import {
  addDedalusCommands,
  cliAuthConfiguration,
  cliOAuthGatewayURL,
  formatDedalusError,
} from '../dist/esm/custom/commands.js'
import { AuthProviderError } from '../dist/esm/custom/auth/types.js'
import { getProgram } from '../dist/esm/index.js'

const session = (overrides = {}) => ({
  version: 1,
  issuer: 'https://clerk.example.com',
  clientId: 'client_cli',
  accessToken: 'oauth-access-token',
  accessTokenExpiresAt: 2_000_000_000_000,
  refreshToken: 'oauth-refresh-token',
  userId: 'user_cli',
  organizationId: 'org_cli',
  organizationName: 'Dedalus Labs',
  grantedScopes: ['offline_access', 'user:org:read'],
  ...overrides,
})

const metadata = {
  issuer: 'https://clerk.example.com',
  clientId: 'client_cli',
  accessTokenExpiresAt: 2_000_000_000_000,
  userId: 'user_cli',
  organizationId: 'org_cli',
  organizationName: 'Dedalus Labs',
  grantedScopes: ['offline_access', 'user:org:read'],
}

const store = (value = session()) => ({
  backend: 'file',
  read: async () => value,
  write: async () => {},
  remove: async () => true,
  withLifecycleLock: async (operation) => operation(),
})

const provider = (overrides = {}) => ({
  issuer: 'https://clerk.example.com',
  clientId: 'client_cli',
  login: async () => session(),
  refresh: async (value) => value,
  revoke: async () => true,
  ...overrides,
})

const resourceProgram = (onAction) => new Command()
  .option('--base-url <value>')
  .option('--api-key <value>')
  .option('--x-api-key <value>')
  .option('--bearer-auth <value>')
  .option('--format <value>', '', 'auto')
  .option('--format-error <value>', '', 'auto')
  .addCommand(new Command('machines')
    .option('--api-key <value>')
    .option('--x-api-key <value>')
    .option('--bearer-auth <value>')
    .option('--format <value>')
    .option('--format-error <value>')
    .action((...args) => onAction(args.at(-1))))

test('invariant Dedalus custom commands share the generated program', () => {
  const program = getProgram()
  const auth = program.commands.find((command) => command.name() === 'auth')

  assert.ok(auth, 'custom auth command is missing')
  assert.equal(auth.description(), 'Manage the stored Dedalus CLI login')
  assert.ok(program.commands.some((command) => command.name() === 'completion'), 'generated completion command is missing')
})

test('invariant generated commands cannot shadow Dedalus commands', () => {
  const program = new Command().addCommand(new Command('auth'))
  assert.throws(() => addDedalusCommands(program), /Scalar generated the reserved 'auth' command/u)
})

test('invariant V1 configuration contains only the Clerk public-client bundle', () => {
  assert.deepEqual(cliAuthConfiguration({}), {
    issuer: 'https://neat-gator-21.clerk.accounts.dev',
    clientId: 'W27FJtdP5VDfKMTv',
    signInURL: 'https://dev.dedaluslabs.ai/cli/sign-in',
  })
  assert.deepEqual(cliAuthConfiguration({
    DEDALUS_SIGN_IN_URL: 'http://127.0.0.1:3000/cli/sign-in',
  }), {
    issuer: 'https://neat-gator-21.clerk.accounts.dev',
    clientId: 'W27FJtdP5VDfKMTv',
    signInURL: 'http://127.0.0.1:3000/cli/sign-in',
  })
  assert.throws(
    () => cliAuthConfiguration({ DEDALUS_SIGN_IN_URL: 'https://website.example.test/cli/sign-in' }),
    (error) => error instanceof AuthProviderError && error.code === 'invalid_configuration',
  )
  assert.throws(
    () => cliAuthConfiguration({
      DEDALUS_CLERK_ISSUER: 'https://clerk.example.test',
      DEDALUS_CLERK_CLIENT_ID: 'client_test',
    }),
    (error) => error instanceof AuthProviderError && error.code === 'invalid_configuration',
  )
})

test('invariant a development Clerk token uses only the Admin gateway route', () => {
  assert.equal(cliOAuthGatewayURL({}), 'https://dev.admin.api.dedaluslabs.ai/dcs')
  assert.throws(
    () => cliOAuthGatewayURL({ DEDALUS_BASE_URL: 'https://api.dedaluslabs.ai' }),
    (error) => error instanceof Error && error.code === 'environment_mismatch',
  )
  assert.throws(
    () => cliOAuthGatewayURL({ DEDALUS_BASE_URL: 'https://dev.dcs.dedaluslabs.ai' }),
    (error) => error instanceof Error && error.code === 'environment_mismatch',
  )
  assert.equal(
    cliOAuthGatewayURL({ DEDALUS_BASE_URL: 'https://dev.admin.api.dedaluslabs.ai/dcs/' }),
    'https://dev.admin.api.dedaluslabs.ai/dcs',
  )
  assert.throws(
    () => cliOAuthGatewayURL({
      DEDALUS_CLERK_ISSUER: 'not-a-url',
      DEDALUS_CLERK_CLIENT_ID: 'client_test',
      DEDALUS_BASE_URL: 'https://gateway.example.test',
    }),
    (error) => error instanceof AuthProviderError && error.code === 'invalid_configuration',
  )
})

test('invariant an unconfigured Clerk issuer cannot select a gateway', () => {
  const environment = {
    DEDALUS_CLERK_ISSUER: 'https://clerk.example.test',
    DEDALUS_CLERK_CLIENT_ID: 'client_test',
  }
  assert.throws(
    () => cliOAuthGatewayURL({
      ...environment,
      DEDALUS_BASE_URL: 'https://admin.example.test/dcs/',
    }),
    (error) => error instanceof AuthProviderError && error.code === 'invalid_configuration',
  )
  assert.throws(
    () => cliOAuthGatewayURL({
      ...environment,
      DEDALUS_BASE_URL: 'https://admin.example.test/dcs/v1',
    }),
    (error) => error instanceof AuthProviderError && error.code === 'invalid_configuration',
  )
})

test('invariant generated commands receive stored OAuth only as bearerAuth', async () => {
  let options
  const program = resourceProgram((command) => { options = command.optsWithGlobals() })
  addDedalusCommands(program, {
    environment: { DEDALUS_BASE_URL: 'https://dev.admin.api.dedaluslabs.ai/dcs' },
    credentialStore: () => store(),
    authProvider: () => provider(),
  })

  await program.parseAsync(['node', 'dedalus', 'machines'])
  assert.equal(options.apiKey, null)
  assert.equal(options.xApiKey, null)
  assert.equal(options.bearerAuth, 'oauth-access-token')
  assert.equal(options.baseUrl, 'https://dev.admin.api.dedaluslabs.ai/dcs')
})

test('invariant workload API keys use the generated API-key transport', async () => {
  let options
  const program = resourceProgram((command) => { options = command.optsWithGlobals() })
  addDedalusCommands(program, { environment: {} })

  await program.parseAsync(['node', 'dedalus', 'machines', '--api-key', 'workload-key'])

  assert.equal(options.apiKey, 'workload-key')
  assert.equal(options.xApiKey, null)
  assert.equal(options.bearerAuth, null)
})

test('invariant JSON convenience remains in Dedalus-owned custom code', async () => {
  let options
  const program = resourceProgram((command) => { options = command.optsWithGlobals() })
  addDedalusCommands(program, {
    environment: { DEDALUS_API_KEY: 'workload-key' },
  })

  await program.parseAsync(['node', 'dedalus', 'machines', '--json'])

  assert.equal(options.json, true)
  assert.equal(options.format, 'json')
  assert.equal(options.formatError, 'json')
})

test('invariant an explicit workload key prevents OAuth reads and refresh', async () => {
  let reads = 0
  let refreshes = 0
  let options
  const program = resourceProgram((command) => { options = command.optsWithGlobals() })
  addDedalusCommands(program, {
    environment: { DEDALUS_API_KEY: 'environment-key' },
    credentialStore: () => ({
      ...store(),
      read: async () => { reads += 1; return session() },
    }),
    authProvider: () => provider({ refresh: async (value) => { refreshes += 1; return value } }),
  })

  await program.parseAsync(['node', 'dedalus', '--x-api-key', 'flag-key', 'machines'])
  assert.equal(options.apiKey, null)
  assert.equal(options.xApiKey, 'flag-key')
  assert.equal(options.bearerAuth, null)
  assert.equal(reads, 0)
  assert.equal(refreshes, 0)
})

test('invariant workload flags do not construct a lower-priority credential store', async () => {
  let options
  const program = resourceProgram((command) => { options = command.optsWithGlobals() })
  addDedalusCommands(program, {
    credentialStore: () => { throw new Error('must not construct credential store') },
  })

  await program.parseAsync(['node', 'dedalus', '--api-key', 'flag-key', 'machines'])

  assert.equal(options.apiKey, 'flag-key')
  assert.equal(options.xApiKey, null)
  assert.equal(options.bearerAuth, null)
})

test('invariant workload environment keys do not construct a lower-priority credential store', async () => {
  let options
  const program = resourceProgram((command) => { options = command.optsWithGlobals() })
  addDedalusCommands(program, {
    credentialStore: () => { throw new Error('must not construct credential store') },
    environment: { DEDALUS_API_KEY: 'environment-key' },
  })

  await program.parseAsync(['node', 'dedalus', 'machines'])

  assert.equal(options.apiKey, 'environment-key')
  assert.equal(options.xApiKey, null)
  assert.equal(options.bearerAuth, null)
})

test('invariant a workload flag ignores a lower-priority Bearer environment override', async () => {
  let options
  let reads = 0
  const program = resourceProgram((command) => { options = command.optsWithGlobals() })
  addDedalusCommands(program, {
    environment: { DEDALUS_BEARER_AUTH: 'unsupported-lower-priority-token' },
    credentialStore: () => ({
      ...store(),
      read: async () => { reads += 1; return session() },
    }),
  })

  await program.parseAsync(['node', 'dedalus', '--api-key', 'flag-key', 'machines'])

  assert.equal(options.apiKey, 'flag-key')
  assert.equal(options.bearerAuth, null)
  assert.equal(reads, 0)
})

test('invariant generated commands receive exactly one workload credential', async () => {
  let options
  let actionCommand
  const program = resourceProgram((command) => {
    actionCommand = command
    options = command.optsWithGlobals()
  })
  addDedalusCommands(program, { environment: {} })

  await program.parseAsync([
    'node', 'dedalus', '--api-key', 'first-key', '--x-api-key', 'second-key', 'machines',
  ])

  let error
  assert.throws(() => { try { options.bearerAuth() } catch (caught) { error = caught; throw caught } }, (caught) =>
    caught instanceof Error && caught.code === 'ambiguous_credential')
  assert.equal(formatDedalusError(error, actionCommand).error.credential_source, 'flag')
  assert.equal(options.apiKey, null)
  assert.equal(options.xApiKey, null)
})

test('invariant direct Bearer overrides cannot bypass OAuth selection', async () => {
  let options
  const program = resourceProgram((command) => { options = command.optsWithGlobals() })
  addDedalusCommands(program, { environment: {} })

  await program.parseAsync(['node', 'dedalus', '--bearer-auth', 'bypass-token', 'machines'])

  assert.throws(options.bearerAuth, (error) =>
    error instanceof Error && error.code === 'unsupported_credential')
  assert.equal(options.apiKey, null)
  assert.equal(options.xApiKey, null)
})

test('invariant auth status JSON exposes source metadata without secrets', async () => {
  let output = ''
  let offline
  const program = new Command()
  addDedalusCommands(program, {
    auth: () => ({
      login: async () => { throw new Error('unused') },
      status: async (_flags, value) => { offline = value; return { source: 'oauth_session', offline: value, session: metadata } },
      logout: async () => ({ status: 'not_logged_in', revocationConfirmed: false }),
    }),
    writeOutput: (value) => { output += value },
  })

  await program.parseAsync(['node', 'dedalus', 'auth', 'status', '--offline', '--json'])

  assert.deepEqual(JSON.parse(output), {
    status: 'logged_in',
    credential_source: 'oauth_session',
    offline: true,
    issuer: 'https://clerk.example.com',
    user_id: 'user_cli',
    organization: { id: 'org_cli', name: 'Dedalus Labs' },
    access_token_expires_at: new Date(2_000_000_000_000).toISOString(),
  })
  assert.equal(offline, true)
  assert.equal(output.includes('oauth-access-token'), false)
  assert.equal(output.includes('oauth-refresh-token'), false)
})

test('invariant auth status does not inspect a lower-priority Bearer environment override', async () => {
  let output = ''
  let reads = 0
  const program = new Command()
  addDedalusCommands(program, {
    environment: { DEDALUS_BEARER_AUTH: 'unsupported-lower-priority-token' },
    credentialStore: () => ({
      ...store(),
      read: async () => { reads += 1; return session() },
    }),
    writeOutput: (value) => { output += value },
  })

  await program.parseAsync(['node', 'dedalus', 'auth', 'status', '--api-key', 'flag-key', '--json'])

  assert.deepEqual(JSON.parse(output), { status: 'configured', credential_source: 'flag' })
  assert.equal(reads, 0)
})

test('invariant workload-key status does not construct a lower-priority OAuth provider', async () => {
  let output = ''
  let providerCalls = 0
  const program = new Command()
  addDedalusCommands(program, {
    environment: { DEDALUS_CLERK_ISSUER: 'invalid-unpaired-override' },
    authProvider: () => {
      providerCalls += 1
      throw new Error('must not construct provider')
    },
    writeOutput: (value) => { output += value },
  })

  await program.parseAsync(['node', 'dedalus', 'auth', 'status', '--api-key', 'flag-key', '--json'])

  assert.deepEqual(JSON.parse(output), { status: 'configured', credential_source: 'flag' })
  assert.equal(providerCalls, 0)
})

test('invariant environment-key status does not construct a lower-priority credential store', async () => {
  let output = ''
  const program = new Command()
  addDedalusCommands(program, {
    credentialStore: () => { throw new Error('must not construct credential store') },
    environment: { DEDALUS_API_KEY: 'environment-key' },
    writeOutput: (value) => { output += value },
  })

  await program.parseAsync(['node', 'dedalus', 'auth', 'status', '--json'])

  assert.deepEqual(JSON.parse(output), { status: 'configured', credential_source: 'environment' })
})

test('invariant workload-key human status reports configuration without claiming authentication', async () => {
  let output = ''
  const program = new Command()
  addDedalusCommands(program, {
    environment: { DEDALUS_API_KEY: 'environment-key' },
    writeOutput: (value) => { output += value },
  })

  await program.parseAsync(['node', 'dedalus', 'auth', 'status'])

  assert.equal(output, 'Credential configured from environment.\n')
})

test('invariant OAuth human status identifies the active principal', async () => {
  let output = ''
  const program = new Command()
  addDedalusCommands(program, {
    auth: () => ({
      login: async () => ({ status: 'already_signed_in', session: metadata }),
      status: async () => ({ source: 'oauth_session', offline: false, session: metadata }),
      logout: async () => ({ status: 'not_logged_in', revocationConfirmed: false }),
    }),
    writeOutput: (value) => { output += value },
  })

  await program.parseAsync(['node', 'dedalus', 'auth', 'status'])

  assert.equal(
    output,
    'Active credential source: oauth_session. Issuer: https://clerk.example.com. User: user_cli. Organization: org_cli.\n',
  )
})

test('invariant offline status is independent of current provider configuration', async () => {
  let output = ''
  let providerCalls = 0
  const program = new Command()
  addDedalusCommands(program, {
    environment: { DEDALUS_CLERK_ISSUER: 'invalid-unpaired-override' },
    credentialStore: () => store(),
    authProvider: () => {
      providerCalls += 1
      throw new Error('must not construct provider')
    },
    writeOutput: (value) => { output += value },
  })

  await program.parseAsync(['node', 'dedalus', 'auth', 'status', '--offline', '--json'])

  assert.equal(JSON.parse(output).credential_source, 'oauth_session')
  assert.equal(JSON.parse(output).offline, true)
  assert.equal(providerCalls, 0)
})

test('invariant root JSON override also applies to auth commands', async () => {
  let output = ''
  const program = new Command()
  addDedalusCommands(program, {
    auth: () => ({
      login: async () => ({ status: 'already_signed_in', session: metadata }),
      status: async () => ({ source: 'none' }),
      logout: async () => ({ status: 'not_logged_in', revocationConfirmed: false }),
    }),
    writeOutput: (value) => { output += value },
  })

  await program.parseAsync(['node', 'dedalus', '--json', 'auth', 'status'])

  assert.deepEqual(JSON.parse(output), { status: 'not_logged_in', credential_source: 'none' })
})
