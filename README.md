# ssharc-agent

Run an in-memory SSH agent that serves an AAD/Entra SSH certificate for a generated RSA keypair.

The process also hosts a relay information IPC interface that queries ARM HybridConnectivity relay credentials using the same identity mode used for SSH cert acquisition.

The auth provider is selected via a JSON config file:
- `az_cli`
- `service_principal`

SSH socket endpoint is configured in the same config file:
- Windows: named pipe path, for example `\\\\.\\pipe\\ssharc-agent-auth`
- Unix: domain socket path, for example `/tmp/ssharc-agent-auth.sock`

Relay socket endpoint is configured separately:
- Windows: named pipe path, for example `\\\\.\\pipe\\ssharc-agent-nw`
- Unix: domain socket path, for example `/tmp/ssharc-agent-nw.sock`

## Run

```powershell
go run . --config ./config.json
```

Or build and run:

```powershell
go build -o ./ssharc-agent.exe .
./ssharc-agent.exe --config ./config.json
```

Print version:

```powershell
go run . --version
```

Set version at build time:

```powershell
go build -ldflags "-X main.version=v1.2.3" -o ssharc-agent.exe .
./ssharc-agent.exe --version
```

## Config File

### Option 1: Azure CLI Logged-In Context

```json
{
  "socket_path": "\\\\.\\pipe\\ssharc-agent-auth",
  "relay_socket_path": "\\\\.\\pipe\\ssharc-agent-nw",
  "auth_mode": "az_cli"
}
```

This mode runs `az ssh cert` under the hood and uses the current Azure CLI login context.

### Option 2: Service Principal + Secret

```json
{
  "socket_path": "\\\\.\\pipe\\ssharc-agent-auth",
  "relay_socket_path": "\\\\.\\pipe\\ssharc-agent-nw",
  "subscription_id": "22222222-2222-2222-2222-222222222222",
  "auth_mode": "service_principal",
  "service_principal": {
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "app_id": "11111111-1111-1111-1111-111111111111",
    "credential_type": "secret",
    "client_secret": "<secret>",
    "authority_host": "https://login.microsoftonline.com"
  }
}
```

### Option 3: Service Principal + Key Vault Non-Exportable Certificate

```json
{
  "socket_path": "\\\\.\\pipe\\ssharc-agent-auth",
  "relay_socket_path": "\\\\.\\pipe\\ssharc-agent-nw",
  "subscription_id": "22222222-2222-2222-2222-222222222222",
  "auth_mode": "service_principal",
  "service_principal": {
    "tenant_id": "00000000-0000-0000-0000-000000000000",
    "app_id": "11111111-1111-1111-1111-111111111111",
    "credential_type": "keyvault_certificate",
    "key_vault_url": "https://myvault.vault.azure.net",
    "certificate_name": "my-sp-cert",
    "authority_host": "https://login.microsoftonline.com"
  }
}
```

This mode uses managed identity to access Key Vault, then:
1. Reads certificate metadata (`x5t`, `kid`) from Key Vault.
2. Builds a JWT client assertion for the service principal.
3. Signs the JWT hash using the Key Vault key sign operation (`RS256`).
4. Exchanges the assertion for an AAD SSH cert token.

Notes:
- `socket_path` is optional. Defaults:
  - Windows: `\\\\.\\pipe\\ssharc-agent-auth`
  - Unix: `${TMPDIR}/ssharc-agent-auth.sock` (typically `/tmp/ssharc-agent-auth.sock`)
- `relay_socket_path` is optional. Defaults:
  - Windows: `\\\\.\\pipe\\ssharc-agent-nw`
  - Unix: `${TMPDIR}/ssharc-agent-nw.sock` (typically `/tmp/ssharc-agent-nw.sock`)
- `subscription_id` is optional. If omitted:
  - `az_cli` mode uses `az account show` current subscription.
  - `service_principal` mode resolves from ARM `/subscriptions` (first enabled subscription).
- `authority_host` is optional and defaults to `https://login.microsoftonline.com`.
- `tenant_id` and `app_id` are required for all `service_principal` modes.
- `credential_type` supports `secret` or `keyvault_certificate`.
- For `secret`, `client_secret` is required.
- For `keyvault_certificate`, `key_vault_url` and `certificate_name` are required.
- The managed identity running this tool must have Key Vault permissions to read certificate metadata and sign with the backing key.

## Agent Usage

Run the agent:

```powershell
./ssharc-agent.exe --config ./config.json
```

Then point SSH to the socket:

Windows PowerShell:

```powershell
$env:SSH_AUTH_SOCK="\\.\pipe\ssharc-agent-auth"
ssh user@host
```

Unix shell:

```bash
export SSH_AUTH_SOCK=/tmp/ssharc-agent-auth.sock
ssh user@host
```

## Relay Info Interface

The relay IPC server starts with the same process and uses the same auth mode configured in `auth_mode` to call ARM:
- `az_cli`: uses current Azure CLI identity.
- `service_principal`: uses the configured service principal credential.

Environment variable set by the process:
- `RELAY_INFO_SOCK` -> relay socket/pipe path.

Request format (4-byte big-endian length + JSON body):

```json
{
  "command": "get_relay_info",
  "resource_group": "my-rg",
  "vm_name": "my-arc-machine",
  "resource_type": "Microsoft.HybridCompute/machines",
  "port": 22,
  "yes_without_prompt": true
}
```

Response format:

```json
{
  "type": "response",
  "cred": {
    "namespaceName": "...",
    "namespaceNameSuffix": "...",
    "hybridConnectionName": "...",
    "accessKey": "...",
    "expiresOn": 0,
    "serviceConfigurationToken": "..."
  },
  "new_service_config": false
}
```

Error format:

```json
{
  "type": "error",
  "error": "description"
}
```

### Local Test Client (Go)

A small Go client is included at `nwcreds-info-client` to query relay info from the running agent.

Example:

```powershell
go run ./nwcreds-info-client --resource-group my-rg --vm-name my-arc-machine
```

Optional flags:
- `--socket-path` to override relay socket/pipe path (otherwise uses `RELAY_INFO_SOCK` or default path).
- `--resource-type` to override `Microsoft.HybridCompute/machines`.
- `--port` to request relay info for a different SSH port.
- `--timeout` to control request timeout (default `30s`).
- `--pretty=false` for compact JSON output.
