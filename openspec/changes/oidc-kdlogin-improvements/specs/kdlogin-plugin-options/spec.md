## ADDED Requirements

### Requirement: Configurable listen port for kdlogin

The kdlogin plugin SHALL support a configurable listen port for the local HTTP server that receives the kubeconfig push from the server. The default port SHALL remain 8080. When the user specifies a different port (e.g. via --port), the plugin SHALL listen on that port for GET /info and POST /.

#### Scenario: Default port

- **WHEN** the user runs the plugin without specifying a port (e.g. kubectl kdlogin https://kubedash/)
- **THEN** the plugin SHALL listen on port 8080 as today

#### Scenario: Custom port

- **WHEN** the user runs the plugin with a port option (e.g. kubectl kdlogin --port 9090 https://kubedash/)
- **THEN** the plugin SHALL listen on the specified port so that the server can detect and push to that port (server may need to be informed or discovery may stay on 8080; exact discovery mechanism is implementation-defined—e.g. server could try both or port could be part of a future contract)

### Requirement: Optional exec credential output for OIDC

The kdlogin plugin MAY support writing a kubeconfig user that uses the exec credential plugin mechanism (user.exec) instead of auth-provider=oidc. When this option is enabled, the plugin SHALL write user.exec with command and args that invoke the plugin's exec subcommand (e.g. kubectl kdlogin exec --base-url ... --context ...), and SHALL store the refresh token (or equivalent) in a local file so the exec subcommand can refresh and return the id_token. The default output SHALL remain auth-provider=oidc.

#### Scenario: Default kubeconfig output

- **WHEN** the user obtains kubeconfig via the plugin without requesting exec output
- **THEN** the plugin SHALL write the user with auth-provider name oidc and config (client-id, id-token, refresh-token, idp-issuer-url, etc.) as today

#### Scenario: Exec credential output when requested

- **WHEN** the user requests exec-based output (e.g. via a flag or option)
- **THEN** the plugin SHALL write user.exec with apiVersion client.authentication.k8s.io/v1 (or supported version), and when kubectl runs the exec command, the plugin SHALL return an ExecCredential with status.token set to a valid id_token (refreshing if necessary using stored refresh token or KubeDash/IdP)
