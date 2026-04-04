### PRD: kubelogin Interactive OIDC Login & IdP CA Management

**OpenSpec change**: `openspec/changes/kubelogin-interactive-login/`  
**Status**: Proposed (see OpenSpec for canonical state)

#### Problem / Why

Today KubeDash focuses on generating kubeconfigs that rely on `auth-provider=oidc` and the kdlogin helper, while the broader Kubernetes ecosystem increasingly standardizes on **exec-based credential plugins** such as [`kubelogin` (`kubectl oidc-login`)](https://github.com/int128/kubelogin).  
This creates several gaps:

- KubeDash cannot yet **produce kubeconfigs that are ready to use with `kubectl oidc-login get-token`**, forcing users to hand-edit configs if they want to use the kubectl plugin flow.
- Handling of **custom IdP certificate authorities** is ad‑hoc: KubeDash does not provide a clear way to manage an IdP CA and expose it as `idp-certificate-authority` in generated kubeconfigs.
- Operators who want to harden OIDC (custom CA, strict TLS) and at the same time offer a smooth **interactive kubectl login** experience must currently stitch things together manually.

We want KubeDash to **first‑class support kubelogin’s interactive OIDC login flow**, including optional IdP CA management, so that users can use `kubectl` directly with SSO in a secure and ergonomic way.

#### Goals

- Allow users to download a kubeconfig from KubeDash that:
  - Uses an **exec‑based user** compatible with `kubectl oidc-login get-token`.
  - Includes all required OIDC parameters (issuer URL, client ID, scopes) in a predictable way.
- Provide a clear, optional flow to **manage IdP CA certificates** in KubeDash and:
  - Store the CA configuration in `kubedash.ini`.
  - Surface CA settings in the UI.
  - Emit the corresponding `idp-certificate-authority-data` (or equivalent) in generated kubeconfigs when configured.
- Keep existing kdlogin and `auth-provider=oidc` flows working without breaking changes.

#### Non‑Goals

- Replacing kdlogin or existing OIDC flows; kubelogin support is **additive**.
- Designing a full certificate management lifecycle (rotation, CRL handling, etc.); this PRD focuses on **referencing** a trusted CA (file path or uploaded PEM) for IdP TLS validation.

---

### User Stories

- **CLI‑first cluster user**
  - *As a* developer who works primarily from the terminal
  - *I want* to download a kubeconfig from KubeDash that already uses `kubectl oidc-login get-token` as an exec credential
  - *So that* I can run `kubectl get pods` and have kubelogin open a browser and authenticate without manual kubeconfig surgery.

- **Security‑focused platform admin**
  - *As a* platform admin
  - *I want* to configure a custom IdP CA in `kubedash.ini` (and optionally via the UI)
  - *So that* all OIDC flows – including kubelogin – validate the IdP over TLS using my organization’s CA bundle, and kubeconfigs reference that CA consistently.

- **Ops engineer onboarding new clusters**
  - *As an* ops engineer onboarding new clusters and IdPs
  - *I want* a simple UI flow to opt into kubelogin exec‑based kubeconfigs and IdP CA usage
  - *So that* I can roll out a standard, documented `kubectl oidc-login` flow across teams without custom scripts.

---

### Functional Requirements

#### 1. kubelogin‑Compatible Exec User in Generated Kubeconfigs

- When exporting or generating a kubeconfig from KubeDash, users must be able to select a **kubelogin mode** (in addition to existing kdlogin/`auth-provider=oidc` options).
- In kubelogin mode, the kubeconfig **user** entry must be of type `exec` and follow the kubectl credential plugin contract:
  - `user.exec.apiVersion: client.authentication.k8s.io/v1`
  - `user.exec.command: kubectl`
  - `user.exec.args` must contain at least:
    - `oidc-login`
    - `get-token`
    - `--oidc-issuer-url=…` (taken from current KubeDash OIDC issuer configuration)
    - `--oidc-client-id=…` (taken from current client ID configuration)
  - KubeDash may include additional kubelogin flags as appropriate (see “Additional kubelogin options” below).
- The cluster section must continue to set:
  - `cluster.server` pointing at the Kubernetes API server.
  - TLS settings consistent with existing flows (e.g., `certificate-authority-data` for the cluster CA).
- The generated kubeconfig **must remain valid** even for users who do not have kubelogin installed, but error messages (e.g. “kubectl: exec plugin not found”) are acceptable and can be documented.

#### 2. Additional kubelogin Options (Best Initial Additions)

From the kubelogin feature set, we will initially support:

- **Token cache keying and scopes (docs‑driven)**:
  - Allow KubeDash to optionally include `--oidc-extra-scope` (or equivalent) and/or `--oidc-scope` values in the exec args when configured, to help align with the scopes expected by the IdP.
  - This is *configuration‑only* on the KubeDash side; kubelogin itself handles token caching and keyring integration as documented in the upstream project.
- **Verbose logging hints (docs‑driven)**:
  - KubeDash documentation for kubelogin mode should mention the `-v1` kubelogin verbosity flag so that users can debug ID token claims and flows, but the PRD does not require KubeDash to manipulate verbosity flags by default.

Future enhancements (e.g. advanced token cache controls, standalone mode integration) can be considered in follow‑up OpenSpec changes and are explicitly out of scope here.

#### 3. IdP Certificate Authority Management

- KubeDash must support an **optional IdP CA** configuration that is used for TLS validation of the OIDC issuer and surfaced to clients:
  - New configuration key(s) in `kubedash.ini`, e.g.:
    - `oidc_idp_ca_file = /path/to/idp-ca.pem`
    - (Optional) `oidc_idp_ca_name` or descriptive label for UI display.
  - If `oidc_idp_ca_file` is set and readable:
    - KubeDash must use it when performing OIDC discovery/token/userinfo requests (in addition to or instead of system CAs, per detailed design).
    - Generated kubeconfigs must include an appropriate reference for clients:
      - For kdlogin/`auth-provider=oidc`: continue to use the existing mechanism or extend to include IdP CA as needed.
      - For kubelogin exec users: when IdP CA is configured, include:
        - `idp-certificate-authority-data: ...base64-encoded-PEM...` (or another agreed field that kubelogin honors, consistent with its documentation).
- The KubeDash **UI settings page** must expose:
  - Visibility into whether an IdP CA is configured (e.g. “IdP CA: configured from kubedash.ini” vs “not configured”).
  - A way (subject to security policy) to:
    - Either upload a PEM CA certificate that KubeDash writes to a configured path and references in `kubedash.ini`, **or**
    - Paste a PEM CA and store it in an appropriate config store (file/DB) from which `oidc_idp_ca_file` is derived.
  - Clear warnings when:
    - No IdP CA is configured and system CAs will be used.
    - An insecure mode (e.g. `verify=False`) is configured elsewhere; UI should nudge users towards using an IdP CA instead.

#### 4. KubeDash UI / UX Changes

- **Settings / Authentication section**:
  - Add a sub‑section “OIDC & kubelogin” that:
    - Shows current OIDC issuer URL and client ID.
    - Indicates whether IdP CA is configured (and possibly its source).
    - Provides a toggle or selection for **kubeconfig export modes**:
      - `kdlogin (auth-provider=oidc)` (existing)
      - `kubelogin (exec kubectl oidc-login get-token)` (new)
    - When kubelogin mode is selected:
      - Show a short, copy‑paste snippet of the expected kubeconfig `user` section.
      - Provide a reminder that `kubectl krew install oidc-login` (or other install methods) is required.
- **Kubeconfig export/download flow**:
  - Allow users to choose export mode (kdlogin vs kubelogin).
  - Ensure that when IdP CA is configured, the exported kubeconfig includes `idp-certificate-authority-data` or equivalent field.
  - When no IdP CA is configured:
    - Exported kubeconfig should omit IdP CA fields and rely on system CAs.
    - UI should optionally display a note that a custom IdP CA can be configured for stricter TLS.

---

### Non‑Functional Requirements

- **Security**
  - IdP CA files managed via KubeDash must:
    - Be stored on disk with appropriate file permissions (readable by the KubeDash process only).
    - Not be exposed in plaintext via APIs except as needed for kubeconfig generation.
  - Upload/paste flows for IdP CAs must validate that the input is a PEM‑encoded certificate (basic structural checks) before accepting it.
  - The introduction of `idp-certificate-authority` references must not weaken existing TLS validation; they should only strengthen or make CA usage explicit.

- **Reliability**
  - If `oidc_idp_ca_file` is misconfigured (missing/unreadable), KubeDash must:
    - Log a clear error at startup.
    - Fall back to system CAs or fail fast according to configuration, but must not silently ignore failures.
  - Exported kubeconfigs must remain valid even when IdP CA is not configured.

- **Backward compatibility**
  - Existing kdlogin users and `auth-provider=oidc` kubeconfigs must keep working with no changes unless the operator explicitly switches to kubelogin mode.
  - Any new configuration keys in `kubedash.ini` must have sensible defaults that preserve current behavior when absent.

---

### Scope / Affected Components

- **Python / KubeDash**
  - OIDC configuration and SSO helpers (e.g. `lib/sso.py` and related modules).
  - Kubeconfig export/generation logic for kdlogin today; needs extension for kubelogin exec users.
  - Settings/authentication blueprints for UI (e.g. `blueprint/settings/settings.py`, `blueprint/auth/auth.py`) to surface kubelogin and IdP CA options.
  - Configuration loading from `kubedash.ini` to support `oidc_idp_ca_file` and related keys.

- **Frontend / UI**
  - Settings screens to:
    - Toggle between kubeconfig export modes.
    - Display and optionally manage IdP CA configuration.
  - Kubeconfig download UI to ensure the correct mode (kdlogin vs kubelogin) and IdP CA behavior.

- **External dependency**
  - Assumes kubelogin (`kubectl oidc-login`) is installed on user machines; KubeDash will not manage installation but will document requirements.

---

### Implementation Tasks (High‑Level)

> Detailed task breakdown should be captured in the corresponding OpenSpec change; this PRD only enumerates high‑level work items.

1. **Config & Backend Support**
   - [ ] 1.1 Add new `kubedash.ini` keys for IdP CA management (e.g. `oidc_idp_ca_file`) and load them into the OIDC configuration layer.
   - [ ] 1.2 Update OIDC client construction to use `oidc_idp_ca_file` for TLS verification when set.
   - [ ] 1.3 Extend kubeconfig generation utilities to support a kubelogin exec‑based user, parameterized by issuer URL, client ID, and optional scopes/extra scopes.
  - [ ] 1.4 Ensure that when IdP CA is configured, exported kubeconfigs include the appropriate `idp-certificate-authority-data` (or equivalent) field.

2. **UI: Settings & Kubeconfig Export**
   - [ ] 2.1 Add “OIDC & kubelogin” section in Settings to show issuer, client ID, and IdP CA status.
   - [ ] 2.2 Add controls to choose kubeconfig export mode (kdlogin vs kubelogin) and persist default preferences as appropriate.
   - [ ] 2.3 Add UI flow for providing an IdP CA (upload or paste), wired to backend storage and `kubedash.ini`-backed configuration.
   - [ ] 2.4 Update kubeconfig download/export UI to respect chosen mode and IdP CA configuration.

3. **Docs & Verification**
   - [ ] 3.1 Update KubeDash documentation to include a “Using kubelogin (`kubectl oidc-login`)" section with example kubeconfig and CLI usage.
   - [ ] 3.2 Document IdP CA configuration, including security considerations and examples.
   - [ ] 3.3 Verify end‑to‑end flows:
     - kubelogin exec mode with and without IdP CA configured.
     - Backward compatibility for existing kdlogin users and kubeconfigs.

