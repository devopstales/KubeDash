Feature: Configuration source (kubedash.ini)
  # briefing.md R1-R7. ADR-0028. The load-bearing theme: configuration comes
  # from the operator-editable kubedash.ini (4.1 format, minus plugins), with
  # create_app overrides > KUBEDASH_* env > INI, and no hard-coded in-code
  # defaults for identities/credentials — a missing required value fails fast
  # at boot with a named error. Only optional/behavior knobs keep defaults.
  #
  # Scenario names are the SATISFIES oracle for the blueprint tasks and the
  # test titles. Each scenario's class (happy path / edge / failure) is the
  # comment on its first line.

  Background:
    Given the KubeDash Flask app under test

  # ------------------------------------------------------------- resolution

  Scenario: ini-provides-value
    # happy path — R1
    Given a kubedash.ini that sets [security] jwt_secret
    When the settings are resolved
    Then kubedash_jwt_secret is the INI value

  Scenario: env-overrides-ini
    # happy path — R2
    Given a kubedash.ini that sets [security] jwt_secret
    And the environment KUBEDASH_KUBEDASH_JWT_SECRET set to a different value
    When the settings are resolved
    Then kubedash_jwt_secret is the ENV value

  Scenario: override-beats-env-and-ini
    # happy path — R2 (create_app config_overrides is the highest-priority leg)
    Given a kubedash.ini and an env value for jwt_secret
    And a create_app override for KUBEDASH_KUBEDASH_JWT_SECRET
    When the app is created
    Then kubedash_jwt_secret is the OVERRIDE value

  Scenario: required-key-missing-fails-fast
    # failure — R2
    Given no override, env, or INI value for jwt_secret
    When the settings are resolved
    Then boot fails with a named error naming the security section and jwt_secret key

  Scenario: optional-and-behavior-knobs-keep-defaults
    # edge — R2 (ADR-0025/0027)
    Given cookie_secure, flask_env, kubedash_role, and kubedash_replica_id are unset
    When the settings are resolved
    Then cookie_secure is true and flask_env is development
    And kubedash_role is worker and kubedash_replica_id is local

  # ------------------------------------------------------------------ schema

  Scenario: database-split-or-url
    # happy path — R3
    Given a kubedash.ini [database] with type, host, name, user, password
    When the settings are resolved
    Then database_url is the postgresql URL built from the split fields with quote_plus
    Given a kubedash.ini [database] with both split fields and url
    When the settings are resolved
    Then database_url is the url value

  Scenario: remote-cache-split-or-url
    # happy path — R3
    Given a kubedash.ini [remote_cache] with redis_host, redis_db
    When the settings are resolved
    Then redis_url is the redis URL built from the split fields
    Given a kubedash.ini [remote_cache] with url and redis_host
    When the settings are resolved
    Then redis_url is the url value

  Scenario: retired-k8s-and-plugin-sections-ignored
    # edge — R4, R3
    Given a kubedash.ini containing [k8s] and [plugin_settings] sections
    When the settings are resolved
    Then boot succeeds
    And the k8s and plugin_settings sections are ignored

  # ------------------------------------------------------------ call-surface

  Scenario: existing-fixtures-keep-working
    # regression — R6 (access pattern unchanged; fixtures may gain config sourcing)
    Given the existing tests that set KUBEDASH_* via env and create_app overrides
    When the full backend suite runs
    Then the env-injecting sites and the config_overrides seam keep passing
    And fixtures that need required keys point KUBEDASH_CONFIG_FILE at a fixture INI

  # ------------------------------------------------------------- dev + chart

  Scenario: dev-stack-boots-from-ini
    # backstop — R1, R7 (runtime: full dev stack, not the test client)
    Given task dev-stack points KUBEDASH_CONFIG_FILE at dev/kubedash.ini
    When the backend boots
    Then the bootstrap admin and KUBEDASH_ROLE come from the INI
    And the health endpoint returns 200

  Scenario: chart-env-overrides-ini
    # backstop — R7 (ADR-0006)
    Given the Helm chart injects KUBEDASH_JWT_SECRET via secretKeyRef
    When the deployment starts with a kubedash.ini present
    Then the env-injected secret overrides the INI [security] jwt_secret
