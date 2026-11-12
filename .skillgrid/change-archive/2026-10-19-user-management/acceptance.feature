Feature: KubeDash user management — role templates, bindings, and self-service kubeconfig
  # ADR-0013 (permission management), ADR-0011 (credential plugin kubeconfig),
  # ADR-0002 (encrypted registry / one-way-door), ADR-0004 (RBAC read path).
  # Scenario names are the SATISFIES oracle for tasks.md.

  Background:
    Given a KubeDash app built by create_app() against Testcontainers Postgres and Redis
    And the four built-in role templates are seeded

  Scenario: admin-lists-and-patches-a-user
    # T4: admin user management.
    Given an admin user and a regular user
    When the admin GETs the admin users list
    Then the response is 200 and lists both users with role, status, and cluster count
    When the admin PATCHes the regular user's role to admin
    Then the response is 200 and an audit entry records the role change with the admin as actor

  Scenario: bootstrap-admin-cannot-be-demotion-or-disabled
    # T4: the local: bootstrap admin (ADR-0021) is immutable for role/status.
    Given the bootstrap local admin user
    When an admin PATCHes the bootstrap admin's role to user
    Then the response is 409 and the bootstrap admin keeps its admin role
    When an admin PATCHes the bootstrap admin's status to disabled
    Then the response is 409 and the bootstrap admin stays active

  Scenario: non-admin-cannot-reach-admin-users
    # T4: the admin gate.
    Given a regular (non-admin) user
    When the regular user GETs the admin users list
    Then the response is 403 with code RBAC_DENIED

  Scenario: disabled-user-is-rejected
    # T3: _auth_check rejects status == disabled.
    Given a user whose status is disabled
    When the disabled user calls any authenticated endpoint
    Then the response is 401 with code UNAUTHORIZED

  Scenario: admin-creates-and-reads-a-custom-template
    # T4: template CRUD.
    Given an admin user
    When the admin creates a custom template with a namespace scope and rules
    Then the response is 201 and the template appears in the templates list
    When the admin GETs the template back
    Then the response is 200 and the rules match what was created

  Scenario: builtin-templates-are-seeded-and-protected
    # T2 seeds, T4 guards delete.
    Given an admin user
    When the admin GETs the templates list
    Then the response includes the four built-in templates viewer, developer, admin, and cluster-admin
    When the admin DELETEs the developer template
    Then the response is 409 with code BUILTIN_TEMPLATE_PROTECTED

  Scenario: template-in-use-cannot-be-deleted
    # T4: referenced-custom guard.
    Given a custom template bound to a user
    When an admin DELETEs that template
    Then the response is 409 and names the binding that references it

  Scenario: malformed-template-rule-is-rejected
    # T4: rules validation.
    Given an admin user
    When the admin creates a template with a rule missing its verbs
    Then the response is 422 and the template is not stored

  Scenario: admin-binds-a-template-and-it-applies-in-the-cluster
    # T3 + T4: the tracer core. kind-gated.
    Given a user, a namespace-scoped template, and a live cluster
    When an admin binds the template to the user in a namespace
    Then the response is 200 and the cluster has a Role and a RoleBinding carrying the template's rules and kubedash labels
    And the binding is recorded for the user, cluster, and namespace

  Scenario: rebinding-the-same-binding-is-a-no-op
    # T3: idempotency — no second RoleBinding, no new audit row.
    Given an existing binding for a user, cluster, and namespace
    When an admin binds the same template to the same user in the same namespace
    Then the response is 200 and the cluster has exactly one RoleBinding for that user and no new audit entry

  Scenario: binding-with-a-mismatched-scope-is-rejected
    # T3: scope guard.
    Given a cluster-scoped template and a namespace-scoped template
    When an admin binds the cluster-scoped template providing a namespace
    Then the response is 422 and nothing is applied in the cluster
    When an admin binds the namespace-scoped template without a namespace
    Then the response is 422 and nothing is applied in the cluster

  Scenario: unbinding-the-last-user-deletes-the-cluster-role
    # T3: role GC. kind-gated.
    Given two users bound to the same template in the same namespace
    When an admin unbinds the first user
    Then the response is 200 and the cluster Role remains
    When an admin unbinds the second user
    Then the response is 200 and the cluster Role is deleted

  Scenario: unbinding-a-missing-binding-is-a-404
    # T4: unbind resolution.
    Given no binding for a user on a cluster
    When an admin unbinds that user on that cluster
    Then the response is 404 with code NO_BINDINGS

  Scenario: binding-against-an-unreachable-cluster-records-nothing
    # T3: cluster error path.
    Given a cluster whose API server is down
    When an admin binds a template to a user on that cluster
    Then the response is 502 with code CLUSTER_UNREACHABLE and the binding is not recorded

  Scenario: user-lists-their-own-bindings
    # T4: my-access.
    Given a user bound to two clusters
    When the user GETs their own access
    Then the response is 200 and lists exactly the user's two bindings with cluster, namespace, and template

  Scenario: user-with-no-bindings-sees-an-empty-list
    # T4: my-access empty.
    Given a user who has no bindings
    When the user GETs their own access
    Then the response is 200 with an empty list

  Scenario: a-user-never-sees-another-users-bindings
    # T4: my-access isolation.
    Given two users, one bound and one not
    When the unbound user GETs their own access
    Then the response is 200 with an empty list and none of the other user's bindings appear

  Scenario: user-downloads-a-multi-cluster-kubeconfig
    # T5: the tracer end. kind-gated for the kubectl round-trip.
    Given a user bound to two clusters in two namespaces
    When the user GETs their kubeconfig
    Then the response is 200 with a YAML attachment named kubedash-kubeconfig.yaml
    And the YAML has one context and one cluster per bound cluster with the correct server and certificate-authority data
    And the YAML has a single shared user entry that execs the kubedash credential plugin with the plugin server URL
    And each context's default namespace matches the user's bound namespace
    And kubectl config view parses the downloaded file

  Scenario: user-bound-to-one-cluster-gets-a-single-context-kubeconfig
    # T5: single-cluster shape.
    Given a user bound to one cluster in one namespace
    When the user GETs their kubeconfig
    Then the response is 200 and the YAML has exactly one context and one cluster

  Scenario: user-with-no-bindings-gets-a-404
    # T5: NO_BINDINGS.
    Given a user who has no bindings
    When the user GETs their kubeconfig
    Then the response is 404 with code NO_BINDINGS

  Scenario: the-kubeconfig-never-embeds-a-token
    # T5: ADR-0011 — plugin-only auth.
    Given a bound user
    When the user GETs their kubeconfig
    Then the YAML has no token, tokenFile, or oidc fields and authentication is by the credential plugin only

  Scenario: user-downloads-a-kubeconfig-from-my-access
    # T6: frontend My Access.
    Given a bound user
    When the user opens the My Access screen
    Then their bindings are listed and a Download kubeconfig button is shown
    When the user clicks Download kubeconfig
    Then a file named kubedash-kubeconfig.yaml is downloaded

  Scenario: my-access-shows-an-empty-state-for-no-bindings
    # T6: empty state.
    Given a user who has no bindings
    When the user opens the My Access screen
    Then an empty state is shown and no broken table is rendered

  Scenario: admin-binds-a-template-from-the-admin-view
    # T7: 4.1 User List → privilege form.
    Given an admin and a user
    When the admin opens the User List
    Then the list is a DataTable with columns Username, Email, Permission, Type, and Action
    When the admin opens that user's privileges and saves a namespaced template on the selected cluster
    Then the binding is created and listed on the privilege page

  Scenario: the-admin-view-shows-api-errors-as-messages
    # T7: error envelope.
    Given a bind that returns a 409 conflict
    When the admin submits the bind from the admin view
    Then the API error message is shown and no unhandled console error is raised

  Scenario: a-non-admin-is-redirected-away-from-the-admin-view
    # T7: route gate.
    Given a regular (non-admin) user
    When the regular user navigates to the admin permissions route
    Then the user is redirected and the admin view is not rendered
