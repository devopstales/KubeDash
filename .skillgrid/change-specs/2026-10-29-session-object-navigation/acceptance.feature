Feature: Session object navigation (no object identity in the URL)

  Background:
    Given I am logged in as a local admin
    And a bound cluster "local" is selected in the header
    And the header namespace selector shows "team-a"

  # R1 — no identity in the URL
  Scenario: opening an object from a list leaves the URL clean
    Given the Secrets list for namespace "team-a" shows a secret "db-creds"
    When I click the "db-creds" name cell
    Then the Secret data page for "db-creds" in "team-a" is rendered
    And the URL is exactly "/security/secret" with no query string

  Scenario: the data page never carries identity params
    Given the open object ref is { kind: "secret", name: "db-creds", namespace: "team-a" }
    When the Secret data page renders
    Then window.location.search is ""

  # R2 — session storage
  Scenario: the open object ref lives in sessionStorage only
    Given I have opened the secret "db-creds" in "team-a"
    Then sessionStorage contains a "kd_object_refs" entry with kind "secret", name "db-creds", namespace "team-a"
    And sessionStorage contains a "kd_object_active" token that resolves to that entry
    And localStorage contains no key starting with "kd_ref_"
    And no API request was made to persist the object selection

  # R3 — refresh survives + 15-min lazy expiry
  Scenario: refreshing the tab keeps the open object
    Given the Secret data page for "db-creds" in "team-a" is rendered
    When I reload the page
    Then the Secret data page for "db-creds" in "team-a" is rendered again
    And the URL is exactly "/security/secret" with no query string

  Scenario: an expired ref renders the list
    Given the active object ref is the secret "db-creds" in "team-a" with ts backdated 16 minutes
    When I navigate to /security/secret
    Then the Secrets list for "team-a" is rendered
    And the active ref pointer is cleared

  # R4 — cross-tab deep link via POST
  Scenario: the share action opens the object in a new tab with a clean URL
    Given the Secret data page for "db-creds" in "team-a" is rendered
    When I click the share button
    And a new tab of the same origin opens
    Then the new tab renders the Secret data page for "db-creds" in "team-a"
    And the new tab's URL is exactly "/security/secret" with no query string
    And the new tab's sessionStorage contains the ref { kind: "secret", name: "db-creds", namespace: "team-a" }

  Scenario: the POST body and the relay carry no readable identity in the URL
    Given I am on the Secret data page for "db-creds" in "team-a"
    When I click the share button
    Then the opened document's URL contains no "name=" and no "namespace=" segment

  # R5 — one-shot handoff
  Scenario: a stale relay key is not consumed by a plain GET
    Given localStorage contains a relay key "kd_ref_deadbeef" with an expired "_exp"
    When I open /security/secret by plain GET
    Then the Secrets list for "team-a" is rendered
    And localStorage still contains no active ref for token "deadbeef" in sessionStorage

  Scenario: the relay self-deletes after consumption
    Given I have shared the secret "db-creds" in "team-a" to a new tab
    And the new tab has rendered the data page
    Then localStorage contains no key "kd_ref_<token>" for that handoff
    And localStorage contains no key "kd_ref_<token>_exp" for that handoff

  # R6 — route merge
  Scenario: one route per kind; detail renders only for a matching ref
    Given the routes table has no "/security/secret/data" entry
    And the open object ref is { kind: "poddisruptionbudget", name: "pdb-1", namespace: "team-a" }
    When I open /security/secret
    Then the Secrets list for "team-a" is rendered

  Scenario: back from the detail returns to the list
    Given the Secret data page for "db-creds" in "team-a" is rendered
    When I press the browser back button
    Then the Secrets list for "team-a" is rendered
    And the URL is exactly "/security/secret" with no query string

  # R7 — one-shot migration redirect
  Scenario: an old data URL redirects to the clean route with the ref hydrated
    Given I open the legacy URL "/security/secret/data?name=db-creds&namespace=team-a"
    Then the Secret data page for "db-creds" in "team-a" is rendered
    And the final URL is exactly "/security/secret" with no query string
    And the ref origin is "link"

  # R8 — namespace authority
  Scenario: the ref's namespace wins over the header selector
    Given the header namespace selector shows "default"
    And the open object ref is { kind: "secret", name: "db-creds", namespace: "team-a" }
    When the Secret data page renders
    Then the API read is for namespace "team-a" and name "db-creds"
    And the Namespace row renders "team-a"

  # R9 — filters stay, the selected hint goes
  Scenario: the selected bolding hint is replaced by the active ref
    Given the open object ref is { kind: "secret", name: "db-creds", namespace: "team-a" }
    When I open /security/secret (the list)
    Then the "db-creds" name cell is bolded
    And the URL is exactly "/security/secret" with no query string

  Scenario: a genuine filter param may remain a query param
    Given the Pods list supports a labelSelector filter
    When I filter pods by labelSelector "app=web"
    Then the URL may carry "?labelSelector=app=web"

  # R10 — no backend change
  Scenario: no new endpoint serves the object selection
    Given the API surface before this change
    When the SPA opens, refreshes, and shares an object
    Then no request is made to any /api/v1/session/* route
    And the backend diff for this change is empty
