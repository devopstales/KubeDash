import { Fragment } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  CBreadcrumb,
  CBreadcrumbItem,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CTable,
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { Light as SyntaxHighlighter } from 'react-syntax-highlighter'
import json from 'react-syntax-highlighter/dist/esm/languages/hljs/json'
import anOldHope from 'react-syntax-highlighter/dist/esm/styles/hljs/an-old-hope'
import { apiFetch } from '../../lib/api'
import { clearActiveRef, openObject } from '../../lib/objectRef'
import { formatTimestamp } from '../../lib/format'
import type { DeploymentItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import ObjectTabs from '../../components/ObjectTabs'
import TopMenu from '../../components/TopMenu'

// Same pattern as SecretData.tsx / HPAData: the hljs language module is a
// singleton, so a second registration is harmless. Register `json` — the
// block is `JSON.stringify` of the to_dict object, so the json grammar is
// the truthful classifier for the exact text rendered (ratified rule,
// PriorityClassData final review 2026-10-28).
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

// The Related Resources rows (4.1's deployment-data shape — from the pod
// template spec): image-pull secrets, the service account, secrets (env
// value_from + volumes), configmaps (volumes), PVCs (volumes). Deep-linking
// (ratified 2026-10-28): Secrets link to the LANDED Secret view; the rest
// render plain text (their views are not yet landed — the links would 404).
type RefRow = { type: string; name: string; secret: boolean }

const refersTo = (deployment: DeploymentItem): RefRow[] => {
  const templateSpec = deployment.spec?.template?.spec
  const rows: RefRow[] = []
  for (const ips of templateSpec?.image_pull_secrets ?? []) {
    if (ips.name) rows.push({ type: 'ImagePullSecret', name: ips.name, secret: false })
  }
  if (templateSpec?.service_account_name) {
    rows.push({ type: 'ServiceAccount', name: templateSpec.service_account_name, secret: false })
  }
  for (const c of templateSpec?.containers ?? []) {
    for (const e of c.env ?? []) {
      const ref = e.value_from?.secret_key_ref?.name
      if (ref) rows.push({ type: 'Secret', name: ref, secret: true })
    }
  }
  for (const v of templateSpec?.volumes ?? []) {
    if (v.secret?.secret_name) rows.push({ type: 'Secret', name: v.secret.secret_name, secret: true })
    if (v.config_map?.name) rows.push({ type: 'Configmap', name: v.config_map.name, secret: false })
    if (v.persistent_volume_claim?.claim_name) {
      rows.push({ type: 'PVC', name: v.persistent_volume_claim.claim_name, secret: false })
    }
  }
  return rows
}

const KeyValueTable = ({ entries, empty }: { entries: [string, string][]; empty: string }) =>
  entries.length === 0 ? (
    empty
  ) : (
    <CTable bordered small className="mb-0">
      <thead>
        <tr>
          <th style={{ width: '50%' }}>Key</th>
          <th style={{ width: '50%' }}>Value</th>
        </tr>
      </thead>
      <tbody>
        {entries.map(([key, value]) => (
          <tr key={key}>
            <td>{key}</td>
            <td>{value}</td>
          </tr>
        ))}
      </tbody>
    </CTable>
  )

/**
 * 4.1 `workload/deployment-data.html.j2` port: one Deployment's metadata
 * plus the 4.1 six-tab set (Deployment / Containers / Variables /
 * Conditions / Security Contexts / Related Resources) and the full object
 * as a syntax-highlighted block (`JSON.stringify` — the block is JSON text
 * with the truthful `json` highlighter). The read is a SINGLE
 * `?name=&namespace=` fetch (4.1's list-then-filter is dropped). The kind
 * is namespaced (apps/v1, snake_case to_dict).
 * 4.1 deviations (recorded in the change's adr.md): the Admin-only replica
 * spinner is NOT replicated (a write path — Replicas is plain text,
 * ratified deviation 9); the Containers tab renders the template's
 * name + image only (no live state — this is the deployment's template,
 * not a running pod); `trimAnnotations` is NOT replicated (annotations
 * verbatim, deviation 7); the 4.1 "Lables" typo is NOT replicated
 * (deviation 8). The Related Resources tab deep-links to LANDED kinds only
 * (deviation 5).
 */
// ADR-0040: identity arrives as props from ObjectRoute (the active ref),
// never from useSearchParams — the URL stays clean (R1). The namespace is
// the ref's namespace (authoritative, R8): never the header's
// selectedNamespace. The legacy /data route (the R7 redirect) passes the
// legacy ?name=/?namespace= through as props; this view no longer reads
// the URL.
const DeploymentDataView = ({ name, namespace }: { name: string; namespace: string }) => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const navigate = useNavigate()

  const query = useQuery<DeploymentItem>({
    queryKey: ['workload-deployment-data', cluster?.id, namespace, name],
    enabled: cluster != null && name !== '' && namespace !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<DeploymentItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/deployments?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      const [item] = r.data?.items ?? []
      if (!item) throw new Error(NOT_FOUND)
      return item
    },
  })

  const deployment = query.data
  // The pod TEMPLATE spec (spec.template.spec) — the containers/volumes/
  // env the data tabs render. Distinct from the live pod spec (the
  // deployment does not run pods itself).
  const templateSpec = deployment?.spec?.template?.spec
  const labels = Object.entries(deployment?.metadata?.labels ?? {})
  // VERBATIM (ratified deviation 7: no trimAnnotations).
  const annotations = Object.entries(deployment?.metadata?.annotations ?? {})
  // 4.1's Selectors sub-table: spec.selector.match_labels (the deployment's
  // own selector — where 4.1's pod-data labels read metadata.labels, this
  // reads spec.selector.match_labels; 'No selectors' when absent).
  const selectors = Object.entries(deployment?.spec?.selector?.match_labels ?? {})
  const conditions = deployment?.status?.conditions ?? []
  const securityContext = Object.entries(templateSpec?.security_context ?? {})
  const containers = (templateSpec?.containers ?? []).map((c) => ({
    name: c.name ?? '',
    image: c.image ?? '—',
  }))
  const initContainers = (templateSpec?.init_containers ?? []).map((c) => ({
    name: c.name ?? '',
    image: c.image ?? '—',
  }))
  // 4.1's `environment_variables`: env entries with a literal `value`
  // (secret refs contribute to Related Resources, not here).
  const variables = (templateSpec?.containers ?? []).flatMap((c) =>
    (c.env ?? [])
      .filter((e) => e.name != null && e.value != null)
      .map((e) => ({ name: e.name!, value: e.value! })),
  )
  const refs = refersTo(deployment ?? {})

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Workloads</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/workload/deployments" onClick={clearActiveRef}>
              Deployments List
            </Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Deployment Data</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: deployment name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading deployment data...</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            // A miss is a state, not an error.
            <div className="text-center text-muted">No deployment '{name}' found</div>
          ) : (
            <div className="text-danger">Error loading deployment: {query.error.message}</div>
          )
        ) : (
          <>
            <ObjectTabs
              defaultActiveKey="deployment"
              tabs={[
                { key: 'deployment', label: 'Deployment' },
                { key: 'containers', label: 'Containers' },
                { key: 'variables', label: 'Variables' },
                { key: 'conditions', label: 'Conditions' },
                { key: 'security-contexts', label: 'Security Contexts' },
                { key: 'related-resources', label: 'Related Resources' },
              ]}
            >
              <Fragment>
                <CTable bordered>
                  <tbody>
                    <tr>
                      <th scope="row">Namespace:</th>
                      <td>{deployment?.metadata?.namespace ?? 'N/A'}</td>
                    </tr>
                    <tr>
                      <th scope="row">Name:</th>
                      <td>{deployment?.metadata?.name ?? 'N/A'}</td>
                    </tr>
                    <tr>
                      <th scope="row">Created:</th>
                      <td>{formatTimestamp(deployment?.metadata?.creation_timestamp)}</td>
                    </tr>
                    <tr>
                      <th scope="row">Replicas:</th>
                      {/* Plain text (ratified deviation 9): 4.1's Admin-only
                          replica spinner is a write path, not ported. */}
                      <td>
                        {deployment?.spec?.replicas != null
                          ? String(deployment.spec.replicas)
                          : '—'}
                      </td>
                    </tr>
                    <tr>
                      <th scope="row">Annotations:</th>
                      <td>
                        <KeyValueTable entries={annotations} empty="No annotations" />
                      </td>
                    </tr>
                    <tr>
                      <th scope="row">Labels:</th>
                      <td>
                        <KeyValueTable entries={labels} empty="No labels" />
                      </td>
                    </tr>
                    <tr>
                      <th scope="row">Selectors:</th>
                      <td>
                        <KeyValueTable entries={selectors} empty="No selectors" />
                      </td>
                    </tr>
                  </tbody>
                </CTable>
              </Fragment>

              <Fragment>
                {initContainers.length === 0 ? (
                  <div className="mb-3">No init containers</div>
                ) : (
                  <CTable bordered className="mb-3">
                    <caption className="fs-6 fw-bold text-primary">Init Containers</caption>
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>Image</th>
                      </tr>
                    </thead>
                    <tbody>
                      {initContainers.map((c) => (
                        <tr key={c.name}>
                          <td>{c.name || '—'}</td>
                          <td>{c.image}</td>
                        </tr>
                      ))}
                    </tbody>
                  </CTable>
                )}
                <CTable bordered>
                  <caption className="fs-6 fw-bold text-primary">Containers</caption>
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Image</th>
                    </tr>
                  </thead>
                  <tbody>
                    {containers.map((c) => (
                      <tr key={c.name}>
                        <td>{c.name || '—'}</td>
                        <td>{c.image}</td>
                      </tr>
                    ))}
                  </tbody>
                </CTable>
              </Fragment>

              <Fragment>
                <CTable bordered>
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {variables.length === 0 ? (
                      <tr>
                        <td colSpan={2} className="text-center text-muted">
                          No variables
                        </td>
                      </tr>
                    ) : (
                      variables.map((v, i) => (
                        <tr key={`${v.name}-${i}`}>
                          <td>{v.name}</td>
                          <td>{v.value}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </CTable>
              </Fragment>

              <Fragment>
                <CTable bordered>
                  <thead>
                    <tr>
                      <th>State</th>
                      <th>Reason</th>
                      <th>Message</th>
                      <th>Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {conditions.length === 0 ? (
                      <tr>
                        <td colSpan={4} className="text-center text-muted">
                          No conditions
                        </td>
                      </tr>
                    ) : (
                      conditions.map((c, i) => (
                        <tr key={c.type ?? i}>
                          <td>{c.type ?? 'N/A'}</td>
                          <td>{c.reason ?? 'N/A'}</td>
                          <td>{c.message ?? 'N/A'}</td>
                          <td>{c.last_transition_time ?? 'N/A'}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </CTable>
              </Fragment>

              <Fragment>
                <CTable bordered>
                  <thead>
                    <tr>
                      <th>Context</th>
                      <th>State</th>
                    </tr>
                  </thead>
                  <tbody>
                    {securityContext.length === 0 ? (
                      <tr>
                        <td colSpan={2} className="text-center text-muted">
                          No security context
                        </td>
                      </tr>
                    ) : (
                      securityContext.map(([key, value]) => (
                        <tr key={key}>
                          <td>{key}</td>
                          <td>{String(value)}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </CTable>
              </Fragment>

              <Fragment>
                <CTable bordered>
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Name</th>
                      <th>Namespace</th>
                    </tr>
                  </thead>
                  <tbody>
                    {refs.length === 0 ? (
                      <tr>
                        <td colSpan={3} className="text-center text-muted">
                          —
                        </td>
                      </tr>
                    ) : (
                      refs.map((ref, i) => (
                        <tr key={`${ref.type}-${ref.name}-${i}`}>
                          <td>{ref.type}</td>
                          <td>
                            {ref.secret ? (
                              // Deep-link to the LANDED Secret view (ratified
                              // 2026-10-28): the ADR-0040 openObject delta.
                              <button
                                type="button"
                                className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
                                onClick={() =>
                                  openObject('secret', ref.name, namespace, '/security/secret', navigate)
                                }
                              >
                                {ref.name}
                              </button>
                            ) : (
                              ref.name
                            )}
                          </td>
                          <td>{namespace}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </CTable>
              </Fragment>
            </ObjectTabs>
            <CCard className="mb-0 mt-4">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">Deployment</CCardTitle>
              </CCardHeader>
              <CCardBody>
                <SyntaxHighlighter
                  language="json"
                  style={anOldHope}
                  wrapLongLines
                  customStyle={{ margin: 0 }}
                  codeTagProps={{ style: { whiteSpace: 'pre-wrap', wordBreak: 'break-word' } }}
                >
                  {JSON.stringify(deployment, null, 2)}
                </SyntaxHighlighter>
              </CCardBody>
            </CCard>
          </>
        )}
      </CCardBody>
    </CCard>
  )
}

export default DeploymentDataView
