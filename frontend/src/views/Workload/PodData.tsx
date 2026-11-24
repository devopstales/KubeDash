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
import type { Pod, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import KubeDataTable from '../../components/KubeDataTable'
import ObjectTabs from '../../components/ObjectTabs'
import TopMenu from '../../components/TopMenu'

// Same pattern as SecretData.tsx / HPAData: the hljs language module is a
// singleton, so a second registration is harmless. Register `json` — the
// block is `JSON.stringify` of the to_dict object, so the json grammar is
// the truthful classifier for the exact text rendered (ratified rule,
// PriorityClassData final review 2026-10-28).
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

// 4.1's effective-phase rule (k8sPodListGet): status.phase, overridden to
// `Terminated` when metadata.deletion_timestamp is set. Same badge mapping
// as the list view.
const effectivePhase = (pod: Pod): string =>
  pod.metadata?.deletion_timestamp ? 'Terminated' : (pod.status?.phase ?? '')

const PHASE_BADGE: Record<string, string> = {
  Running: 'badge-success',
  Pending: 'badge-warning',
  Succeeded: 'badge-secondary',
  Terminated: 'badge-danger',
  CrashLoopBackOff: 'badge-danger',
}

// 4.1's container-state badge mapping (pod-data.html.j2): Running ->
// success, ImagePullBackOff/ErrImagePull/Error/CrashLoopBackOff -> danger,
// PodInitializing -> info, Completed/else -> secondary (grey).
const STATE_BADGE: Record<string, string> = {
  Running: 'badge-success',
  ImagePullBackOff: 'badge-danger',
  ErrImagePull: 'badge-danger',
  Error: 'badge-danger',
  CrashLoopBackOff: 'badge-danger',
  PodInitializing: 'badge-info',
  Completed: 'badge-secondary',
}

// The effective container state: k8s's `state` is a one-of
// ({running}|{waiting}|{terminated}) map — the generated to_dict shape.
// The waiting/terminated values are untrusted cluster metadata: narrowed
// with `in` before reading `reason` (never an unchecked cast).
const containerStateOf = (status?: { state?: Record<string, unknown> }): string => {
  const st = status?.state
  if (!st) return '—'
  if (st.running) return 'Running'
  const waiting = st.waiting
  if (waiting && typeof waiting === 'object' && 'reason' in waiting) {
    return String(waiting.reason ?? 'Waiting')
  }
  const terminated = st.terminated
  if (terminated && typeof terminated === 'object' && 'reason' in terminated) {
    return terminated.reason === 'Completed' ? 'Completed' : 'Terminated'
  }
  return '—'
}

// The Pod tab's Restarts is the SUM of ALL container_statuses'
// restart_counts (4.1 read only container_statuses[0].restart_count — a
// latent 4.1 bug for multi-container pods; 5.0 sums them, the truthful
// value — ratified deviation 3).
const restartsOf = (pod: Pod): number =>
  (pod.status?.container_statuses ?? []).reduce(
    (sum, cs) => sum + (cs.restart_count ?? 0),
    0,
  )

// The 5.0 owner cell (the Service data page's podOwner precedent): the
// first owner reference as `kind.lower() + "/" + name`, plain text (the
// owning-workload views are not yet landed; 4.1's hidden-form owner POST
// is the ADR-0040 delta). "—" when absent.
const ownerOf = (pod: Pod): string => {
  const ref = pod.metadata?.owner_references?.[0]
  if (!ref) return '—'
  return `${String(ref.kind ?? '').toLowerCase()}/${ref.name ?? ''}`
}

// The Related Resources rows (4.1's `Refers To` — from spec): image-pull
// secrets, the service account, secrets (env value_from + volumes),
// configmaps (volumes), PVCs (volumes). Deep-linking (ratified
// 2026-10-28): Secrets link to the LANDED Secret view; the rest render
// plain text (their views are not yet landed — the links would 404).
type RefRow = { type: string; name: string; secret: boolean }

const refersTo = (pod: Pod): RefRow[] => {
  const spec = pod.spec
  const rows: RefRow[] = []
  for (const ips of spec?.image_pull_secrets ?? []) {
    if (ips.name) rows.push({ type: 'ImagePullSecret', name: ips.name, secret: false })
  }
  if (spec?.service_account_name) {
    rows.push({ type: 'ServiceAccount', name: spec.service_account_name, secret: false })
  }
  for (const c of spec?.containers ?? []) {
    for (const e of c.env ?? []) {
      const ref = e.value_from?.secret_key_ref?.name
      if (ref) rows.push({ type: 'Secret', name: ref, secret: true })
    }
  }
  for (const v of spec?.volumes ?? []) {
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
 * 4.1 `workload/pod-data.html.j2` port: one Pod's metadata + the 4.1
 * Containers / Conditions / Security Contexts / Related Resources tables
 * and the full object as a syntax-highlighted block (`JSON.stringify` —
 * the block is JSON text with the truthful `json` highlighter). The read
 * is a SINGLE `?name=&namespace=` fetch (4.1's list-then-filter is
 * dropped). The kind is namespaced (core/v1, snake_case to_dict).
 * `trimAnnotations` is NOT replicated — annotations render verbatim
 * (ratified deviation 7). The "Lables" typo is NOT replicated (ratified
 * deviation 8). 4.1's exec/logs buttons are the pod-exec-logs-views
 * change. The "Refered By" table title is 4.1's, kept verbatim (the
 * e2e-smoke contract pins the list title only; the data title is
 * "Pod Data").
 */
// ADR-0040: identity arrives as props from ObjectRoute (the active ref),
// never from useSearchParams — the URL stays clean (R1). The namespace is
// the ref's namespace (authoritative, R8): never the header's
// selectedNamespace. The legacy /data route (the R7 redirect) passes the
// legacy ?name=/?namespace= through as props; this view no longer reads
// the URL.
const PodDataView = ({ name, namespace }: { name: string; namespace: string }) => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const navigate = useNavigate()

  const query = useQuery<Pod>({
    queryKey: ['workload-pod-data', cluster?.id, namespace, name],
    enabled: cluster != null && name !== '' && namespace !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<Pod>>(
        `/api/v1/clusters/${cluster!.id}/resources/pods?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      const [item] = r.data?.items ?? []
      if (!item) throw new Error(NOT_FOUND)
      return item
    },
  })

  const pod = query.data
  const labels = Object.entries(pod?.metadata?.labels ?? {})
  // VERBATIM (ratified deviation 7: no trimAnnotations).
  const annotations = Object.entries(pod?.metadata?.annotations ?? {})
  const conditions = pod?.status?.conditions ?? []
  const securityContext = Object.entries(pod?.spec?.security_context ?? {})
  const phase = effectivePhase(pod ?? {})
  const refs = refersTo(pod ?? {})
  // spec.containers joined to status.container_statuses by name (the
  // effective state + restart count ride on the status entry).
  const containers = (pod?.spec?.containers ?? []).map((c, i) => {
    const cs = (pod?.status?.container_statuses ?? []).find((s) => s.name === c.name)
    return { name: c.name ?? '', image: c.image ?? '—', state: containerStateOf(cs), restarts: cs?.restart_count ?? 0 }
  })
  const initContainers = (pod?.spec?.init_containers ?? []).map((c, i) => {
    const cs = (pod?.status?.init_container_statuses ?? []).find((s) => s.name === c.name)
    return { name: c.name ?? '', image: c.image ?? '—', state: containerStateOf(cs), restarts: cs?.restart_count ?? 0 }
  })

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Workloads</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/workload/pods" onClick={clearActiveRef}>
              Pod List
            </Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Pod Data</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: pod name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading pod data...</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            // A miss is a state, not an error.
            <div className="text-center text-muted">No pod '{name}' found</div>
          ) : (
            <div className="text-danger">Error loading pod: {query.error.message}</div>
          )
        ) : (
          <>
          <ObjectTabs
            defaultActiveKey="pod"
            tabs={[
              { key: 'pod', label: 'Pod' },
              { key: 'containers', label: 'Containers' },
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
                    <td>{pod?.metadata?.namespace ?? 'N/A'}</td>
                  </tr>
                  <tr>
                    <th scope="row">Name:</th>
                    <td>{pod?.metadata?.name ?? 'N/A'}</td>
                  </tr>
                  <tr>
                    <th scope="row">Status:</th>
                    <td>
                      {phase ? (
                        <span className={`badge ${PHASE_BADGE[phase] ?? 'badge-info'}`}>
                          {phase}
                        </span>
                      ) : (
                        '—'
                      )}
                    </td>
                  </tr>
                  <tr>
                    <th scope="row">Restarts:</th>
                    <td>{restartsOf(pod ?? {})}</td>
                  </tr>
                  <tr>
                    <th scope="row">Created:</th>
                    <td>{formatTimestamp(pod?.metadata?.creation_timestamp)}</td>
                  </tr>
                  <tr>
                    <th scope="row">Node:</th>
                    <td>
                      {pod?.spec?.node_name ? (
                        // Deep-link to the LANDED Nodes view (ratified
                        // deviation 4): cluster-scoped — the ref carries
                        // no namespace. 4.1 used a hidden-form POST; this
                        // is the ADR-0040 openObject delta.
                        <button
                          type="button"
                          className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
                          onClick={() =>
                            openObject('node', pod.spec!.node_name!, undefined, '/cluster/node', navigate)
                          }
                        >
                          {pod.spec.node_name}
                        </button>
                      ) : (
                        '—'
                      )}
                    </td>
                  </tr>
                  <tr>
                    <th scope="row">Owner:</th>
                    <td>{ownerOf(pod ?? {})}</td>
                  </tr>
                  <tr>
                    <th scope="row">Priority:</th>
                    <td>{pod?.spec?.priority != null ? String(pod.spec.priority) : '—'}</td>
                  </tr>
                  <tr>
                    <th scope="row">Priority Class:</th>
                    <td>{pod?.spec?.priority_class_name ?? '—'}</td>
                  </tr>
                  <tr>
                    <th scope="row">Runtime Class:</th>
                    <td>{pod?.spec?.runtime_class_name ?? '—'}</td>
                  </tr>
                  <tr>
                    <th scope="row">Labels:</th>
                    <td>
                      <KeyValueTable entries={labels} empty="No labels" />
                    </td>
                  </tr>
                  <tr>
                    <th scope="row">Annotations:</th>
                    <td>
                      <KeyValueTable entries={annotations} empty="No annotations" />
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
                      <th>State</th>
                      <th>Name</th>
                      <th>Image</th>
                      <th>Restarts</th>
                    </tr>
                  </thead>
                  <tbody>
                    {initContainers.map((c) => (
                      <tr key={c.name}>
                        <td>
                          <span className={`badge ${STATE_BADGE[c.state] ?? 'badge-secondary'}`}>
                            {c.state}
                          </span>
                        </td>
                        <td>{c.name || '—'}</td>
                        <td>{c.image}</td>
                        <td>{c.restarts}</td>
                      </tr>
                    ))}
                  </tbody>
                </CTable>
              )}
              <CTable bordered>
                <caption className="fs-6 fw-bold text-primary">Containers</caption>
                <thead>
                  <tr>
                    <th>State</th>
                    <th>Name</th>
                    <th>Image</th>
                    <th>Restarts</th>
                  </tr>
                </thead>
                <tbody>
                  {containers.map((c) => (
                    <tr key={c.name}>
                      <td>
                        <span className={`badge ${STATE_BADGE[c.state] ?? 'badge-secondary'}`}>
                          {c.state}
                        </span>
                      </td>
                      <td>{c.name || '—'}</td>
                      <td>{c.image}</td>
                      <td>{c.restarts}</td>
                    </tr>
                  ))}
                </tbody>
              </CTable>
            </Fragment>

            <Fragment>
              <CTable bordered>
                <thead>
                  <tr>
                    <th>Condition</th>
                    <th>State</th>
                  </tr>
                </thead>
                <tbody>
                  {conditions.length === 0 ? (
                    <tr>
                      <td colSpan={2} className="text-center text-muted">
                        No conditions
                      </td>
                    </tr>
                  ) : (
                    conditions.map((c, i) => (
                      <tr key={c.type ?? i}>
                        <td>{c.type ?? 'N/A'}</td>
                        <td>{c.status ?? 'N/A'}</td>
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
              <CTable bordered className="mb-3">
                <caption className="fs-6 fw-bold text-primary">Refered By</caption>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Name</th>
                    <th>Namespace</th>
                  </tr>
                </thead>
                <tbody>
                  {pod?.metadata?.owner_references?.length ? (
                    pod.metadata.owner_references.map((ref, i) => (
                      <tr key={`${ref.kind}-${ref.name}-${i}`}>
                        <td>{String(ref.kind ?? '').toLowerCase()}</td>
                        <td>{ref.name ?? '—'}</td>
                        <td>{namespace}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={3} className="text-center text-muted">
                        —
                      </td>
                    </tr>
                  )}
                </tbody>
              </CTable>
              <CTable bordered>
                <caption className="fs-6 fw-bold text-primary">Refers To</caption>
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
              <CCardTitle className="m-0 fw-bold text-primary fs-6">Pod</CCardTitle>
            </CCardHeader>
            <CCardBody>
              <SyntaxHighlighter
                language="json"
                style={anOldHope}
                wrapLongLines
                customStyle={{ margin: 0 }}
                codeTagProps={{ style: { whiteSpace: 'pre-wrap', wordBreak: 'break-word' } }}
              >
                {JSON.stringify(pod, null, 2)}
              </SyntaxHighlighter>
            </CCardBody>
          </CCard>
          </>
        )}
      </CCardBody>
    </CCard>
  )
}

export default PodDataView
