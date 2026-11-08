import { Link } from 'react-router-dom'
import {
  CBreadcrumb,
  CBreadcrumbItem,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CTabs,
  CTab,
  CTabPanel,
  CTable,
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { Light as SyntaxHighlighter } from 'react-syntax-highlighter'
import json from 'react-syntax-highlighter/dist/esm/languages/hljs/json'
import anOldHope from 'react-syntax-highlighter/dist/esm/styles/hljs/an-old-hope'
import { apiFetch } from '../../lib/api'
import { clearActiveRef } from '../../lib/objectRef'
import { formatTimestamp } from '../../lib/format'
import type { Pod, ResourceList, ServiceItem } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as the sibling data views: the hljs language module is a
// singleton, so a second registration is harmless. Register `json` — the
// block is `JSON.stringify` of the to_dict object, so the json grammar is
// the truthful classifier for the exact text rendered (ratified
// 2026-10-28, PriorityClassData final review).
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

// 4.1's External IP: status.load_balancer.ingress[0].ip for a LoadBalancer,
// else "—". The 4.1 deep index 500s on a pending LoadBalancer with no
// ingress yet — 5.0 renders "—" for absent ingress/ip (certainty rule:
// never crash the row).
const externalIp = (item: ServiceItem): string => {
  if (item.spec?.type !== 'LoadBalancer') return '—'
  const ingress = item.status?.load_balancer?.ingress?.[0]
  return ingress?.ip ?? '—'
}

// The 4.1 `k8sPodSelectorListGet` labelSelector format: a comma-separated
// key=value equality expression built from spec.selector (the view has the
// dict; the route forwards the plain string, unvalidated).
const selectorToLabelSelector = (
  selector: Record<string, string> | undefined,
): string => Object.entries(selector ?? {}).map(([k, v]) => `${k}=${v}`).join(',')

// 4.1's four-tier pod phase badge (the 5.0 CoreUI badge classes):
// Running -> success, Pending -> warning, Succeeded -> secondary, else info.
const PHASE_BADGE: Record<string, string> = {
  Running: 'badge-success',
  Pending: 'badge-warning',
  Succeeded: 'badge-secondary',
}

// The 4.1 `"%ss/%s" % (owner.kind.lower(), owner.name)` format — the stray
// `s` was a 4.1 typo; 5.0 renders the conventional `kind.name` form
// (kind lowercased). "—" when there are no owner references.
const podOwner = (pod: Pod): string => {
  const ref = pod.metadata?.owner_references?.[0]
  if (!ref) return '—'
  return `${String(ref.kind ?? '').toLowerCase()}/${ref.name ?? ''}`
}

const KeyValueTable = ({ entries, empty }: { entries: [string, string][]; empty: string }) =>
  entries.length === 0 ? (
    <>{empty}</>
  ) : (
    <CTable bordered small className="mb-0">
      <thead>
        <tr>
          <th>Key</th>
          <th>Value</th>
        </tr>
      </thead>
      <tbody>
        {entries.map(([key, value]) => (
          <tr key={key}>
            <td>{key}</td>
            <td className="text-break">{value}</td>
          </tr>
        ))}
      </tbody>
    </CTable>
  )

/**
 * 4.1 `network/service-data.html.j2` port: one Service as a THREE-tab page
 * (Service / Ports / Pods — CoreUI `CTabs`/`CTab`/`CTabPanel`, NOT 4.1's
 * Bootstrap-JS `data-bs-toggle` tabs). The Service tab is a CTable (the
 * 4.1 row set, "Lables" typo fixed) + the full-object JSON block (a 5.0
 * addition). The Ports tab is one CTable row per `spec.ports` entry. The
 * Pods tab is fed by a SECOND query on the pods route with `?labelSelector=`
 * (built from `spec.selector`; fired ONLY when the selector is non-empty —
 * a headless/ExternalName Service must not fetch pods).
 *
 * ADR-0040: identity arrives as props from the route (the active ref),
 * never from useSearchParams — the URL stays clean (R1). The namespace IS
 * the ref's namespace (R8); an empty namespace falls back to the
 * header-selected one (the spec's missing-namespace rule) and the resolved
 * value is sent in both requests.
 *
 * 4.1 deviations: trimAnnotations is NOT replicated (annotations render
 * verbatim — the JSON block has the full object); the pod/node cells are
 * plain text (no pod-data destination yet; the node link is a non-goal);
 * the pod owner format is fixed; the External IP deep-index 500 is fixed.
 */
const ServiceDataView = ({ name, namespace: namespaceProp }: { name: string; namespace: string }) => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const storeNamespace = useClusterStore((s) => s.selectedNamespace)
  // The ref's namespace is authoritative (R8); a missing one falls back to
  // the header store (the spec's missing-namespace rule — the page only
  // renders with a cluster, so the store value is available).
  const namespace = namespaceProp || storeNamespace || 'default'

  const query = useQuery<ServiceItem>({
    queryKey: ['service-data', cluster?.id, name, namespace],
    enabled: cluster != null && name !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<ServiceItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/services?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      const [item] = r.data?.items ?? []
      if (!item) throw new Error(NOT_FOUND)
      return item
    },
  })

  const service = query.data
  const labelSelector = selectorToLabelSelector(service?.spec?.selector)

  // The SECOND fetch: the pods matching the Service's selector. `enabled`
  // requires a RESOLVED service with a non-empty selector — NO fetch at all
  // for a headless/ExternalName Service (the load-bearing gate).
  const podsQuery = useQuery<ResourceList<Pod>>({
    queryKey: ['service-pods', cluster?.id, namespace, name, labelSelector],
    enabled: cluster != null && name !== '' && service != null && labelSelector !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<Pod>>(
        `/api/v1/clusters/${cluster!.id}/resources/pods?namespace=${encodeURIComponent(namespace)}&labelSelector=${encodeURIComponent(labelSelector)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return r.data ?? { items: [] }
    },
  })

  const labels = Object.entries(service?.metadata?.labels ?? {})
  // Annotations render VERBATIM (no trimAnnotations — the 4.1 inline
  // last-applied-configuration filter is NOT replicated).
  const annotations = Object.entries(service?.metadata?.annotations ?? {})
  const ports = service?.spec?.ports ?? []
  const pods = podsQuery.data?.items ?? []
  const podsEnabled =
    cluster != null && name !== '' && service != null && labelSelector !== ''

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Network</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/network/service" onClick={clearActiveRef}>
              Service List
            </Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Service Data</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: service name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading service data...</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            <div className="text-center text-muted">No Service '{name}' found</div>
          ) : (
            <div className="text-danger">Error loading service: {query.error.message}</div>
          )
        ) : (
          <CTabs defaultActiveItemKey="service">
            <CTab itemKey="service">Service</CTab>
            <CTabPanel itemKey="service">
              <CTable bordered>
                <tbody>
                  <tr>
                    <th scope="row">Name:</th>
                    <td>{service?.metadata?.name ?? 'N/A'}</td>
                  </tr>
                  <tr>
                    <th scope="row">Type:</th>
                    <td>{service?.spec?.type ?? '—'}</td>
                  </tr>
                  <tr>
                    <th scope="row">Created:</th>
                    <td>{formatTimestamp(service?.metadata?.creation_timestamp)}</td>
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
                    <th scope="row">Cluster IP:</th>
                    <td>{service?.spec?.cluster_ip ?? '—'}</td>
                  </tr>
                  <tr>
                    <th scope="row">External IP:</th>
                    <td>{externalIp(service ?? {})}</td>
                  </tr>
                </tbody>
              </CTable>
              <CCard className="mb-0 mt-3">
                <CCardHeader className="py-2">
                  <CCardTitle className="m-0 fw-bold text-primary fs-6">Service</CCardTitle>
                </CCardHeader>
                <CCardBody>
                  <SyntaxHighlighter
                    language="json"
                    style={anOldHope}
                    wrapLongLines
                    customStyle={{ margin: 0 }}
                    codeTagProps={{ style: { whiteSpace: 'pre-wrap', wordBreak: 'break-word' } }}
                  >
                    {JSON.stringify(service, null, 2)}
                  </SyntaxHighlighter>
                </CCardBody>
              </CCard>
            </CTabPanel>

            <CTab itemKey="ports">Ports</CTab>
            <CTabPanel itemKey="ports">
              {ports.length === 0 ? (
                <div>No ports</div>
              ) : (
                <CTable bordered>
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Port</th>
                      <th>Protocol</th>
                      <th>Target</th>
                      <th>Node Port</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ports.map((port, i) => (
                      <tr key={port.name ?? i}>
                        <td>{port.name ?? '—'}</td>
                        <td>{port.port ?? '—'}</td>
                        <td>{port.protocol ?? '—'}</td>
                        <td>{port.target_port ?? '—'}</td>
                        <td>{port.node_port ?? '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </CTable>
              )}
            </CTabPanel>

            <CTab itemKey="pods">Pods</CTab>
            <CTabPanel itemKey="pods">
              {!podsEnabled ? (
                // No selector (headless/ExternalName) — no fetch, first-class
                // empty state (muted, NOT an error).
                <div className="text-muted">No pods match this service's selector</div>
              ) : podsQuery.isLoading ? (
                <div>Loading pods...</div>
              ) : podsQuery.error ? (
                <div className="text-danger">
                  Error loading pods: {podsQuery.error.message}
                </div>
              ) : pods.length === 0 ? (
                // The selector matched nothing — the SAME muted empty state
                // (the 4.1 page rendered the table with no rows; 5.0 states
                // it).
                <div className="text-muted">No pods match this service's selector</div>
              ) : (
                <CTable bordered>
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Name</th>
                      <th>IP</th>
                      <th>Node</th>
                      <th>Owner</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pods.map((pod, i) => (
                      <tr key={pod.metadata?.name ?? i}>
                        <td>
                          {pod.status?.phase ? (
                            <span
                              className={`badge ${
                                PHASE_BADGE[pod.status.phase] ?? 'badge-info'
                              }`}
                            >
                              {pod.status.phase}
                            </span>
                          ) : (
                            '—'
                          )}
                        </td>
                        <td>{pod.metadata?.name ?? '—'}</td>
                        <td>{pod.status?.pod_ip ?? '—'}</td>
                        <td>{pod.spec?.node_name ?? '—'}</td>
                        <td>{podOwner(pod)}</td>
                      </tr>
                    ))}
                  </tbody>
                </CTable>
              )}
            </CTabPanel>
          </CTabs>
        )}
      </CCardBody>
    </CCard>
  )
}

export default ServiceDataView
