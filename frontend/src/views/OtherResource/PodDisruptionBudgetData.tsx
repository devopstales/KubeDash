import React from 'react'
import { Link } from 'react-router-dom'
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
import { formatTimestamp } from '../../lib/format'
import type { PodDisruptionBudgetItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as SecretData.tsx / NetworkPolicyData.tsx: the hljs language
// module is a singleton, so a second registration is harmless. Register
// `json` — the block is `JSON.stringify` of the to_dict object (a YAML
// subset), so the json grammar is the truthful classifier for the exact text
// rendered (ratified rule, PriorityClassData final review 2026-10-28).
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

/**
 * 4.1 `other-resources/pod-disruption-budget-data.html.j2` parity: one
 * PodDisruptionBudget's metadata (name, created, namespace, selector,
 * eviction policy, labels, annotations) plus a Status table (allowed
 * disruptions / current healthy / desired) and a typed Conditions table,
 * plus the full object as a syntax-highlighted JSON block. The read is a
 * SINGLE `?name=&namespace=` fetch (not 4.1's list-then-filter); empty
 * `items` is a not-found STATE (pinned copy), not an error. 4.1 deviations
 * (recorded in the change's adr.md): `spec.unhealthy_pod_eviction_policy` is
 * read as a proper list (4.1's trailing-comma tuple bug dropped — 4.1
 * iterated a 1-tuple), the duplicate `Creation` row is collapsed into the
 * single `Created` row, `trimAnnotations` is not replicated (annotations
 * render verbatim), and 4.1's dynamic-key Conditions table is replaced by
 * the typed `Type / Status / Reason / Message` shape (the k8s condition
 * shape is fixed). A missing min/max or a missing status renders "—"
 * (certainty rule: 4.1's Jinja would UndefinedError on a fresh PDB's
 * absent status). The list view's name links are the sole producer of
 * these query strings.
 */
// ADR-0040: identity arrives as props from ObjectRoute (the active ref),
// never from useSearchParams — the URL stays clean (R1). The namespace is
// the ref's namespace (authoritative, R8): never the header's
// selectedNamespace. The legacy /data route (TICKET-07 keeps it working
// until the contract pass) passes the legacy ?name=/?namespace= through as
// props; this view no longer reads the URL.
const PodDisruptionBudgetDataView = ({
  name,
  namespace,
}: {
  name: string
  namespace: string
}) => {
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<PodDisruptionBudgetItem>({
    queryKey: ['pdb-data', cluster?.id, namespace, name],
    enabled: cluster != null && name !== '' && namespace !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<PodDisruptionBudgetItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/poddisruptionbudgets?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      const [item] = r.data?.items ?? []
      if (!item) throw new Error(NOT_FOUND)
      return item
    },
  })

  const item = query.data
  const labels = Object.entries(item?.metadata?.labels ?? {})
  const annotations = Object.entries(item?.metadata?.annotations ?? {})
  // 4.1's Selector row: ONLY match_labels as `key: value` lines — the full
  // selector (including match_expressions) is in the JSON block.
  const selector = Object.entries(item?.spec?.selector?.match_labels ?? {})
  // The k8s API enforces exactly one of min_available/max_unavailable; the
  // status rows below use the controller-computed status.desired (the
  // to_dict field), no client-side floor math — the raw field is the source
  // of truth.
  const conditions = item?.status?.conditions ?? []

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Other Resources</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/other-resource/pod-disruption-budget">Pod Disruption Budget List</Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Pod Disruption Budget Data</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: pod disruption budget name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading pod disruption budget data...</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            <div className="text-center text-muted">No PodDisruptionBudget '{name}' found</div>
          ) : (
            <div className="text-danger">Error loading pod disruption budget: {query.error.message}</div>
          )
        ) : (
          <>
            <CTable bordered>
              <tbody>
                <tr>
                  <th scope="row">Name:</th>
                  <td>{item?.metadata?.name ?? 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Created:</th>
                  <td>{formatTimestamp(item?.metadata?.creation_timestamp) || 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Namespace:</th>
                  <td>{item?.metadata?.namespace ?? 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Selector:</th>
                  <td>
                    {selector.length === 0 ? (
                      '—'
                    ) : (
                      selector.map(([key, value], i) => (
                        <React.Fragment key={key}>
                          {key}: {value}
                          {i < selector.length - 1 && <br />}
                        </React.Fragment>
                      ))
                    )}
                  </td>
                </tr>
                <tr>
                  <th scope="row">Eviction Policy:</th>
                  <td>{item?.spec?.unhealthy_pod_eviction_policy ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Labels:</th>
                  <td>
                    {labels.length === 0 ? (
                      'No labels'
                    ) : (
                      <CTable bordered small className="mb-0">
                        <thead>
                          <tr>
                            <th>Key</th>
                            <th>Value</th>
                          </tr>
                        </thead>
                        <tbody>
                          {labels.map(([key, value]) => (
                            <tr key={key}>
                              <td>{key}</td>
                              <td className="text-break">{value}</td>
                            </tr>
                          ))}
                        </tbody>
                      </CTable>
                    )}
                  </td>
                </tr>
                <tr>
                  <th scope="row">Annotations:</th>
                  <td>
                    {annotations.length === 0 ? (
                      'No annotations'
                    ) : (
                      <CTable bordered small className="mb-0">
                        <thead>
                          <tr>
                            <th>Key</th>
                            <th>Value</th>
                          </tr>
                        </thead>
                        <tbody>
                          {annotations.map(([key, value]) => (
                            <tr key={key}>
                              <td>{key}</td>
                              <td className="text-break">{value}</td>
                            </tr>
                          ))}
                        </tbody>
                      </CTable>
                    )}
                  </td>
                </tr>
              </tbody>
            </CTable>
            <CTable bordered className="mb-4">
              <thead>
                <tr>
                  <th>Key</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Allowed disruptions</td>
                  {/* a fresh PDB has no status: "—" (4.1 would UndefinedError). */}
                  <td>{item?.status?.disruptions_allowed ?? '—'}</td>
                </tr>
                <tr>
                  <td>Current healthy</td>
                  <td>{item?.status?.current_healthy ?? '—'}</td>
                </tr>
                <tr>
                  {/* status.desired is the controller-computed value from
                      to_dict — no client-side floor math. */}
                  <td>Desired</td>
                  <td>{item?.status?.desired ?? '—'}</td>
                </tr>
              </tbody>
            </CTable>
            <CTable bordered className="mb-4">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Reason</th>
                  <th>Message</th>
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
                    <tr key={i}>
                      <td>{c?.type ?? '—'}</td>
                      <td>{c?.status ?? '—'}</td>
                      <td>{c?.reason ?? '—'}</td>
                      <td className="text-break">{c?.message ?? '—'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </CTable>
            <CCard className="mb-0">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">Pod Disruption Budget</CCardTitle>
              </CCardHeader>
              <CCardBody>
                <SyntaxHighlighter
                  language="json"
                  style={anOldHope}
                  wrapLongLines
                  customStyle={{ margin: 0 }}
                  codeTagProps={{ style: { whiteSpace: 'pre-wrap', wordBreak: 'break-word' } }}
                >
                  {JSON.stringify(item, null, 2)}
                </SyntaxHighlighter>
              </CCardBody>
            </CCard>
          </>
        )}
      </CCardBody>
    </CCard>
  )
}

export default PodDisruptionBudgetDataView
