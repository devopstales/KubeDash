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
import { clearActiveRef } from '../../lib/objectRef'
import { formatTimestamp } from '../../lib/format'
import type { ConfigMapItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as SecretData.tsx / NetworkPolicyData.tsx: the hljs language
// module is a singleton, so a second registration is harmless. Register
// `json` — the block is `JSON.stringify` of the to_dict object (a YAML
// subset), so the json grammar is the truthful classifier for the exact
// text rendered (ratified rule, PriorityClassData final review 2026-10-28).
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

/**
 * 4.1 `storage/configmap-data.html.j2` parity: one ConfigMap's metadata
 * (name, namespace, kind, created, version, labels, annotations) plus the
 * 4.1 per-key Data table (one row per `data` entry, value in a
 * `<pre><code>` block) plus the full object as a syntax-highlighted JSON
 * block. The read is a SINGLE `?name=&namespace=` fetch (not 4.1's
 * list-then-filter); empty `items` is a not-found STATE (pinned copy), not
 * an error. 4.1 deviations (briefing.md): the "Lables" typo is NOT
 * replicated (Labels); trimAnnotations is NOT replicated (annotations
 * render verbatim, including last-applied-configuration — unlike the
 * Secret view); the per-key value is plain `<pre><code>` text — NO base64
 * decode, NO `secretLanguage` heuristic (ConfigMap `data` values are plain
 * strings, unlike a Secret's base64 `data`; the `SecretValue` component's
 * decode + eye toggle is Secret-only).
 */
// ADR-0040: identity arrives as props from ObjectRoute (the active ref),
// never from useSearchParams — the URL stays clean (R1). The namespace is
// the ref's namespace (authoritative, R8): never the header's
// selectedNamespace. This kind was a stub until this change: the /data
// URL never shipped, so there is no legacy route (no R7 redirect).
const ConfigMapDataView = ({ name, namespace }: { name: string; namespace: string }) => {
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<ConfigMapItem>({
    queryKey: ['configmap-data', cluster?.id, namespace, name],
    enabled: cluster != null && name !== '' && namespace !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<ConfigMapItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/configmaps?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      const [item] = r.data?.items ?? []
      if (!item) throw new Error(NOT_FOUND)
      return item
    },
  })

  const item = query.data
  const labels = Object.entries(item?.metadata?.labels ?? {})
  // 4.1's trimAnnotations (lib/helper_functions.py): the two machine-managed
  // keys are dropped from the rendered annotations. Replicated 2026-11-05 per
  // user request (overrides the 2026-10-28 "render verbatim" recorded
  // deviation; the HPA view already trims — 46929a10). The JSON block still
  // renders the full object.
  const annotations = Object.entries(item?.metadata?.annotations ?? {}).filter(
    ([key]) =>
      key !== 'kubectl.kubernetes.io/last-applied-configuration'
      && key !== 'autoscaling.alpha.kubernetes.io/conditions',
  )
  // 4.1's per-key Data table, one row per entry.
  const data = Object.entries(item?.data ?? {})

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Storage</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/storage/configmap" onClick={clearActiveRef}>
              Configmaps List
            </Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Configmap Data</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: configmap name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading configmap data...</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            <div className="text-center text-muted">No ConfigMap '{name}' found</div>
          ) : (
            <div className="text-danger">Error loading configmap: {query.error.message}</div>
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
                  <th scope="row">Namespace:</th>
                  <td>{item?.metadata?.namespace ?? namespace}</td>
                </tr>
                <tr>
                  <th scope="row">Kind:</th>
                  <td>ConfigMap</td>
                </tr>
                <tr>
                  <th scope="row">Created:</th>
                  <td>{formatTimestamp(item?.metadata?.creation_timestamp) || 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Version:</th>
                  <td>{item?.metadata?.resource_version ?? '—'}</td>
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
            {/* 4.1's per-key Data table, one row per entry. The value is a
                plain string (NOT base64, unlike a Secret's data) — no
                decode, no secretLanguage heuristic, no eye toggle. The
                <pre><code> block keeps 4.1's pre-wrap + break-word (its
                manual < and > escaping is implicit in React's text
                rendering — no manual escaping needed). */}
            {data.length > 0 ? (
              <CTable bordered className="mb-0">
                <tbody>
                  {data.map(([key, value]) => (
                    <tr key={key}>
                      <th scope="row" className="text-nowrap">
                        {key}:
                      </th>
                      <td className="w-100">
                        <pre className="mb-0" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                          <code>{value}</code>
                        </pre>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </CTable>
            ) : (
              <div className="text-muted">No data</div>
            )}
            <CCard className="mb-0">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">ConfigMap</CCardTitle>
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

export default ConfigMapDataView
