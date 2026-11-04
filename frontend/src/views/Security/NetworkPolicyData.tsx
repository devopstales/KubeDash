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
import yaml from 'react-syntax-highlighter/dist/esm/languages/hljs/yaml'
import anOldHope from 'react-syntax-highlighter/dist/esm/styles/hljs/an-old-hope'
import { apiFetch } from '../../lib/api'
import { clearActiveRef } from '../../lib/objectRef'
import { policyUrl } from '../../lib/policyUrl'
import type { CiliumPolicyItem, NetworkPolicyItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as SecretData.tsx: the hljs language module is a singleton, so
// a second registration is harmless. Register only `yaml` — this view shows
// one whole-object block, not SecretData's per key/value `secretLanguage`
// guesser (the wrong classifier for a whole object).
SyntaxHighlighter.registerLanguage('yaml', yaml)

type AnyPolicyItem = NetworkPolicyItem | CiliumPolicyItem

/**
 * 4.1 `security/network-policy-data.html.j2` parity: one policy's metadata
 * plus the full object as YAML. The read is a SINGLE `?name=` fetch per kind
 * (not 4.1's list-then-filter): `policyUrl` maps the `?kind=` param to the
 * resource plural and validates it against the closed POLICY_KINDS enum
 * BEFORE any fetch, so a bad kind renders an error line and never hits the
 * network. Empty `items` is a not-found STATE (pinned copy), not an error.
 * The list view's name links are the sole producer of these query strings.
 */
// ADR-0040: identity arrives as props from ObjectRoute (the active ref),
// never from useSearchParams — the URL stays clean (R1). `kind` is the
// registry kind (the API kind the ref carries); `namespace` is the ref's
// namespace (authoritative, R8 — undefined for the cluster-scoped kind).
// The legacy /data route (TICKET-07's redirect layer) passes the legacy
// ?name=/?kind=/?namespace= through as props when it keeps working; this
// view no longer reads the URL.
const NetworkPolicyDataView = ({
  name,
  kind,
  namespace,
}: {
  name: string
  kind: string
  namespace: string
}) => {
  const cluster = useClusterStore((s) => s.selectedCluster)

  const url = name !== '' && cluster ? policyUrl(kind, cluster.id, name, namespace) : null
  const invalidKind = name !== '' && url === null

  const query = useQuery<AnyPolicyItem>({
    queryKey: ['network-policy-data', cluster?.id, kind, namespace, name],
    enabled: url !== null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<AnyPolicyItem>>(url!)
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      const [item] = r.data?.items ?? []
      if (!item) throw new Error(`not found`)
      return item
    },
  })

  const item = query.data
  const labels = Object.entries(item?.metadata?.labels ?? {})

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Security</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/security/network-policy" onClick={clearActiveRef}>Network Policies</Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6 d-flex align-items-center gap-2">
          Network Policy Data
        </CCardTitle>
      </CCardHeader>
      <CCardBody>
        {invalidKind ? (
          <div className="text-danger">Error: unknown policy kind '{kind}'</div>
        ) : !name ? (
          <div className="text-danger">Error: policy name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading network policy...</div>
        ) : query.error ? (
          query.error.message === 'not found' ? (
            <div className="text-center text-muted">
              No {kind} '{name}' found
            </div>
          ) : (
            <div className="text-danger">Error loading network policy: {query.error.message}</div>
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
                  <td>{namespace || '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Kind:</th>
                  <td>{kind}</td>
                </tr>
                <tr>
                  <th scope="row">Created:</th>
                  <td>{item?.metadata?.creation_timestamp ?? 'N/A'}</td>
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
              </tbody>
            </CTable>
            <CCard className="mb-0">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">Policy</CCardTitle>
              </CCardHeader>
              <CCardBody>
                <SyntaxHighlighter
                  language="yaml"
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

export default NetworkPolicyDataView
