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
import type { PriorityClassItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as SecretData.tsx / NetworkPolicyData.tsx: the hljs language
// module is a singleton, so a second registration is harmless. Register
// `json` — the block is `JSON.stringify` of the to_dict object (a YAML
// subset), so the json grammar is the truthful classifier for the exact text
// rendered. The yaml language was a prior misclassification (its grammar does
// not parse JSON lines), found by the final branch review.
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

/**
 * 4.1 `other-resources/priorityclass-data.html.j2` parity: one
 * PriorityClass's metadata plus the full object as a syntax-highlighted block
 * (`JSON.stringify` of the `to_dict` item — JSON is a YAML subset; ratified
 * delta, final review 2026-10-28: the block is JSON text with the truthful
 * `json` highlighter). The read is a SINGLE `?name=` fetch (not 4.1's
 * list-then-filter); the kind is cluster-scoped, so the URL carries no
 * namespace param. Empty `items` is a not-found STATE (pinned copy), not an
 * error.
 *
 * ADR-0040: identity arrives as props from ObjectRoute (the active ref),
 * never from useSearchParams — the URL stays clean (R1/R8). The legacy
 * /data route (TICKET-07's redirect layer) passes the legacy ?name=
 * through as a prop when it keeps working; this view no longer reads it.
 */
const PriorityClassDataView = ({ name }: { name: string }) => {
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<PriorityClassItem>({
    queryKey: ['priority-class-data', cluster?.id, name],
    enabled: cluster != null && name !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<PriorityClassItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/priorityclasses?name=${encodeURIComponent(name)}`,
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

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Other Resources</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/other-resource/priorityclass">Priority Classes</Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6 d-flex align-items-center gap-2">
          Priority Class Data
        </CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: priority class name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading priority class data...</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            <div className="text-center text-muted">No PriorityClass '{name}' found</div>
          ) : (
            <div className="text-danger">Error loading priority class: {query.error.message}</div>
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
                  <th scope="row">Kind:</th>
                  <td>PriorityClass</td>
                </tr>
                <tr>
                  <th scope="row">Created:</th>
                  <td>{item?.metadata?.creation_timestamp ?? 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Value:</th>
                  <td>{item?.value == null ? 'N/A' : String(item.value)}</td>
                </tr>
                <tr>
                  <th scope="row">Preemption Policy:</th>
                  <td>{item?.preemption_policy || 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Global Default:</th>
                  <td>{item?.global_default == null ? 'N/A' : String(item.global_default)}</td>
                </tr>
                <tr>
                  <th scope="row">Description:</th>
                  <td>{item?.description || 'N/A'}</td>
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
            <CCard className="mb-0">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">Priority Class</CCardTitle>
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

export default PriorityClassDataView
