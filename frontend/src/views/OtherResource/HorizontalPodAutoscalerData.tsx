import React from 'react'
import { Link, useSearchParams } from 'react-router-dom'
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
import type { HorizontalPodAutoscalerItem, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as SecretData.tsx / NetworkPolicyData.tsx: the hljs language
// module is a singleton, so a second registration is harmless. Register
// `json` — the block is `JSON.stringify` of the to_dict object (a YAML
// subset), so the json grammar is the truthful classifier for the exact text
// rendered (ratified rule, PriorityClassData final review 2026-10-28).
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

// 4.1 read the conditions from the legacy
// autoscaling.alpha.kubernetes.io/conditions annotation (a json.loads of
// the value); modern HPAs carry them on status.conditions. Read
// status.conditions first, fall back to the annotation (4.1's source).
// A malformed/absent annotation renders [] (No conditions), never throws.
const LEGACY_CONDITIONS = 'autoscaling.alpha.kubernetes.io/conditions'
const conditionsOf = (item: HorizontalPodAutoscalerItem | undefined) => {
  const statusConds = item?.status?.conditions
  if (statusConds && statusConds.length) return statusConds
  const raw = item?.metadata?.annotations?.[LEGACY_CONDITIONS]
  if (!raw) return []
  try {
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? parsed : []
  } catch {
    return []
  }
}

/**
 * 4.1 `other-resources/hpa-data.html.j2` port: one HorizontalPodAutoscaler's
 * metadata plus the 4.1 Conditions table and the full object as a
 * syntax-highlighted block (`JSON.stringify` — the block is JSON text with
 * the truthful `json` highlighter). The read is a SINGLE
 * `?name=&namespace=` fetch (4.1's list-then-filter is dropped; the list
 * view's name links are the sole producer of these query strings). The kind
 * is namespaced (autoscaling/v1, core, snake_case to_dict). The Conditions
 * table reads `status.conditions` first, then the legacy
 * `autoscaling.alpha.kubernetes.io/conditions` annotation (4.1's source —
 * 4.1 read ONLY the annotation, so modern HPAs had an empty table); the
 * dynamic-key table is the typed `Type / Status / Last Transition Time /
 * Reason / Message` shape (ratified deviation). The Metrics row keeps 4.1's
 * legacy v1 CPU target (`UNKNOWN` literal for an absent current). The Owner
 * link (4.1's `/workload/<kind-lower>s`) is dropped — plain text; the full
 * `scale_target_ref` is in the JSON block. `trimAnnotations` is not
 * replicated — annotations render verbatim. Empty `items` is a not-found
 * STATE (pinned copy), not an error. Placement under Other Resources is a
 * ratified deviation (ADR-0022).
 */
const HorizontalPodAutoscalerDataView = () => {
  const [params] = useSearchParams()
  const name = params.get('name') ?? ''
  const namespace = params.get('namespace') ?? ''
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<HorizontalPodAutoscalerItem>({
    queryKey: ['hpa-data', cluster?.id, namespace, name],
    enabled: cluster != null && name !== '' && namespace !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<HorizontalPodAutoscalerItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/horizontalpodautoscalers?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(namespace)}`,
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
  const conditions = conditionsOf(item)

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Other Resources</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/other-resource/horizontal-pod-autoscaler">
              Horizontal Pod Autoscaler List
            </Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">
          Horizontal Pod Autoscaler Data
        </CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: horizontal pod autoscaler name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading horizontal pod autoscaler data...</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            // A miss is a state, not an error.
            <div className="text-center text-muted">
              No HorizontalPodAutoscaler '{name}' found
            </div>
          ) : (
            <div className="text-danger">
              Error loading horizontal pod autoscaler: {query.error.message}
            </div>
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
                  <td>{formatTimestamp(item?.metadata?.creation_timestamp)}</td>
                </tr>
                <tr>
                  <th scope="row">Namespace:</th>
                  <td>{item?.metadata?.namespace ?? 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Owner:</th>
                  <td>{item?.spec?.scale_target_ref?.name ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Metrics:</th>
                  <td>
                    {`${item?.status?.current_cpu_utilization_percentage ?? 'UNKNOWN'} / ${
                      item?.spec?.target_cpu_utilization_percentage ?? '—'
                    } %`}
                  </td>
                </tr>
                <tr>
                  <th scope="row">Min Replicas:</th>
                  <td>{item?.spec?.min_replicas ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Max Replicas:</th>
                  <td>{item?.spec?.max_replicas ?? '—'}</td>
                </tr>
                <tr>
                  <th scope="row">Replicas:</th>
                  <td>
                    {`${item?.status?.current_replicas ?? '—'} Current / ${
                      item?.status?.desired_replicas ?? '—'
                    } Desired`}
                  </td>
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
            <CTable bordered className="mt-4">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Last Transition Time</th>
                  <th>Reason</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {conditions.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="text-center text-muted">
                      No conditions
                    </td>
                  </tr>
                ) : (
                  conditions.map((c, i) => {
                    const cond = c as {
                      type?: string
                      status?: string
                      last_transition_time?: string
                      reason?: string
                      message?: string
                      lastTransitionTime?: string
                    }
                    return (
                      <tr key={cond?.type ?? i}>
                        <td>{cond?.type ?? 'N/A'}</td>
                        <td>{cond?.status ?? 'N/A'}</td>
                        <td>{cond?.last_transition_time ?? cond?.lastTransitionTime ?? 'N/A'}</td>
                        <td>{cond?.reason ?? 'N/A'}</td>
                        <td>{cond?.message ?? 'N/A'}</td>
                      </tr>
                    )
                  })
                )}
              </tbody>
            </CTable>
            <CCard className="mb-0 mt-4">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">HorizontalPodAutoscaler</CCardTitle>
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

export default HorizontalPodAutoscalerDataView
