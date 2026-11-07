import React, { useState } from 'react'
import {
  CButton,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CFormSelect,
  CTab,
  CTabPanel,
  CTabs,
} from '@coreui/react'
import { useQueryClient } from '@tanstack/react-query'
import { Light as SyntaxHighlighter } from 'react-syntax-highlighter'
import yaml from 'react-syntax-highlighter/dist/esm/languages/hljs/yaml'
import anOldHope from 'react-syntax-highlighter/dist/esm/styles/hljs/an-old-hope'
import { apiFetch } from '../../lib/api'
import { toYaml } from '../../lib/yaml'
import type { ApplyResult, GatewayConvertResult } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'

// The converter's display serializer is part of this module's surface: the
// preview tests import toYaml from here (the apply path sends raw dicts).
export { toYaml }

// The yaml grammar module is a singleton; a second registration is harmless
// (SecretData / NetworkPolicyData register it too). The preview text is our
// own toYaml output, so yaml is the truthful classifier for the exact text.
SyntaxHighlighter.registerLanguage('yaml', yaml)

interface GatewayConverterProps {
  name: string
  namespace: string
}

/**
 * Ingress -> Gateway API converter (R7/R8). Rendered INLINE, not a CModal —
 * the repo convention (the portal overlay is invisible to jsdom's default
 * queries; BindModal / the Users panels are the precedent).
 *
 * Flow: provider select (envoy default / traefik) -> Convert
 * (POST /gateway-api/convert) -> per-resource YAML preview tabs + the
 * warnings line (dropped annotations) -> Apply (POST /resources/apply, the
 * first generic mutation; a 403 is all-or-nothing — the SAR phase denied
 * BEFORE anything was created) -> per-object result (created/unchanged
 * green, errors red) -> the 'gateway-api' query prefix is invalidated so
 * the four Gateway API tab queries go stale and refetch on next mount (the
 * applied resources appear without a manual refresh).
 */
const GatewayConverter = ({ name, namespace }: GatewayConverterProps) => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const queryClient = useQueryClient()
  const [provider, setProvider] = useState('envoy')
  const [converting, setConverting] = useState(false)
  const [result, setResult] = useState<GatewayConvertResult | null>(null)
  const [convertError, setConvertError] = useState<string | null>(null)
  const [applying, setApplying] = useState(false)
  const [applyResult, setApplyResult] = useState<ApplyResult | null>(null)
  const [applyError, setApplyError] = useState<string | null>(null)

  const convert = async () => {
    if (!cluster) return
    setConverting(true)
    setConvertError(null)
    setApplyResult(null)
    setApplyError(null)
    const r = await apiFetch<GatewayConvertResult>(
      `/api/v1/clusters/${cluster.id}/gateway-api/convert`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ingressName: name, namespace, provider }),
      },
    )
    setConverting(false)
    if (r.error) {
      setConvertError(`${r.error.code}: ${r.error.message}`)
      return
    }
    setResult(r.data)
  }

  const apply = async () => {
    if (!cluster || !result) return
    setApplying(true)
    setApplyError(null)
    const r = await apiFetch<ApplyResult>(
      `/api/v1/clusters/${cluster.id}/resources/apply`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ namespace, objects: result.resources }),
      },
    )
    setApplying(false)
    if (r.error) {
      // 403 (RBAC_DENIED) means the all-or-nothing SAR phase denied before
      // any object was created — surface it, nothing was applied.
      setApplyError(`${r.error.code}: ${r.error.message}`)
      return
    }
    setApplyResult(r.data)
    // The load-bearing re-fetch link: the shared 'gateway-api' prefix marks
    // all four tab queries stale (they refetch on next mount).
    void queryClient.invalidateQueries({ queryKey: ['gateway-api'] })
  }

  return (
    <CCard className="mb-3 border-primary">
      <CCardHeader>
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Convert to Gateway API</CCardTitle>
      </CCardHeader>
      <CCardBody>
        <div className="d-flex align-items-center gap-2">
          <CFormSelect
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
            style={{ maxWidth: 180 }}
            aria-label="Gateway API provider"
          >
            <option value="envoy">envoy</option>
            <option value="traefik">traefik</option>
          </CFormSelect>
          <CButton
            color="primary"
            size="sm"
            onClick={() => void convert()}
            disabled={converting || applying}
          >
            {converting ? 'Converting...' : 'Convert'}
          </CButton>
        </div>
        {convertError && <div className="text-danger mt-2">{convertError}</div>}
        {result && (
          <>
            {result.warnings.length > 0 && (
              <>
                <div className="text-warning mt-2">
                  {`${result.warnings.length} annotation${result.warnings.length === 1 ? '' : 's'} has no Gateway API equivalent and were dropped:`}
                </div>
                {result.warnings.map((w) => (
                  <div key={w} className="text-warning">
                    {w}
                  </div>
                ))}
              </>
            )}
            <CTabs
              className="mt-3"
              defaultActiveItemKey={`${result.resources[0].kind}-${result.resources[0].metadata.name}`}
            >
              {result.resources.map((res) => {
                const itemKey = `${res.kind}-${res.metadata.name}`
                return (
                  <React.Fragment key={itemKey}>
                    <CTab itemKey={itemKey}>{`${res.kind} ${res.metadata.name}`}</CTab>
                    <CTabPanel itemKey={itemKey}>
                      <SyntaxHighlighter
                        language="yaml"
                        style={anOldHope}
                        wrapLongLines
                        customStyle={{ margin: 0 }}
                        codeTagProps={{ style: { whiteSpace: 'pre-wrap', wordBreak: 'break-word' } }}
                      >
                        {toYaml(res)}
                      </SyntaxHighlighter>
                    </CTabPanel>
                  </React.Fragment>
                )
              })}
            </CTabs>
            <CButton
              color="success"
              size="sm"
              className="mt-3"
              onClick={() => void apply()}
              disabled={applying || converting}
            >
              {applying ? 'Applying...' : 'Apply'}
            </CButton>
            {applyError && <div className="text-danger mt-2">{applyError}</div>}
            {applyResult && (
              <div className="mt-2">
                {applyResult.applied.map((a) => (
                  <div key={`${a.kind}-${a.name}`} className="text-success">
                    {a.kind} {a.name}: {a.status}
                  </div>
                ))}
                {applyResult.errors.map((e) => (
                  <div key={`${e.kind}-${e.name}`} className="text-danger">
                    {e.kind} {e.name}: {e.message}
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </CCardBody>
    </CCard>
  )
}

export default GatewayConverter
