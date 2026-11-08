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
import type {
  CertManagerCondition,
  CertificateItem,
  CertificateRequestItem,
  ClusterIssuerItem,
  IssuerItem,
  IssuerSpec,
  OwnerReference,
  ResourceList,
} from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

// Same pattern as the sibling data views: the hljs language module is a
// singleton, so a second registration is harmless. Register `json` — the
// block is `JSON.stringify` of the full custom object, so the json grammar
// is the truthful classifier for the exact text rendered.
SyntaxHighlighter.registerLanguage('json', json)

const NOT_FOUND = 'not found'

// The closed kind set (validated BEFORE the fetch — a bad kind renders the
// error line with NO network hit). The registry kind (lowercase) maps to
// the API resource plural + the pinned copy set + the scope. clusterissuer
// is CLUSTER-scoped (no namespace param); the other three are namespaced.
// The card title is `Cert-Manager <Type>` (the spec's per-type shape —
// 4.1's fixed "Cert-Manager" title, per-type in 5.0).
const KIND_INFO = {
  clusterissuer: {
    resource: 'clusterissuers',
    label: 'Cluster Issuer',
    title: 'Cert-Manager Cluster Issuer',
    loading: 'Loading cluster issuer data...',
    notFound: (name: string) => `No Cluster Issuer '${name}' found`,
    missingName: 'Error: clusterissuer name not provided',
    namespaced: false,
  },
  issuer: {
    resource: 'issuers',
    label: 'Issuer',
    title: 'Cert-Manager Issuer',
    loading: 'Loading issuer data...',
    notFound: (name: string) => `No Issuer '${name}' found`,
    missingName: 'Error: issuer name not provided',
    namespaced: true,
  },
  certificaterequest: {
    resource: 'certificaterequests',
    label: 'Certificate Request',
    title: 'Cert-Manager Certificate Request',
    loading: 'Loading certificate request data...',
    notFound: (name: string) => `No Certificate Request '${name}' found`,
    missingName: 'Error: certificaterequest name not provided',
    namespaced: true,
  },
  certificate: {
    resource: 'certificates',
    label: 'Certificate',
    title: 'Cert-Manager Certificate',
    loading: 'Loading certificate data...',
    notFound: (name: string) => `No Certificate '${name}' found`,
    missingName: 'Error: certificate name not provided',
    namespaced: true,
  },
} as const

type CertManagerKind = keyof typeof KIND_INFO
type Item = ClusterIssuerItem | IssuerItem | CertificateRequestItem | CertificateItem

const lastCondition = (item: Item): CertManagerCondition | null => {
  const conditions = item.status?.conditions
  return conditions && conditions.length > 0 ? conditions[conditions.length - 1] : null
}

// 4.1's Status cell: the LAST condition's `reason`, badge green when its
// `status === "True"`, red otherwise (the 4.1 mapping).
const statusBadge = (cond: CertManagerCondition | null) => {
  if (!cond) return '—'
  const cls = cond.status === 'True' ? 'badge-success' : 'badge-danger'
  return <span className={`badge ${cls}`}>{cond.reason ?? '—'}</span>
}

// 4.1 `GenerateIssuerData`: the message with `"` stripped (the Jinja
// template rendered the raw message; the helper pre-stripped quotes).
const statusMessage = (cond: CertManagerCondition | null): string =>
  cond?.message ? cond.message.replace(/"/g, '') : '—'

// 4.1 `GenerateIssuerData`'s type classification: a LATER-present key wins
// (the 4.1 if-chain overwrites — selfSigned < ca < acme < vault). 5.0
// renders "Self Signed" (the 4.1 "Sel Signed" typo fixed).
const issuerType = (spec: IssuerSpec | undefined): string => {
  if (!spec) return '—'
  let type = '—'
  if (spec.selfSigned) type = 'Self Signed'
  if (spec.ca) type = 'CA'
  if (spec.acme) type = 'ACME'
  if (spec.vault) type = 'Vault'
  return type
}

// 4.1 `GenerateIssuerData`'s `issuer_data` — 4.1 rendered the raw Python
// dict repr; 5.0 renders it as readable text (the same fields).
const issuerDataText = (spec: IssuerSpec | undefined): string => {
  if (!spec) return '—'
  if (spec.selfSigned) return '—'
  if (spec.ca) return `secret: ${spec.ca.secretName ?? '—'}`
  if (spec.acme) {
    // 4.1's solver scan: each solver contributes at most one challenge
    // (http01 wins over dns01).
    const challenges: string[] = []
    for (const solver of spec.acme.solvers ?? []) {
      if (solver.http01) challenges.push('http01')
      else if (solver.dns01) challenges.push('dns01')
    }
    return `email: ${spec.acme.email ?? '—'}, server: ${spec.acme.server ?? '—'}, challenges: ${
      challenges.length > 0 ? challenges.join(', ') : '—'
    }`
  }
  if (spec.vault) {
    // 4.1's auth classification (a LATER-present key wins).
    const auth = spec.vault.auth
    let text = '—'
    if (auth?.appRole) {
      text = `auth: App Role, roleId: ${auth.appRole.roleId ?? '—'}, secret: ${
        auth.appRole.secretRef?.name ?? '—'
      }`
    }
    if (auth?.tokenSecretRef) {
      text = `auth: Token, secret: ${auth.tokenSecretRef.name ?? '—'}`
    }
    if (auth?.kubernetes) {
      text = `auth: Kubernetes, role: ${auth.kubernetes.role ?? '—'}, serviceAccount: ${
        auth.kubernetes.serviceAccountRef?.name ?? '—'
      }`
    }
    return text
  }
  return '—'
}

// The last ownerReference, rendered `<kind>/<name>`. "—" when there are no
// owner references.
const lastOwnerText = (ownerReferences: OwnerReference[] | undefined): string => {
  const ref =
    ownerReferences && ownerReferences.length > 0
      ? ownerReferences[ownerReferences.length - 1]
      : null
  if (!ref) return '—'
  return `${ref.kind ?? '—'}/${ref.name ?? '—'}`
}

/**
 * 4.1 `plugins/cert_manager/templates/cert-manager-data.html.j2` port: one
 * cert-manager object per registry kind (the 4.1 per-object_type metadata
 * table). ADR-0040: identity arrives as props from the route's dispatcher
 * (the active ref — kind + name + namespace), never from useSearchParams
 * (R1/R8). The single `?name=` request re-fetches by identity (4.1's
 * hidden-form `ast.literal_eval(object_data)` round-trip is NOT
 * replicated). Empty `items` is the kind's pinned not-found STATE (muted,
 * never an error; the CRD-absent state is the same). The page GAINS the
 * full-object JSON block (4.1's data pages had none — a ratified 5.0
 * deviation).
 */
const CertManagerDataView = ({
  name,
  kind,
  namespace,
}: {
  name: string
  kind: string
  namespace: string
}) => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const info = KIND_INFO[kind as CertManagerKind]

  const query = useQuery<Item>({
    queryKey: ['cert-manager-data', kind, cluster?.id, name, namespace],
    enabled: cluster != null && name !== '' && info !== undefined,
    queryFn: async () => {
      const url =
        `/api/v1/clusters/${cluster!.id}/resources/${info!.resource}?name=${encodeURIComponent(name)}` +
        (info!.namespaced ? `&namespace=${encodeURIComponent(namespace)}` : '')
      const r = await apiFetch<ResourceList<Item>>(url)
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      const [item] = r.data?.items ?? []
      if (!item) throw new Error(NOT_FOUND)
      return item
    },
  })

  // The closed-set validation (bad kind → error line, no fetch — the query
  // is disabled for a bad kind).
  if (!info) {
    return (
      <CCard className="shadow mb-4">
        <TopMenu>
          <CBreadcrumb className="my-0" aria-label="breadcrumb">
            <CBreadcrumbItem>Network</CBreadcrumbItem>
            <CBreadcrumbItem>
              <Link to="/network/cert-manager" onClick={clearActiveRef}>
                Cert-Manager Objects
              </Link>
            </CBreadcrumbItem>
            <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
          </CBreadcrumb>
        </TopMenu>
        <CCardHeader className="py-3">
          <CCardTitle className="m-0 fw-bold text-primary fs-6">Cert-Manager Data</CCardTitle>
        </CCardHeader>
        <CCardBody>
          <div className="text-danger">Error: unknown cert-manager kind: {kind || '(none)'}</div>
        </CCardBody>
      </CCard>
    )
  }

  const item = query.data
  const cond = item ? lastCondition(item) : null

  // The 4.1 per-object_type row set (the 5.0 additions are the Status
  // badge + the JSON block; 4.1's "Status" text and the raw dict renders
  // are the 5.0 readability deltas).
  const kindRows: { label: string; value: React.ReactNode }[] = []
  if (item) {
    if (kind === 'clusterissuer' || kind === 'issuer') {
      const i = item as ClusterIssuerItem | IssuerItem
      if (kind === 'clusterissuer') {
        // The 4.1 shape: Cluster Issuer has the Issuer Type row; Issuer
        // does not.
        kindRows.push({ label: 'Issuer Type', value: issuerType(i.spec) })
      }
      kindRows.push({ label: 'Issuer Data', value: issuerDataText(i.spec) })
    } else if (kind === 'certificaterequest') {
      const cr = item as CertificateRequestItem
      kindRows.push(
        {
          label: 'Issuer',
          value: cr.spec?.issuerRef?.name
            ? `${cr.spec.issuerRef.kind ?? '—'}/${cr.spec.issuerRef.name}`
            : '—',
        },
        { label: 'Owner', value: lastOwnerText(cr.metadata?.ownerReferences) },
      )
    } else {
      const c = item as CertificateItem
      kindRows.push(
        { label: 'Validity Not After', value: c.status?.notAfter ?? '—' },
        {
          label: 'Certificate',
          value: c.spec?.secretName ? (
            // Deep-link to the LANDED Secret data view (the legacy /data
            // URL is a redirect layer).
            <Link
              to={`/security/secret/data?name=${encodeURIComponent(c.spec.secretName)}&namespace=${encodeURIComponent(namespace)}`}
            >
              {c.spec.secretName}
            </Link>
          ) : (
            '—'
          ),
        },
        {
          label: 'Hostnames',
          value: c.spec?.dnsNames && c.spec.dnsNames.length > 0 ? (
            // 4.1 rendered one hostname per line.
            c.spec.dnsNames.map((h) => (
              <React.Fragment key={h}>
                {h}
                <br />
              </React.Fragment>
            ))
          ) : (
            '—'
          ),
        },
      )
    }
  }

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Network</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/network/cert-manager" onClick={clearActiveRef}>
              Cert-Manager Objects
            </Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">{info.title}</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">{info.missingName}</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>{info.loading}</div>
        ) : query.error ? (
          query.error.message === NOT_FOUND ? (
            <div className="text-center text-muted">{info.notFound(name)}</div>
          ) : (
            <div className="text-danger">
              Error loading {info.label.toLowerCase()}: {query.error.message}
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
                  <th scope="row">Status:</th>
                  <td>{statusBadge(cond)}</td>
                </tr>
                <tr>
                  <th scope="row">Status message:</th>
                  <td>{statusMessage(cond)}</td>
                </tr>
                {kindRows.map((row) => (
                  <tr key={row.label}>
                    <th scope="row">{row.label}:</th>
                    <td>{row.value}</td>
                  </tr>
                ))}
              </tbody>
            </CTable>
            <CCard className="mb-0 mt-3">
              <CCardHeader className="py-2">
                <CCardTitle className="m-0 fw-bold text-primary fs-6">{info.label}</CCardTitle>
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

export default CertManagerDataView
