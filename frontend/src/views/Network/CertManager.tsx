import React, { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
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
} from '@coreui/react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../../lib/api'
import { getActiveRef, openObject } from '../../lib/objectRef'
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
import KubeDataTable, { Column } from '../../components/KubeDataTable'
import TopMenu from '../../components/TopMenu'

// ADR-0040 (2026-10-29-certmanager-external-loadbalancer-views): the four
// cert-manager.io/v1 registry kinds (API resource names) and the ONE clean
// list route this page renders. The 4.1 `/plugins/cert-manager` page is
// re-implemented at /network/cert-manager (the /plugins/ -> /network/ move,
// ratified 2026-10-29 — NO Plugins group revived, ADR-0022 "minus Plugins"
// intact). The CertManagerRoute dispatcher (App.tsx) renders the ref-matched
// CertManagerData for any of the four kinds on this clean route.
// clusterissuer is CLUSTER-scoped (the ref carries no namespace); the other
// three are namespaced (the ref rides the selected namespace, R8).
const LIST_ROUTE = '/network/cert-manager'

type Row = Record<string, unknown>
type TabKey = 'clusterissuers' | 'issuers' | 'certificaterequests' | 'certificates'

// 4.1's Status cell: the LAST status.conditions[] entry's `reason`, in a
// badge — green when its `status === "True"`, red otherwise (the 4.1
// mapping). No conditions -> "—" plain (certainty rule: never guess).
const statusBadge = (conditions: CertManagerCondition[] | undefined) => {
  const last = conditions && conditions.length > 0 ? conditions[conditions.length - 1] : null
  if (!last) return '—'
  const cls = last.status === 'True' ? 'badge-success' : 'badge-danger'
  return (
    <span className={`badge ${cls}`}>{last.reason ?? '—'}</span>
  )
}

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

// The last ownerReference, rendered `<kind>/<name>` (plain text in the
// Certificate Request tab). "—" when there are no owner references.
const lastOwnerText = (ownerReferences: OwnerReference[] | undefined): string => {
  const ref =
    ownerReferences && ownerReferences.length > 0
      ? ownerReferences[ownerReferences.length - 1]
      : null
  if (!ref) return '—'
  return `${ref.kind ?? '—'}/${ref.name ?? '—'}`
}

/**
 * 4.1 `plugins/cert_manager/templates/cert-manager.html.j2` parity: the
 * four cert-manager CRDs as CoreUI tabs (Cluster Issuer / Issuer /
 * Certificate Request / Certificates — the 4.1 order). The card title stays
 * EXACTLY "Cert-Manager Objects" (the e2e-smoke contract). CTabPanel keeps
 * every panel mounted, so all four fetch on mount. ADR-0040: the Name cells
 * are buttons (openObject), never Links — the URL stays clean (R1).
 *
 * 4.1's `goToTab` (the Certificate Request Issuer cell's in-page tab-switch
 * + row-highlight) is re-implemented with the CoreUI CTabs API: a controlled
 * tab switch + the target row's name cell bolded (KubeDataTable exposes no
 * row-class hook — the bold name cell is the 5.0 row highlight).
 */
const CertManagerView = () => {
  const cluster = useClusterStore((s) => s.selectedCluster)
  const namespace = useClusterStore((s) => s.selectedNamespace) ?? 'default'
  const navigate = useNavigate()
  const active = getActiveRef()

  // The 4.1 `goToTab` re-implementation: a tab click clears the highlight;
  // an Issuer-cell click sets BOTH the tab and the highlight directly
  // (bypassing onTabChange so the highlight survives the switch).
  const [activeTab, setActiveTab] = useState<TabKey>('clusterissuers')
  const [highlight, setHighlight] = useState<{ tab: TabKey; name: string } | null>(null)

  const onTabChange = (key: number | string) => {
    setActiveTab(key as TabKey)
    setHighlight(null)
  }

  const goToIssuerTab = (tab: TabKey, name: string) => {
    setActiveTab(tab)
    setHighlight({ tab, name })
  }

  const clusterIssuersQuery = useQuery<Row[]>({
    queryKey: ['cert-manager', 'clusterissuers', cluster?.id],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<ClusterIssuerItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/clusterissuers`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => ({
        name: item.metadata?.name ?? '',
        status: statusBadge(item.status?.conditions),
        type: issuerType(item.spec),
      }))
    },
  })

  const issuersQuery = useQuery<Row[]>({
    queryKey: ['cert-manager', 'issuers', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<IssuerItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/issuers?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => ({
        name: item.metadata?.name ?? '',
        status: statusBadge(item.status?.conditions),
        type: issuerType(item.spec),
      }))
    },
  })

  const certificateRequestsQuery = useQuery<Row[]>({
    queryKey: ['cert-manager', 'certificaterequests', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<CertificateRequestItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/certificaterequests?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => ({
        name: item.metadata?.name ?? '',
        status: statusBadge(item.status?.conditions),
        issuer: item.spec?.issuerRef ?? null,
        owner: lastOwnerText(item.metadata?.ownerReferences),
      }))
    },
  })

  const certificatesQuery = useQuery<Row[]>({
    queryKey: ['cert-manager', 'certificates', cluster?.id, namespace],
    enabled: cluster != null,
    queryFn: async () => {
      const r = await apiFetch<ResourceList<CertificateItem>>(
        `/api/v1/clusters/${cluster!.id}/resources/certificates?namespace=${encodeURIComponent(namespace)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      return (r.data?.items ?? []).map((item) => ({
        name: item.metadata?.name ?? '',
        status: statusBadge(item.status?.conditions),
        secret: item.spec?.secretName ?? null,
        owner:
          item.metadata?.ownerReferences && item.metadata.ownerReferences.length > 0
            ? item.metadata.ownerReferences[item.metadata.ownerReferences.length - 1]
            : null,
      }))
    },
  })

  // One name-cell factory for every tab: the button's openObject call is the
  // ADR-0040 identity write (the ref carries the row's namespace for the
  // namespaced kinds; the cluster-scoped kind carries none) and navigates to
  // this SAME clean route — the CertManagerRoute dispatcher renders the
  // matching detail. The bold is driven by the active ref (R9).
  const isSelected = (kind: string, ns: string | undefined) =>
    active !== null && active.kind === kind && active.namespace === ns

  const nameButton = (
    name: unknown,
    kind: string,
    ns: string | undefined,
    highlighted = false,
  ) =>
    typeof name === 'string' && name ? (
      <button
        type="button"
        className={
          'btn btn-link btn-sm p-0 text-primary text-decoration-underline' +
          (isSelected(kind, ns) || highlighted ? ' fw-bold' : '')
        }
        aria-current={isSelected(kind, ns) ? 'true' : undefined}
        onClick={() => openObject(kind, name, ns, LIST_ROUTE, navigate)}
      >
        {name}
      </button>
    ) : null

  const tabState = (
    query: { isLoading: boolean; error: Error | null; data: Row[] | undefined },
    { loading, empty, errorPrefix }: { loading: string; empty: string; errorPrefix: string },
  ) =>
    query.isLoading ? (
      <div>{loading}</div>
    ) : query.error ? (
      <div className="text-danger">
        {errorPrefix}: {query.error.message}
      </div>
    ) : (query.data ?? []).length === 0 ? (
      <div className="text-center text-muted">{empty}</div>
    ) : null

  const loadState = { loading: 'Loading cert-manager objects...' }
  const errState = { errorPrefix: 'Error loading cert-manager objects' }

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Network</CBreadcrumbItem>
          <CBreadcrumbItem active>Cert-Manager Objects</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Cert-Manager Objects</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!cluster ? (
          <div>No cluster selected.</div>
        ) : (
          <CTabs activeItemKey={activeTab} onChange={onTabChange}>
            <CTab itemKey="clusterissuers">Cluster Issuer</CTab>
            <CTabPanel itemKey="clusterissuers">
              {tabState(clusterIssuersQuery, {
                ...loadState,
                ...errState,
                empty: 'No cluster issuers found',
              }) ?? (
                <KubeDataTable data={clusterIssuersQuery.data ?? []}>
                  <Column title="Status" data="status" />
                  <Column title="Name" data="name">
                    {(name: unknown) =>
                      nameButton(
                        name,
                        'clusterissuer',
                        undefined,
                        highlight?.tab === 'clusterissuers' &&
                          typeof name === 'string' &&
                          highlight.name === name,
                      )
                    }
                  </Column>
                  <Column title="Type" data="type" />
                </KubeDataTable>
              )}
            </CTabPanel>

            <CTab itemKey="issuers">Issuer</CTab>
            <CTabPanel itemKey="issuers">
              {tabState(issuersQuery, {
                ...loadState,
                ...errState,
                empty: 'No issuers found',
              }) ?? (
                <KubeDataTable data={issuersQuery.data ?? []}>
                  <Column title="Status" data="status" />
                  <Column title="Name" data="name">
                    {(name: unknown) =>
                      nameButton(
                        name,
                        'issuer',
                        namespace,
                        highlight?.tab === 'issuers' &&
                          typeof name === 'string' &&
                          highlight.name === name,
                      )
                    }
                  </Column>
                  <Column title="Type" data="type" />
                </KubeDataTable>
              )}
            </CTabPanel>

            <CTab itemKey="certificaterequests">Certificate Request</CTab>
            <CTabPanel itemKey="certificaterequests">
              {tabState(certificateRequestsQuery, {
                ...loadState,
                ...errState,
                empty: 'No certificate requests found',
              }) ?? (
                <KubeDataTable data={certificateRequestsQuery.data ?? []}>
                  <Column title="Status" data="status" />
                  <Column title="Name" data="name">
                    {(name: unknown) => nameButton(name, 'certificaterequest', namespace)}
                  </Column>
                  {/* 4.1's `goToTab`: an in-page tab-switch (to the matching
                      Issuer / Cluster Issuer tab) + row-highlight — NOT a
                      navigation. The KubeDataTable surface has no row-class
                      hook, so the 5.0 row highlight is the target row's
                      bolded name cell. */}
                  <Column title="Issuer" data="issuer">
                    {(value: unknown) => {
                      const ref = value as { name?: string; kind?: string } | null
                      if (!ref?.name) return '—'
                      const tab: TabKey = ref.kind === 'ClusterIssuer' ? 'clusterissuers' : 'issuers'
                      return (
                        <button
                          type="button"
                          className="btn btn-link btn-sm p-0 text-primary text-decoration-underline"
                          onClick={() => goToIssuerTab(tab, ref.name!)}
                        >
                          {`${ref.kind ?? '—'}/${ref.name}`}
                        </button>
                      )
                    }}
                  </Column>
                  <Column title="Owner" data="owner" />
                </KubeDataTable>
              )}
            </CTabPanel>

            <CTab itemKey="certificates">Certificates</CTab>
            <CTabPanel itemKey="certificates">
              {tabState(certificatesQuery, {
                ...loadState,
                ...errState,
                empty: 'No certificates found',
              }) ?? (
                <KubeDataTable data={certificatesQuery.data ?? []}>
                  <Column title="Status" data="status" />
                  <Column title="Name" data="name">
                    {(name: unknown) => nameButton(name, 'certificate', namespace)}
                  </Column>
                  {/* Deep-link to the LANDED Secret data view (the legacy
                      /data URL is a redirect layer — the "deep-link to
                      landed kinds" pattern). */}
                  <Column title="Secret" data="secret">
                    {(value: unknown) =>
                      typeof value === 'string' && value ? (
                        <Link
                          to={`/security/secret/data?name=${encodeURIComponent(value)}&namespace=${encodeURIComponent(namespace)}`}
                        >
                          {value}
                        </Link>
                      ) : (
                        '—'
                      )
                    }
                  </Column>
                  {/* `<kind>/<name>`; a link to the Ingress list ONLY when
                      kind is Ingress (the Ingress view is landed — the
                      "deep-link to landed kinds" pattern), else plain text. */}
                  <Column title="Owner" data="owner">
                    {(value: unknown) => {
                      const ref = value as { kind?: string; name?: string } | null
                      if (!ref?.name) return '—'
                      const text = `${ref.kind ?? '—'}/${ref.name}`
                      return ref.kind === 'Ingress' ? (
                        <Link to="/network/ingress">{text}</Link>
                      ) : (
                        text
                      )
                    }}
                  </Column>
                </KubeDataTable>
              )}
            </CTabPanel>
          </CTabs>
        )}
      </CCardBody>
    </CCard>
  )
}

export default CertManagerView
