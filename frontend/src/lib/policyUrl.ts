import { POLICY_KINDS, type PolicyKind } from './types'

type NamespacedPolicyKind = 'NetworkPolicy' | 'CiliumNetworkPolicy'

function namespacedUrl(id: number, name: string, ns: string, kind: NamespacedPolicyKind): string {
  const resource = kind === 'NetworkPolicy' ? 'networkpolicies' : 'ciliumnetworkpolicies'
  return `/api/v1/clusters/${id}/resources/${resource}?name=${encodeURIComponent(name)}&namespace=${encodeURIComponent(ns)}`
}

/**
 * Returns the fetch URL for a valid policy kind, or null when `kind` is
 * outside POLICY_KINDS (the caller renders the error line and makes NO
 * fetch). Per-kind arities on purpose (NOT a shared-arity
 * `Record<PolicyKind, …>`): the cluster-scoped kind takes no namespace, so a
 * single signature would let a namespace param slip into its URL — exactly
 * what `detail-clusterwide-omits-namespace` exists to catch.
 */
export function policyUrl(kind: string, id: number, name: string, ns: string): string | null {
  if (!POLICY_KINDS.includes(kind as PolicyKind)) return null
  if (kind === 'CiliumClusterwideNetworkPolicy') {
    // cluster-scoped: the namespace param is intentionally absent
    return `/api/v1/clusters/${id}/resources/ciliumclusterwidenetworkpolicies?name=${encodeURIComponent(name)}`
  }
  return namespacedUrl(id, name, ns, kind as NamespacedPolicyKind)
}
