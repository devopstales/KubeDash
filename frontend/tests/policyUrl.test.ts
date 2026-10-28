import { expect, test } from 'vitest'
import { policyUrl } from '../src/lib/policyUrl'

// The kind → fetch URL contract (Task 4, seam table). A byte drift here
// means the detail view fetches a URL the list view never links to.

test('policyUrl-network-policy', () => {
  expect(policyUrl('NetworkPolicy', 1, 'deny-all', 'team-a')).toBe(
    '/api/v1/clusters/1/resources/networkpolicies?name=deny-all&namespace=team-a',
  )
})

test('policyUrl-cilium-network-policy', () => {
  expect(policyUrl('CiliumNetworkPolicy', 3, 'cnp', 'team-a')).toBe(
    '/api/v1/clusters/3/resources/ciliumnetworkpolicies?name=cnp&namespace=team-a',
  )
})

test('policyUrl-clusterwide-omits-namespace', () => {
  // Cluster-scoped kind: no namespace param, byte-for-byte.
  expect(policyUrl('CiliumClusterwideNetworkPolicy', 2, 'ccnp', 'team-a')).toBe(
    '/api/v1/clusters/2/resources/ciliumclusterwidenetworkpolicies?name=ccnp',
  )
})

test('policyUrl-unknown-kind-is-null', () => {
  // Closed enum: a kind outside POLICY_KINDS gets no URL (no fetch).
  expect(policyUrl('Foo', 1, 'deny-all', 'team-a')).toBeNull()
})
