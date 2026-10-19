import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '../lib/api'
import { useClusterStore } from '../store/cluster'
import type { Me } from '../lib/types'

export interface ClusterItem {
  id: number
  name: string
  api_server?: string
  context?: string | null
  status?: string
  last_probe_at?: string | null
}

/**
 * Populates the cluster selection store with the caller's bound clusters
 * and exposes `/api/v1/auth/me` (identity + permissions) for later
 * button-hiding. R4's 403 path is where the permissions surface pays off.
 */
export function useCluster() {
  const selectedCluster = useClusterStore((s) => s.selectedCluster)
  const setSelectedCluster = useClusterStore((s) => s.setSelectedCluster)

  const clustersQuery = useQuery({
    queryKey: ['clusters'],
    queryFn: async () => {
      const r = await apiFetch<ClusterItem[] | { items: ClusterItem[] }>('/api/v1/clusters')
      if (r.error) throw new Error(r.error.message)
      const items = Array.isArray(r.data) ? r.data : (r.data?.items ?? [])
      return items
    },
  })

  const meQuery = useQuery({
    queryKey: ['me'],
    queryFn: async () => {
      const r = await apiFetch<Me>('/api/v1/auth/me')
      if (r.error) throw new Error(r.error.message)
      return r.data
    },
  })

  useEffect(() => {
    const items = clustersQuery.data
    if (!items) return
    // Keep the selection if it's still bound; otherwise clear it (a stale
    // selection from a prior session would 404 on the cluster detail route)
    // and auto-select the first.
    const stillBound = selectedCluster && items.some((c) => c.id === selectedCluster.id)
    if (!stillBound) {
      if (selectedCluster) setSelectedCluster(null)
      if (items.length > 0) setSelectedCluster({ id: items[0].id, name: items[0].name })
    }
  }, [clustersQuery.data, selectedCluster, setSelectedCluster])

  return {
    clusters: clustersQuery.data ?? [],
    clustersLoading: clustersQuery.isLoading,
    me: meQuery.data ?? null,
    permissions: meQuery.data?.groups ?? [],
    role: meQuery.data?.role ?? null,
  }
}
