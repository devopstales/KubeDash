import React, { useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useClusterStore } from '../../store/cluster'
import { useCluster } from '../../hooks/useCluster'
import Pods from './Pods'

/**
 * Single-cluster view: the cluster id comes from the route param
 * (`/clusters/:id`), falling back to the store when the param is absent
 * (direct render, e.g. tests). If the param doesn't match any bound
 * cluster (stale URL from a prior session), redirect to the store's
 * selection to avoid a 404 on the pod list.
 */
const ClusterView = () => {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const selectedCluster = useClusterStore((s) => s.selectedCluster)
  const { clusters } = useCluster()

  const paramId = id ? Number(id) : null
  // Cross-reference the URL param against the bound clusters. A stale
  // param (from a prior session) that no longer exists would 404 on the
  // pod list — redirect to the store's selection instead.
  const isStale =
    paramId != null &&
    clusters.length > 0 &&
    !clusters.some((c) => c.id === paramId)

  useEffect(() => {
    if (isStale && selectedCluster) {
      navigate(`/clusters/${selectedCluster.id}`, { replace: true })
    }
  }, [isStale, selectedCluster, navigate])

  const clusterId = isStale ? selectedCluster?.id : paramId ?? selectedCluster?.id

  if (clusterId == null || Number.isNaN(clusterId)) {
    return <div>Select a cluster to see its pods.</div>
  }

  return <Pods clusterId={clusterId} />
}

export default ClusterView
