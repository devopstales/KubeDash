import React from 'react'
import { useParams } from 'react-router-dom'
import { useClusterStore } from '../../store/cluster'
import Pods from './Pods'

/**
 * Single-cluster view: the cluster id comes from the route param
 * (`/clusters/:id`), falling back to the store when the param is absent
 * (direct render, e.g. tests). Renders the pod table.
 */
const ClusterView = () => {
  const { id } = useParams<{ id: string }>()
  const selectedCluster = useClusterStore((s) => s.selectedCluster)

  const clusterId = id ? Number(id) : selectedCluster?.id

  if (clusterId == null || Number.isNaN(clusterId)) {
    return <div>Select a cluster to see its pods.</div>
  }

  return <Pods clusterId={clusterId} />
}

export default ClusterView
