/**
 * AppBreadcrumb Component
 *
 * Breadcrumb for the KubeDash SPA shell: / → Clusters → <cluster name>.
 */

import React from 'react'
import { useLocation } from 'react-router-dom'

import { useCluster } from '../hooks/useCluster'

import { CBreadcrumb, CBreadcrumbItem } from '@coreui/react'

const AppBreadcrumb = () => {
  const { pathname } = useLocation()
  const { clusters } = useCluster()

  const parts = pathname.split('/').filter(Boolean)
  const crumbs = [{ name: 'Home', pathname: '/', active: parts.length === 0 }]
  if (parts[0] === 'clusters') {
    crumbs.push({ name: 'Clusters', pathname: '/clusters', active: parts.length === 1 })
    if (parts[1]) {
      const cluster = clusters.find((c) => String(c.id) === parts[1])
      crumbs.push({
        name: cluster ? cluster.name : `#${parts[1]}`,
        pathname,
        active: true,
      })
    }
  }

  return (
    <CBreadcrumb className="mb-0">
      {crumbs.map((crumb, i) => (
        <CBreadcrumbItem key={i} active={crumb.active}>
          {crumb.name}
        </CBreadcrumbItem>
      ))}
    </CBreadcrumb>
  )
}

export default AppBreadcrumb
