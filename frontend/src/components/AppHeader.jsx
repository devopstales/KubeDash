/**
 * AppHeader Component
 *
 * Top navigation bar for the KubeDash SPA shell:
 * - Cluster switcher (CDropdown bound to the Zustand cluster store)
 * - User menu (identity from /api/v1/auth/me via useCluster)
 *
 * The template's sidebar-toggle + search + notifications are not part of
 * the KubeDash shell: the sidebar is static for now and the cluster
 * switcher lives here (the header IS the cluster switcher surface).
 */

import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  CButton,
  CDropdown,
  CDropdownItem,
  CDropdownMenu,
  CDropdownToggle,
  CHeader,
  CHeaderNav,
  CHeaderToggler,
  CNavItem,
  CNavLink,
  CSpinner,
} from '@coreui/react'
import CIcon from '@coreui/icons-react'
import { cilList, cilMenu, cilUser } from '@coreui/icons'

import { useCluster } from '../hooks/useCluster'
import { useClusterStore } from '../store/cluster'

const AppHeader = () => {
  const { clusters, clustersLoading, me } = useCluster()
  const selectedCluster = useClusterStore((s) => s.selectedCluster)
  const setSelectedCluster = useClusterStore((s) => s.setSelectedCluster)
  const [sidebarShow, setSidebarShow] = useState(true)

  useEffect(() => {
    // Keep the selection valid: if the bound list changes and the selected
    // cluster is gone, fall back to the first bound cluster.
    if (!clustersLoading && clusters.length > 0) {
      const stillBound = selectedCluster && clusters.some((c) => c.id === selectedCluster.id)
      if (!stillBound) {
        setSelectedCluster({ id: clusters[0].id, name: clusters[0].name })
      }
    }
  }, [clusters, clustersLoading, selectedCluster, setSelectedCluster])

  return (
    <CHeader sticky>
      <CHeaderToggler onClick={() => setSidebarShow((v) => !v)}>
        <CIcon icon={cilMenu} alt="KubeDash" />
      </CHeaderToggler>
      <CHeaderNav className="d-none d-lg-flex me-auto">
        <CDropdown variant="dropdown" placement="bottom-start">
          <CDropdownToggle color="secondary" className="align-middle">
            <CIcon icon={cilList} customClassName="me-2" />
            {selectedCluster ? (
              selectedCluster.name
            ) : clustersLoading ? (
              <CSpinner size="sm" />
            ) : (
              'No cluster'
            )}
          </CDropdownToggle>
          <CDropdownMenu>
            {clusters.map((c) => (
              <CDropdownItem
                key={c.id}
                active={selectedCluster?.id === c.id}
                href={`/clusters/${c.id}`}
                onClick={() => setSelectedCluster({ id: c.id, name: c.name })}
              >
                {c.name}
              </CDropdownItem>
            ))}
            {clusters.length === 0 && <CDropdownItem disabled>No clusters bound</CDropdownItem>}
          </CDropdownMenu>
        </CDropdown>
      </CHeaderNav>
      <CHeaderNav>
        <CNavItem>
          <CNavLink href="/clusters" className="text-body">
            <CIcon icon={cilUser} customClassName="me-2" />
            {me ? me.display_name || me.email || me.sub : '…'}
          </CNavLink>
        </CNavItem>
      </CHeaderNav>
    </CHeader>
  )
}

export default AppHeader
