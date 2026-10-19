import React from 'react'
import { CNavItem, CNavTitle } from '@coreui/react'
import CIcon from '@coreui/icons-react'
import { cilLayers, cilList, cilShieldAlt, cilUserFollow } from '@coreui/icons'

/**
 * Sidebar navigation for the KubeDash SPA shell. The template's demo nav
 * (components, forms, widgets, ...) is demo material and is not carried
 * forward; the R5 surface (workflows, settings, docs) will add entries
 * here when it lands.
 */
const _nav = [
  {
    component: CNavTitle,
    name: 'KubeDash',
  },
  {
    component: CNavItem,
    name: 'Clusters',
    to: '/clusters',
    icon: <CIcon icon={cilLayers} customClassName="nav-icon" />,
  },
  {
    component: CNavItem,
    name: 'Cluster detail',
    to: '/clusters/1',
    icon: <CIcon icon={cilList} customClassName="nav-icon" />,
  },
  {
    component: CNavItem,
    name: 'My access',
    to: '/permissions',
    icon: <CIcon icon={cilShieldAlt} customClassName="nav-icon" />,
  },
  {
    component: CNavItem,
    name: 'Admin permissions',
    to: '/admin/permissions',
    icon: <CIcon icon={cilUserFollow} customClassName="nav-icon" />,
    // ponytail: the ROUTE gate (AdminRoute in routes.tsx) is the real
    // admin control — the nav entry is always rendered; a non-admin who
    // clicks it lands on the redirect to /.
  },
]

export default _nav
