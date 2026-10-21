import React from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router-dom'
import { CButton, CHeaderNav, CNavItem } from '@coreui/react'
import CIcon from '@coreui/icons-react'
import { cilArrowLeft, cilReload } from '@coreui/icons'
import { useTopMenuStore } from '../store/topmenu'

/**
 * 4.1 `segments/partials/topmenu.html.j2` back and reload links, shown at
 * the right end of the header's second row on every page.
 */
export const TopMenuNav = () => {
  const navigate = useNavigate()
  return (
    <CHeaderNav className="d-flex align-items-center ms-auto me-2 py-2">
      <CNavItem className="py-1 align-self-stretch">
        <div className="vr h-100 mx-2 text-body text-opacity-75" />
      </CNavItem>
      <a
        className="card-link me-3"
        href="#"
        aria-label="Back"
        title="Back"
        onClick={(e) => {
          e.preventDefault()
          navigate(-1)
        }}
      >
        <CIcon icon={cilArrowLeft} size="lg" />
      </a>
      <CButton
        color="link"
        className="card-link p-0"
        type="button"
        aria-label="Reload page"
        title="Reload page"
        style={{ color: '#6261cc' }}
        onClick={() => window.location.reload()}
      >
        <CIcon icon={cilReload} size="lg" />
      </CButton>
    </CHeaderNav>
  )
}

/**
 * A page's 4.1 `{% block topmenu %}` (breadcrumb and page buttons), rendered
 * into the header's second row. Without a header (unit tests) it renders in place.
 */
const TopMenu = ({ children }: { children: React.ReactNode }) => {
  const slot = useTopMenuStore((s) => s.slot)
  const content = <div className="d-flex align-items-center flex-grow-1 gap-3">{children}</div>
  return slot ? createPortal(content, slot) : content
}

export default TopMenu
