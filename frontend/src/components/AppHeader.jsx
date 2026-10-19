/**
 * AppHeader Component
 *
 * Top navigation bar for the KubeDash SPA shell, mirroring the main-branch
 * header (segments/header.html.j2): sidebar toggle, cluster switcher, then a
 * right-aligned nav of GitHub link, theme switcher, and user profile.
 *
 * The cluster switcher is the KubeDash analog of main's namespace selector —
 * it stays in the left nav. The main-branch notifications dropdown is dropped:
 * it was wired to Flask flash messages, which have no React equivalent here.
 */

import React, { useState } from 'react'
import {
  CButton,
  CDropdown,
  CDropdownDivider,
  CDropdownHeader,
  CDropdownItem,
  CDropdownMenu,
  CDropdownToggle,
  CForm,
  CFormSelect,
  CHeader,
  CHeaderNav,
  CHeaderToggler,
  CInputGroup,
  CNavItem,
  useColorModes,
} from '@coreui/react'
import CIcon from '@coreui/icons-react'
import { cibGithub } from '@coreui/icons'
import {
  cilAccountLogout,
  cilContrast,
  cilMenu,
  cilMoon,
  cilSettings,
  cilSun,
  cilUser,
} from '@coreui/icons'
import undrawProfile from '../../public/assets/img/avatars/undraw_profile.svg'

import { useCluster } from '../hooks/useCluster'
import { useClusterStore } from '../store/cluster'
import { apiFetch } from '../lib/api'
import { useNavigate } from 'react-router-dom'

/**
 * One theme option (Light / Dark / Auto) in the switcher dropdown. Markup
 * mirrors the main-branch color-modes switcher: a button with the icon at
 * `me-3` spacing, `active` on the current mode.
 */
const ThemeItem = ({ value, icon, label, colorMode, onSet }) => (
  <button
    className={`dropdown-item d-flex align-items-center${colorMode === value ? ' active' : ''}`}
    type="button"
    data-coreui-theme-value={value}
    onClick={() => onSet(value)}
  >
    <CIcon icon={icon} customClassName="icon icon-lg me-3" />
    {label}
  </button>
)

const AppHeader = () => {
  const { clusters, me } = useCluster()
  const selectedCluster = useClusterStore((s) => s.selectedCluster)
  const setSelectedCluster = useClusterStore((s) => s.setSelectedCluster)
  const [sidebarShow, setSidebarShow] = useState(true)
  const [loggingOut, setLoggingOut] = useState(false)
  const navigate = useNavigate()

  // Light/dark/auto theme switcher, matching main's contrast dropdown. Applies
  // data-coreui-theme to <html> (CoreUI's dark vars are already compiled in)
  // and persists the choice.
  const { colorMode, setColorMode } = useColorModes('coreui-theme')

  // Logout mirrors the Profile view's handler: best-effort server-side revoke,
  // then clear the localStorage token pair and bounce to /login. One contract
  // for session teardown, reachable from the header AND the profile page.
  const logout = async () => {
    if (loggingOut) return
    setLoggingOut(true)
    try {
      await apiFetch('/api/v1/auth/logout', { method: 'POST' })
    } finally {
      localStorage.removeItem('kd_token')
      localStorage.removeItem('kd_refresh')
      setLoggingOut(false)
      navigate('/login', { replace: true })
    }
  }

  return (
    <CHeader sticky className="p-0">
      <CHeaderToggler className="px-4" onClick={() => setSidebarShow((v) => !v)}>
        <CIcon icon={cilMenu} size="xl" alt="Toggle sidebar" />
      </CHeaderToggler>

      {/* Cluster switcher — the KubeDash analog of main's namespace selector:
          a form-select + Submit button in an input-group. */}
      <CHeaderNav className="d-none d-lg-flex">
        <CNavItem>
          <CForm className="form-inline row">
            <CInputGroup>
              <CFormSelect
                aria-label="Select cluster"
                value={selectedCluster?.id ?? ''}
                onChange={(e) => {
                  const c = clusters.find((x) => String(x.id) === e.target.value)
                  if (c) setSelectedCluster({ id: c.id, name: c.name })
                }}
              >
                {clusters.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </CFormSelect>
              <CButton
                color="primary"
                type="button"
                onClick={() => {
                  if (selectedCluster) navigate(`/clusters/${selectedCluster.id}`)
                }}
              >
                Submit
              </CButton>
            </CInputGroup>
          </CForm>
        </CNavItem>
      </CHeaderNav>

      {/* Right-aligned nav: GitHub, theme switcher, user profile */}
      <CHeaderNav className="ms-auto">
        {/* GitHub link */}
        <CNavItem>
          <a
            className="nav-link"
            href="https://github.com/devopstales/KubeDash"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="KubeDash on GitHub"
          >
            <CIcon icon={cibGithub} size="xl" />
          </a>
        </CNavItem>

        {/* Theme switcher dropdown (light / dark / auto) */}
        <CDropdown variant="nav-item" placement="bottom-end">
          <CDropdownToggle className="d-flex align-items-center" caret={false}>
            <CIcon
              icon={colorMode === 'dark' ? cilMoon : colorMode === 'light' ? cilSun : cilContrast}
              customClassName="icon icon-lg"
            />
          </CDropdownToggle>
          <CDropdownMenu
            className="dropdown-menu-end"
            placement="bottom-end"
            style={{ '--cui-dropdown-min-width': '8rem' }}
          >
            <ThemeItem
              value="light"
              icon={cilSun}
              label="Light"
              colorMode={colorMode}
              onSet={setColorMode}
            />
            <ThemeItem
              value="dark"
              icon={cilMoon}
              label="Dark"
              colorMode={colorMode}
              onSet={setColorMode}
            />
            <ThemeItem
              value="auto"
              icon={cilContrast}
              label="Auto"
              colorMode={colorMode}
              onSet={setColorMode}
            />
          </CDropdownMenu>
        </CDropdown>

        <CNavItem className="py-1">
          <div className="vr h-100 mx-2 text-body text-opacity-75" />
        </CNavItem>

        {/* User profile dropdown */}
        <CDropdown variant="nav-item" placement="bottom-end">
          <CDropdownToggle className="py-0 pe-0" caret={false}>
            <div className="avatar avatar-md">
              <img
                className="avatar-img"
                src={undrawProfile}
                alt={me?.display_name || me?.email || 'User'}
              />
            </div>
          </CDropdownToggle>
          <CDropdownMenu className="pt-0" placement="bottom-end">
            <CDropdownHeader className="bg-body-tertiary text-body-secondary fw-semibold my-2">
              <div className="fw-semibold">{me?.display_name || me?.email || 'Account'}</div>
            </CDropdownHeader>
            <CDropdownItem href="/profile">
              <CIcon icon={cilUser} className="me-2" />
              Profile
            </CDropdownItem>
            <CDropdownItem
              href="https://devopstales.github.io/KubeDash/latest/"
              target="_blank"
              rel="noopener noreferrer"
            >
              <CIcon icon={cilSettings} className="me-2" />
              Docs
            </CDropdownItem>
            <CDropdownDivider />
            <CDropdownItem
              href="#"
              onClick={(e) => {
                e.preventDefault()
                void logout()
              }}
            >
              <CIcon icon={cilAccountLogout} className="me-2" />
              {loggingOut ? 'Logging out…' : 'Logout'}
            </CDropdownItem>
          </CDropdownMenu>
        </CDropdown>
      </CHeaderNav>
    </CHeader>
  )
}

export default AppHeader
