/**
 * AppHeader Component
 *
 * Top navigation bar for the KubeDash SPA shell, mirroring 4.1
 * segments/partials/header.html.j2: sidebar toggle, namespace selector,
 * then GitHub, docs, and API links, notifications, theme, profile.
 */

import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
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
import {
  cilAccountLogout,
  cilBell,
  cilBook,
  cilCode,
  cilContrast,
  cilMenu,
  cilMoon,
  cilSettings,
  cilSun,
  cilUser,
} from '@coreui/icons'

import { useCluster } from '../hooks/useCluster'
import { useClusterStore } from '../store/cluster'
import { useSidebarStore } from '../store/sidebar'
import { useTopMenuStore } from '../store/topmenu'
import { apiFetch } from '../lib/api'
import { TopMenuNav } from './TopMenu'

const undrawProfile = '/assets/img/avatars/undraw_profile.svg'

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

const githubIcon = [
  '32 32',
  '<path fill="var(--ci-primary-color, currentColor)" d="M16 0.396c-8.839 0-16 7.167-16 16 0 7.073 4.584 13.068 10.937 15.183 0.803 0.151 1.093-0.344 1.093-0.772 0-0.38-0.009-1.385-0.015-2.719-4.453 0.964-5.391-2.151-5.391-2.151-0.729-1.844-1.781-2.339-1.781-2.339-1.448-0.989 0.115-0.968 0.115-0.968 1.604 0.109 2.448 1.645 2.448 1.645 1.427 2.448 3.744 1.74 4.661 1.328 0.14-1.031 0.557-1.74 1.011-2.135-3.552-0.401-7.287-1.776-7.287-7.907 0-1.751 0.62-3.177 1.645-4.297-0.177-0.401-0.719-2.031 0.141-4.235 0 0 1.339-0.427 4.4 1.641 1.281-0.355 2.641-0.532 4-0.541 1.36 0.009 2.719 0.187 4 0.541 3.043-2.068 4.381-1.641 4.381-1.641 0.859 2.204 0.317 3.833 0.161 4.235 1.015 1.12 1.635 2.547 1.635 4.297 0 6.145-3.74 7.5-7.296 7.891 0.556 0.479 1.077 1.464 1.077 2.959 0 2.14-0.020 3.864-0.020 4.385 0 0.416 0.28 0.916 1.104 0.755 6.4-2.093 10.979-8.093 10.979-15.156 0-8.833-7.161-16-16-16z"></path>',
]

const AppHeader = () => {
  const { me } = useCluster()
  const selectedCluster = useClusterStore((s) => s.selectedCluster)
  const selectedNamespace = useClusterStore((s) => s.selectedNamespace)
  const setSelectedNamespace = useClusterStore((s) => s.setSelectedNamespace)
  const toggleSidebar = useSidebarStore((state) => state.toggle)
  const setTopMenuSlot = useTopMenuStore((state) => state.setSlot)
  const [draftNamespace, setDraftNamespace] = useState(null)
  const [draftClusterId, setDraftClusterId] = useState(selectedCluster?.id)
  if (selectedCluster?.id !== draftClusterId) {
    setDraftClusterId(selectedCluster?.id)
    setDraftNamespace(null)
  }
  const [loggingOut, setLoggingOut] = useState(false)
  const navigate = useNavigate()

  // Light/dark/auto theme switcher, matching main's contrast dropdown. Applies
  // data-coreui-theme to <html> (CoreUI's dark vars are already compiled in)
  // and persists the choice.
  const { colorMode, setColorMode } = useColorModes('coreui-theme')

  const namespacesQuery = useQuery({
    queryKey: ['namespaces', selectedCluster?.id],
    enabled: selectedCluster != null,
    queryFn: async () => {
      const r = await apiFetch(`/api/v1/clusters/${selectedCluster.id}/resources/namespaces`)
      if (r.error) throw new Error(r.error.message)
      return r.data?.items ?? []
    },
  })
  const namespaces = (namespacesQuery.data ?? []).map((item) => item.metadata?.name).filter(Boolean)
  const preferredNamespace =
    selectedNamespace && namespaces.includes(selectedNamespace)
      ? selectedNamespace
      : namespaces.includes('default')
        ? 'default'
        : (namespaces[0] ?? '')
  const shownNamespace = draftNamespace ?? preferredNamespace

  // Notifications: mirrors main's flash-message bell, but wired to real in-app
  // events (auth failures, API errors) since the SPA has no Flask flash. State
  // is persisted to localStorage so it survives a reload (main's was session-
  // scoped flash messages that cleared on the next request). Cap at 20 to keep
  // the list bounded.
  const [notifications, setNotifications] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('kd_notifications') || '[]')
    } catch {
      return []
    }
  })
  useEffect(() => {
    localStorage.setItem('kd_notifications', JSON.stringify(notifications))
  }, [notifications])

  const addNotification = (category, message) => {
    setNotifications((prev) =>
      [{ id: Date.now() + Math.random(), category, message, time: new Date() }, ...prev].slice(
        0,
        20,
      ),
    )
  }
  const removeNotification = (id) => setNotifications((prev) => prev.filter((n) => n.id !== id))
  const clearAllNotifications = () => setNotifications([])

  // Logout mirrors the Profile view's handler: best-effort server-side revoke,
  // then clear the localStorage token pair and bounce to /login. One contract
  // for session teardown, reachable from the header AND the profile page.
  const logout = async () => {
    if (loggingOut) return
    setLoggingOut(true)
    try {
      await apiFetch('/api/v1/auth/logout', { method: 'POST' })
    } catch {
      addNotification('warning', 'Could not reach the server — session cleared locally.')
    } finally {
      localStorage.removeItem('kd_token')
      localStorage.removeItem('kd_refresh')
      setLoggingOut(false)
      navigate('/login', { replace: true })
    }
  }

  return (
    <CHeader sticky className="p-0 mb-4">
      <div className="container-fluid border-bottom px-4 d-flex align-items-center flex-nowrap">
        <CHeaderToggler aria-label="Toggle sidebar" onClick={() => toggleSidebar()}>
          <CIcon icon={cilMenu} customClassName="icon icon-lg" alt="Toggle sidebar" />
        </CHeaderToggler>

        {/* 4.1 namespace selector: the choice is applied on Submit. */}
        <CHeaderNav className="d-none d-lg-flex" style={{ minWidth: 0 }}>
          <CNavItem>
            <CForm
              className="form-inline row"
              onSubmit={(e) => {
                e.preventDefault()
                setSelectedNamespace(shownNamespace || null)
              }}
            >
              <CInputGroup>
                <CFormSelect
                  aria-label="Select Namespace"
                  name="ns_select"
                  value={shownNamespace}
                  onChange={(e) => setDraftNamespace(e.target.value)}
                >
                  {namespaces.map((name) => (
                    <option key={name} value={name}>
                      {name}
                    </option>
                  ))}
                </CFormSelect>
                <CButton color="primary" type="submit">
                  Submit
                </CButton>
              </CInputGroup>
            </CForm>
          </CNavItem>
        </CHeaderNav>

        <CHeaderNav className="ms-auto">
          <CNavItem>
            <a
              className="nav-link"
              href="https://github.com/devopstales/KubeDash"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="GitHub"
            >
              <CIcon icon={githubIcon} customClassName="icon icon-xl" />
            </a>
          </CNavItem>
          <CNavItem>
            <a
              className="nav-link"
              href="https://devopstales.github.io/KubeDash/latest/"
              target="_blank"
              rel="noopener noreferrer"
              aria-label="Docs"
            >
              <CIcon icon={cilBook} customClassName="icon icon-xl" />
            </a>
          </CNavItem>
          <CNavItem>
            <a className="nav-link" href="/api/docs" aria-label="REST API">
              <CIcon icon={cilCode} customClassName="icon icon-xl" />
            </a>
          </CNavItem>
          <CNavItem className="py-1">
            <div className="vr h-100 mx-2 text-body text-opacity-75" />
          </CNavItem>
          {/* Notifications bell (mirrors main's flash-message dropdown) */}
          <CDropdown variant="nav-item" placement="bottom-end">
            <CDropdownToggle
              className="btn btn-link nav-link py-2 px-2 d-flex align-items-center position-relative"
              caret={false}
              aria-label="Notifications"
            >
              <CIcon icon={cilBell} customClassName="icon icon-xl" />
              {notifications.length > 0 && (
                <span className="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger">
                  {notifications.length}
                  {notifications.length >= 9 ? '+' : ''}
                  <span className="visually-hidden">unread notifications</span>
                </span>
              )}
            </CDropdownToggle>
            <CDropdownMenu
              className="dropdown-menu-end dropdown-menu-notifications pt-0"
              placement="bottom-end"
            >
              <div className="dropdown-header d-flex justify-content-between align-items-center px-3 pt-2 pb-1">
                <span className="fw-semibold">Notifications</span>
                <CButton
                  color="secondary"
                  size="sm"
                  className="btn-outline-secondary"
                  onClick={clearAllNotifications}
                  disabled={notifications.length === 0}
                >
                  Clear All
                </CButton>
              </div>
              <hr className="dropdown-divider my-1" />
              {notifications.length === 0 ? (
                <div className="px-3 py-2 text-center text-muted small">No notifications</div>
              ) : (
                <ul className="list-unstyled mb-0">
                  {notifications.map((n, i) => (
                    <li
                      key={n.id}
                      className={`px-3 py-2 notification-item notification-item-${n.category}`}
                    >
                      <div className="d-flex justify-content-between">
                        <div>
                          <strong className={`text-${n.category}`}>{n.category}</strong>
                          <span className="notification-time ms-2 small text-muted">
                            {new Date(n.time).toLocaleTimeString([], {
                              hour: '2-digit',
                              minute: '2-digit',
                            })}
                          </span>
                        </div>
                        <button
                          type="button"
                          className="btn-close"
                          aria-label="Dismiss"
                          onClick={() => removeNotification(n.id)}
                        />
                      </div>
                      <div className="mt-1 small">{n.message}</div>
                      {i < notifications.length - 1 && <hr className="dropdown-divider my-1" />}
                    </li>
                  ))}
                </ul>
              )}
            </CDropdownMenu>
          </CDropdown>

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
                href="/settings/export"
                onClick={(e) => {
                  e.preventDefault()
                  navigate('/settings/export')
                }}
              >
                <CIcon icon={cilSettings} className="me-2" />
                Download KubeConfig
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
      </div>
      <div className="container-fluid px-4 d-flex align-items-center">
        <div ref={setTopMenuSlot} className="d-flex align-items-center flex-grow-1" />
        <TopMenuNav />
      </div>
    </CHeader>
  )
}

export default AppHeader
