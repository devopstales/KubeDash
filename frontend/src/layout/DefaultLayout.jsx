/**
 * DefaultLayout Component
 *
 * Main application layout wrapper for authenticated routes.
 *
 * Layout structure:
 * - AppSidebar: Collapsible navigation sidebar
 * - AppHeader: Top navigation bar (cluster switcher + user menu)
 * - children: the routed view (App.tsx renders the Routes here)
 * - AppFooter: Footer with copyright
 *
 * @component
 * @example
 * <Route path="/*" element={<DefaultLayout><Routes>...</Routes></DefaultLayout>} />
 */

import React from 'react'
import { AppSidebar, AppFooter, AppHeader } from '../components/index'

const DefaultLayout = ({ children }) => {
  return (
    <div>
      <AppSidebar />
      <div className="wrapper d-flex flex-column min-vh-100">
        <AppHeader />
        <div className="body flex-grow-1">{children}</div>
        <AppFooter />
      </div>
    </div>
  )
}

export default DefaultLayout
