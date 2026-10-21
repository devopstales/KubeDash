/**
 * AppFooter Component
 *
 * KubeDash footer, mirroring the main-branch footer (segments/footer.html.j2):
 * DevOpsTales + KubeDash copyright on the left, "Powered by CoreUI" on the
 * right.
 */

import React from 'react'
import { CFooter } from '@coreui/react'

const AppFooter = () => {
  return (
    <CFooter fixed={false} className="px-4">
      <div>DevOpsTales - KubeDash Copyright &copy; 2021-2026</div>
      <div className="ms-auto">Powered by CoreUI UI Components</div>
    </CFooter>
  )
}

export default AppFooter
