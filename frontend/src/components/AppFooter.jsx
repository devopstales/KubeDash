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
      <div>
        {/* ADR-0020: air-gapped bundle — labels only, no outbound docs links */}
        DevOpsTales - KubeDash Copyright &copy; 2021-2025
      </div>
      <div className="ms-auto">
        Powered by&nbsp;
        <a href="https://coreui.io/docs/" target="_blank" rel="noopener noreferrer">
          CoreUI UI Components
        </a>
      </div>
    </CFooter>
  )
}

export default AppFooter
