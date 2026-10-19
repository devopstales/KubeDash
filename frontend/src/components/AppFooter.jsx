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
        <a href="https://devopstales.github.io" target="_blank" rel="noopener noreferrer">
          DevOpsTales
        </a>{' '}
        -{' '}
        <a
          href="https://devopstales.github.io/KubeDash/latest/"
          target="_blank"
          rel="noopener noreferrer"
        >
          KubeDash
        </a>{' '}
        Copyright &copy; 2021-2025
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
