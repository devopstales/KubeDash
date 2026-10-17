/**
 * AppFooter Component
 *
 * KubeDash footer: version + copyright.
 */

import React from 'react'
import { CFooter } from '@coreui/react'

const AppFooter = () => {
  return (
    <CFooter fixed={false}>
      <span>&copy; 2026 KubeDash.</span>
    </CFooter>
  )
}

export default AppFooter
