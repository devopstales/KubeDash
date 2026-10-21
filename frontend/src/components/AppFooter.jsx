/**
 * AppFooter Component
 *
 * 4.1 footer (segments/partials/footer.html.j2): DevOpsTales and KubeDash
 * links, copyright, and the CoreUI docs link.
 */

import React from 'react'
import { CFooter } from '@coreui/react'

const AppFooter = () => {
  return (
    <CFooter fixed={false} className="px-4">
      <div>
        <a href="https://devopstales.github.io">DevOpsTales</a>
        {' - '}
        <a href="https://devopstales.github.io/KubeDash/latest/">KubeDash</a> Copyright &copy;
        2021-2026
      </div>
      <div className="ms-auto">
        Powered by&nbsp;
        <a href="https://coreui.io/docs/">CoreUI UI Components</a>
      </div>
    </CFooter>
  )
}

export default AppFooter
