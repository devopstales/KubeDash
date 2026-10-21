import React from 'react'
import { CCard, CCardBody, CCardHeader, CCardTitle } from '@coreui/react'
import TemplateEditor from './components/TemplateEditor'

/** Template admin, its own page at `/admin/permissions?tab=templates`. */
const TemplatesPage = () => (
  <CCard>
    <CCardHeader>
      <CCardTitle>Templates</CCardTitle>
    </CCardHeader>
    <CCardBody>
      <TemplateEditor existingNames={[]} onCreated={() => {}} />
    </CCardBody>
  </CCard>
)

export default TemplatesPage
