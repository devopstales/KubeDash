import React, { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import {
  CBreadcrumb,
  CBreadcrumbItem,
  CButton,
  CCard,
  CCardBody,
  CCardHeader,
  CCardTitle,
  CTable,
} from '@coreui/react'
import CIcon from '@coreui/icons-react'
import { cilLockLocked, cilLockUnlocked } from '@coreui/icons'
import { useQuery } from '@tanstack/react-query'
import { Light as SyntaxHighlighter } from 'react-syntax-highlighter'
import json from 'react-syntax-highlighter/dist/esm/languages/hljs/json'
import yaml from 'react-syntax-highlighter/dist/esm/languages/hljs/yaml'
import xml from 'react-syntax-highlighter/dist/esm/languages/hljs/xml'
import javascript from 'react-syntax-highlighter/dist/esm/languages/hljs/javascript'
import anOldHope from 'react-syntax-highlighter/dist/esm/styles/hljs/an-old-hope'
import { apiFetch } from '../../lib/api'
import type { K8sSecret, ResourceList } from '../../lib/types'
import { useClusterStore } from '../../store/cluster'
import TopMenu from '../../components/TopMenu'

const LAST_APPLIED = 'kubectl.kubernetes.io/last-applied-configuration'

SyntaxHighlighter.registerLanguage('json', json)
SyntaxHighlighter.registerLanguage('yaml', yaml)
SyntaxHighlighter.registerLanguage('xml', xml)
SyntaxHighlighter.registerLanguage('javascript', javascript)

/**
 * 4.1 `detectLanguage`: json, yaml, xml, and javascript get a grammar.
 * Keys and PEM blocks (`-----BEGIN`) return `text`. Passing nothing makes
 * the highlighter guess a language and color the block.
 */
export const secretLanguage = (key: string, value: string): string => {
  const keyLower = key.toLowerCase()
  const valueStr = value.toLowerCase()
  const trimmed = valueStr.trim()
  if (keyLower.includes('json') || trimmed.startsWith('{') || trimmed.startsWith('[')) return 'json'
  if (
    keyLower.includes('yaml') ||
    keyLower.includes('yml') ||
    (valueStr.includes('---') && valueStr.includes(':'))
  ) {
    return 'yaml'
  }
  if (keyLower.includes('xml') || trimmed.startsWith('<')) return 'xml'
  if (
    keyLower.includes('key') ||
    keyLower.includes('cert') ||
    keyLower.includes('pem') ||
    valueStr.includes('-----begin')
  ) {
    return 'text'
  }
  if (
    keyLower.includes('script') ||
    valueStr.includes('function') ||
    valueStr.includes('const ') ||
    valueStr.includes('var ')
  ) {
    return 'javascript'
  }
  return 'text'
}

/** Base64 (standard or URL-safe, padding optional) to UTF-8 text; the input on failure. */
const decodeBase64 = (value: string): string => {
  try {
    let s = value.replace(/-/g, '+').replace(/_/g, '/')
    while (s.length % 4) s += '='
    const bytes = Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
    return new TextDecoder().decode(bytes)
  } catch {
    return value
  }
}

const KeyValueTable = ({ entries, empty }: { entries: [string, string][]; empty: string }) =>
  entries.length === 0 ? (
    <>{empty}</>
  ) : (
    <CTable bordered small className="mb-0">
      <thead>
        <tr>
          <th>Key</th>
          <th>Value</th>
        </tr>
      </thead>
      <tbody>
        {entries.map(([key, value]) => (
          <tr key={key}>
            <td>{key}</td>
            <td className="text-break">{value}</td>
          </tr>
        ))}
      </tbody>
    </CTable>
  )

/** One data key. The decoded value stays out of the DOM until revealed. */
const SecretValue = ({ name, encoded }: { name: string; encoded: string }) => {
  const [visible, setVisible] = useState(false)
  const decoded = visible ? decodeBase64(encoded) : ''
  return (
    <tr>
      <th scope="row" className="text-nowrap">
        {name}:
      </th>
      <td className="w-100">
        <div className="d-flex align-items-start gap-2">
          <CButton
            color="link"
            className="p-0"
            type="button"
            aria-label={visible ? `Hide ${name}` : `Show ${name}`}
            aria-pressed={visible}
            onClick={() => setVisible((v) => !v)}
          >
            <CIcon icon={visible ? cilLockUnlocked : cilLockLocked} />
          </CButton>
          {visible ? (
            <SyntaxHighlighter
              language={secretLanguage(name, decoded)}
              style={anOldHope}
              wrapLongLines
              customStyle={{
                margin: 0,
                flexGrow: 1,
                minWidth: 0,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
              }}
              codeTagProps={{ style: { whiteSpace: 'pre-wrap', wordBreak: 'break-word' } }}
            >
              {decoded}
            </SyntaxHighlighter>
          ) : (
            <pre className="mb-0 flex-grow-1 text-break" style={{ whiteSpace: 'pre-wrap' }}>
              <code>{'••••••••'}</code>
            </pre>
          )}
        </div>
      </td>
    </tr>
  )
}

/**
 * 4.1 `security/secret-data.html.j2`: one Secret's metadata, annotations
 * (without last-applied), labels, and its decoded data values, each hidden
 * until its eye button is pressed.
 */
const SecretDataView = () => {
  const [params] = useSearchParams()
  const name = params.get('name') ?? ''
  const selectedNamespace = useClusterStore((s) => s.selectedNamespace)
  const namespace = params.get('namespace') || selectedNamespace || 'default'
  const cluster = useClusterStore((s) => s.selectedCluster)

  const query = useQuery<K8sSecret>({
    queryKey: ['secrets', cluster?.id, namespace, name],
    enabled: cluster != null && name !== '',
    queryFn: async () => {
      const r = await apiFetch<ResourceList<K8sSecret>>(
        `/api/v1/clusters/${cluster!.id}/resources/secrets?namespace=${encodeURIComponent(namespace)}&name=${encodeURIComponent(name)}`,
      )
      if (r.error) throw new Error(`${r.error.code}: ${r.error.message}`)
      const [secret] = r.data?.items ?? []
      if (!secret) throw new Error(`Secret '${name}' not found in namespace '${namespace}'`)
      return secret
    },
  })

  const secret = query.data
  const annotations = Object.entries(secret?.metadata?.annotations ?? {}).filter(
    ([key]) => key !== LAST_APPLIED,
  )
  const labels = Object.entries(secret?.metadata?.labels ?? {})
  const data = Object.entries(secret?.data ?? {})

  return (
    <CCard className="shadow mb-4">
      <TopMenu>
        <CBreadcrumb className="my-0" aria-label="breadcrumb">
          <CBreadcrumbItem>Security</CBreadcrumbItem>
          <CBreadcrumbItem>
            <Link to="/security/secret">Secrets</Link>
          </CBreadcrumbItem>
          <CBreadcrumbItem active>{name || 'Error'}</CBreadcrumbItem>
        </CBreadcrumb>
      </TopMenu>
      <CCardHeader className="py-3">
        <CCardTitle className="m-0 fw-bold text-primary fs-6">Secret Data</CCardTitle>
      </CCardHeader>
      <CCardBody>
        {!name ? (
          <div className="text-danger">Error: Secret name not provided</div>
        ) : !cluster ? (
          <div>No cluster selected.</div>
        ) : query.isLoading ? (
          <div>Loading secret data...</div>
        ) : query.error ? (
          <div className="text-danger">Error loading secret: {query.error.message}</div>
        ) : (
          <>
            <CTable bordered>
              <tbody>
                <tr>
                  <th scope="row">Name:</th>
                  <td>{secret?.metadata?.name ?? 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Namespace:</th>
                  <td>{namespace}</td>
                </tr>
                <tr>
                  <th scope="row">Kind:</th>
                  <td>Secret</td>
                </tr>
                <tr>
                  <th scope="row">Created:</th>
                  <td>{secret?.metadata?.creation_timestamp ?? 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Type:</th>
                  <td>{secret?.type || 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Version:</th>
                  <td>{secret?.metadata?.resource_version ?? 'N/A'}</td>
                </tr>
                <tr>
                  <th scope="row">Annotations:</th>
                  <td>
                    <KeyValueTable entries={annotations} empty="No annotations" />
                  </td>
                </tr>
                <tr>
                  <th scope="row">Labels:</th>
                  <td>
                    <KeyValueTable entries={labels} empty="No labels" />
                  </td>
                </tr>
              </tbody>
            </CTable>
            {data.length > 0 ? (
              <CTable bordered className="mb-0">
                <tbody>
                  {data.map(([key, encoded]) => (
                    <SecretValue key={key} name={key} encoded={encoded} />
                  ))}
                </tbody>
              </CTable>
            ) : null}
          </>
        )}
      </CCardBody>
    </CCard>
  )
}

export default SecretDataView
