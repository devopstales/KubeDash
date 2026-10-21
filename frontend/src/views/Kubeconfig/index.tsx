import React, { useState } from 'react'
import { CButton, CCard, CCardBody, CCardHeader } from '@coreui/react'
import { downloadFile } from '../../lib/api'
import { useCluster } from '../../hooks/useCluster'
import { useClusterStore } from '../../store/cluster'

/**
 * 4.1 kubectl config page (`settings/export.html.j2`, route `/settings/export`).
 * Same chrome: breadcrumb, centered welcome, anchor tabs, five stacked cards.
 * The download is GET /api/v1/kubeconfig (ADR-0011). The manual card merges
 * that file; it does not print tokens, client secrets, or certificates.
 */

const TABS = [
  { id: 'DownloadKubeconfig', label: 'Download Kubeconfig' },
  { id: 'DownloadKubectl', label: 'Download Kubectl' },
  { id: 'KubectlPlugin', label: 'Kubectl Plugin' },
  { id: 'lAdvanced', label: 'Manual Config' },
  { id: 'RunningKubectl', label: 'User kubectl' },
] as const

const KUBECTL_INSTALL = `# Install kubectl binary with curl on Linux
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x ./kubectl
sudo mv ./kubectl /usr/local/bin/kubectl

# Install kubectl binary with curl on macOS
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/darwin/amd64/kubectl"
chmod +x ./kubectl
sudo mv ./kubectl /usr/local/bin/kubectl

# Install kubectl on Windows
curl.exe -LO "https://dl.k8s.io/release/$(curl.exe -L -s https://dl.k8s.io/release/stable.txt)/bin/windows/amd64/kubectl.exe"`

const PLUGIN_INSTALL = `# Homebrew (macOS and Linux)
brew install kubedash

# Krew (macOS, Linux, Windows and ARM)
kubectl krew install kubedash

# Binary release (Windows, macOS and Linux)
https://github.com/devopstales/kubedash/releases`

const RUNNING = `# These are examples. Your context and cluster names will likely differ.

$ kubectl config get-contexts
CURRENT   NAME       CLUSTER            AUTHINFO   NAMESPACE
      k8s        k8s                k8s
      microk8s   microk8s-cluster   admin

$ kubectl --context k8s get namespaces
NAME          STATUS    AGE
default       Active    83d
experimental  Active    15d

$ kubectl --context k8s -n experimental get pods
NAME                                       READY     STATUS             RESTARTS   AGE
testapp-4074452424-06m0b                   1/1       Running            1          6d`

const Snippet = ({ children }: { children: string }) => (
  <pre className="kd-snippet mb-0 overflow-auto">
    <code>{children}</code>
  </pre>
)

const Section = ({
  id,
  title,
  children,
}: {
  id: string
  title: string
  children: React.ReactNode
}) => (
  <CCard className="mb-4 mx-3 mx-lg-5">
    <CCardHeader className="py-3">
      <h5 className="m-0 fw-bold text-primary" id={id} style={{ scrollMarginTop: '5rem' }}>
        {title}
      </h5>
    </CCardHeader>
    <CCardBody>{children}</CCardBody>
  </CCard>
)

const KubeconfigView = () => {
  const { me, clusters } = useCluster()
  const selectedCluster = useClusterStore((s) => s.selectedCluster)
  const [active, setActive] = useState<string>(TABS[0].id)
  const [downloading, setDownloading] = useState(false)
  const [downloadError, setDownloadError] = useState<string | null>(null)

  const name = me?.display_name || me?.email || me?.sub || ''
  const clusterName = selectedCluster?.name ?? clusters[0]?.name ?? ''
  const clusterPhrase = clusterName
    ? `the ${clusterName} Kubernetes cluster`
    : 'the Kubernetes cluster'
  const server = typeof window === 'undefined' ? '' : window.location.origin

  const onDownload = async () => {
    setDownloading(true)
    setDownloadError(null)
    try {
      const r = await downloadFile('/api/v1/kubeconfig', 'kubedash-kubeconfig.yaml')
      if (!r.ok) setDownloadError(`${r.error?.code ?? 'UNKNOWN'}: ${r.error?.message ?? ''}`)
    } catch {
      setDownloadError('Download failed')
    } finally {
      setDownloading(false)
    }
  }

  const jump = (id: string) => {
    setActive(id)
    document.getElementById(id)?.scrollIntoView({ block: 'start' })
  }

  const manual = `# Keep your existing contexts and add the downloaded file
mkdir -p ~/.kube
KUBECONFIG=~/.kube/config:kubedash-kubeconfig.yaml kubectl config view --flatten > ~/.kube/config.merged
mv ~/.kube/config.merged ~/.kube/config

# Select this cluster
kubectl config use-context ${clusterName || 'CLUSTER'}

# The user entry is the kubedash credential plugin.
# The file stores no token, client secret, or certificate.`

  const pluginUse = `$ kubectl kubedash get-token --server=${server}
# First run opens a browser. Later runs use the cached token.

$ kubectl get namespaces`

  return (
    <div>
      <div className="px-4 py-3">
        <nav aria-label="breadcrumb">
          <ol className="breadcrumb my-0">
            <li className="breadcrumb-item">
              <span>Settings</span>
            </li>
            <li className="breadcrumb-item active">
              <span>Download KubeConfig</span>
            </li>
          </ol>
        </nav>
      </div>

      <h2 className="text-center my-4">Welcome {name}</h2>
      <h3 className="text-center my-4 mx-3">
        In order to get command-line access to {clusterPhrase}, you will need to configure OpenID
        Connect (OIDC) authentication for your kubectl client.
      </h3>

      <ul className="nav nav-tabs mb-4 mx-3 mx-lg-5">
        {TABS.map((tab) => (
          <li className="nav-item" key={tab.id}>
            <a
              className={`nav-link${active === tab.id ? ' active' : ''}`}
              href={`#${tab.id}`}
              onClick={(e) => {
                e.preventDefault()
                jump(tab.id)
              }}
            >
              {tab.label}
            </a>
          </li>
        ))}
      </ul>

      <Section id="DownloadKubeconfig" title="Download Kubeconfig File">
        <p className="card-text">
          If you didn&apos;t want to use the kubectl plugin, save this file as{' '}
          <code>~/.kube/config</code> to enable OIDC based <code>kubectl</code> authentication.
        </p>
        <CButton color="primary" disabled={downloading} onClick={() => void onDownload()}>
          {downloading ? 'Downloading…' : 'Download Config File'}
        </CButton>
        {downloadError && <div className="text-danger mt-2">{downloadError}</div>}
      </Section>

      <Section id="DownloadKubectl" title="Download Kubectl">
        <h5 className="card-title">Install as Kubectl</h5>
        <Snippet>{KUBECTL_INSTALL}</Snippet>
      </Section>

      <Section id="KubectlPlugin" title="Kubectl Plugin">
        <h5 className="card-title">Install as Kubectl plugin.</h5>
        <Snippet>{PLUGIN_INSTALL}</Snippet>
        <h5 className="card-title mt-3">Use the plugin.</h5>
        <Snippet>{pluginUse}</Snippet>
      </Section>

      <Section id="lAdvanced" title="Authenticate Manually">
        <p className="card-text">
          If you want to maintain your existing <code>~/.kube/config</code> file you can run the
          following commands to add your user to the file:
        </p>
        <Snippet>{manual}</Snippet>
      </Section>

      <Section id="RunningKubectl" title="Running kubectl">
        <p className="card-text">
          Once you get the <code>~/.kube/config</code> file you should be able to run{' '}
          <code>kubectl</code>:
        </p>
        <Snippet>{RUNNING}</Snippet>
      </Section>
    </div>
  )
}

export default KubeconfigView
