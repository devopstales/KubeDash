# Installation

## Before you Begin

You need to have a Kubernetes cluster, and the kubectl command-line tool must be configured to communicate with your
cluster. If you do not already have a cluster, you can create one by installing [minikube], [kind] or [microk8s], or you can use the following [Kubernetes playground].

## Helm

[Helm], which is a popular package manager for Kubernetes, allows installing applications from parameterized
YAML manifests called Helm [charts].

### Installing from the DevOpsTales Chart Repository

```
helm repo add devopstales https://devopstales.github.io/helm-charts
helm repo update
helm upgrade --install kubedash devopstales/kubedash
```

> **Tip**: List all releases using `helm list`.

### Advanced Configuration

The command deploys kubedash on the Kubernetes cluster in the default configuration. The [Parameters](configuration.md)
section lists the parameters that can be configured during installation.

### Uninstall

You can uninstall the operator with the following command:

```
helm uninstall kubedash
```

[minikube]: https://minikube.sigs.k8s.io/docs/start/
[kind]: https://kind.sigs.k8s.io/
[microk8s]: https://microk8s.io
[Kubernetes playground]: https://labs.play-with-k8s.com/
[Helm]: https://helm.sh/docs/helm/helm/#helm
[charts]: https://helm.sh/docs/topics/charts/
