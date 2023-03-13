# Platforms

## Tested Kubernetes Platforms

This section shows the different platforms where KubeDash has been tested or is intended to be tested, and useful observations about it.
If you have tested KubeDash on a different flavor or Kubernetes, please file a PR or [issue](https://github.com/devopstales/kubedash/issues/new/choose) to add your remarks to the list.

The "works" column refers to the overall Kubernetes related functionality when running in the respective platform; it may have 3 different values:

* ✔️ : Has been tried and works fine to the extent of what has been tested
* ❌ : Has been tried and didn't work or had issues that prevented a regular use of it
* ❔: Hasn't been tried/reported yet

Platform<div style="min-width: 300px"></div>    | Works | Comments
----------------------------------------------|:-----:|------------------------------------------------------------------------------------------
[Amazon EKS](https://aws.amazon.com/eks/)                     |  ✔️     |  - Simple to install
[Google Kubernetes Engine (GKE)](https://cloud.google.com/kubernetes-engine) |  ✔️     |  - Simple to install
[Microsoft AKS](https://azure.microsoft.com/)                  |  ✔️     |  - Simple to install
[DigitalOcean Kubernetes](https://www.digitalocean.com/products/kubernetes/)        | ❔    | - Have you tried KubeDash on this platform? Please report your experience.
[K3s](https://k3s.io/)                                         |  ✔️     |  - Simple to install
[Kind](https://kind.sigs.k8s.io/)                              |  ✔️     |  - Simple to install
[Minikube](https://minikube.sigs.k8s.io/)                     | ✔️     | - For exposing with an ingress, enable ingresses with `minikube addons enable ingress`
[RKE2](https://docs.rke2.io/)                     |  ✔️     |  - Simple to install
[Lokomotive](https://kinvolk.io/lokomotive-kubernetes/)                     | ❔    | - Have you tried KubeDash on this platform? Please report your experience.
[Vultr Kubernetes Engine](https://www.vultr.com/kubernetes/)                    | ❔    | - Have you tried KubeDash on this platform? Please report your experience.


## Tested Browsers

We mostly test with 'modern browsers' defined as the latest version and two older versions. But we try to make KubeDash work with web standards, so it's quite likely other standards conforming browsers will also work.

Platform<div style="min-width: 300px"></div>    | Works | Comments
----------------------------------------------|:-----:|------------------------------------------------------------------------------------------
Edge                     |  ✔️     |
Safari        | ✔️    |
Firefox                     |  ✔️     |
Chrome                     |  ✔️     |
Internet Explorer 11                     |  ✔️     |
