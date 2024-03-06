# What is KubeDash?

KubeDash is a general purpose, web-based UI for Kubernetes clusters. It allows users to observe applications running in the cluster and troubleshoot them, as well as manage the cluster itself.

KubeDash was created to be a Kubernetes web UI that has the traditional functionality of other web UIs/dashboards available (i.e. to list and view resources) as well as other features.

## Features

* Manage any Kubernetes cluster.
* CPU and Memory metrics visualization.
* User management.
  * Role management for users based on templates
  * Role management for SSO groups based on templates
* Pod Debugging
  * Login to pod with UI based terminal
  * View container logs in pods
* [trivy-operator](https://devopstales.github.io/trivy-operator/) integration to visualize vulnerability
* Single sign-on integration with authentication and authorization
* Kubectl configuration generation
  * Generate OIDC based Kubernetes API authentication
  * Generate Certificate based authentication
  * kubectl plugin for easier config download
* Dashboard Plugins
  * Docker Registry UI
  * Hem Chart listing
* Coming soon:
  * Gateway API Plugin for object visualization
  * Cert-manager Plugin object visualization
  * FluxCD Plugin object visualization