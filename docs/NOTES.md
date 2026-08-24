I want to create a new enterprise grade opensource kubernetes dashboard called kubedash. Using python, gunicorn, and bootstrap 5 with coreui for the frontend.


* development env
  * poetry
  * docker compose files
  * Tasfile for build automatization and docker dev env start stop
* kubedash
  * swagger-ui
  * prometheus endpoint
  * opentelemetry integration
  * technology
    * python api
      * poetry
      * gunicorn
      * flask
      * flask_wtf
      * flask-socketio
      * flask-smorest
      * flask_sqlalchemy
        * postgresql db
      * flask_socketio
    * use Blueprint for separation
    * bootstrap 5 with coreui for the frontend
  * ini based main config
  * login
    *  KubeDash also supports Kubernetes ServiceAccount token authentication and OIDC/SSO for teams that already have an identity provider.
  * CRD auto detection
    * The first thing KubeDash does on startup is call GET /apis on the Kubernetes API Server. This enumerates every API group, version, and resource type in your cluster — including all installed CRDs.
  * GitOps:
    * KubeDash automatically detects whether ArgoCD or Flux CD is installed by checking for their CRDs in the cluster.
  * kubernetes extension api (separate to mini app ???)
    * project object that similare to ns but onlyi show namespace that you have permission. similrate the openshift.
  * ingress and gatewai api
  * network policy (basic, cilium)
  * network loadbalancer (cilium, metallb)
  * AI help for debugging
  * socket based terminal and log viever for pods.
  * cloud shell shimilare then azure cloud shell or in rancher with configurable base image

* kdlogin
  * go based kubectl plugin for automatic sso based login.

* documentation
  * use mkdocs to generate documentation