# TODO

* cache K8S Api resoults in redis [!]
  * https://levelup.gitconnected.com/api-caching-with-redis-flask-and-kubernetes-a20ac2a11a8b
* dashboard events list
* store user selected ns persist
* Show user groups on user panel.
* Cluster / CRDs [!]
* Cluster / Runetime Class [!]
* POD data: [!]
  * events
  * Priority Class as link
  * Runetime Class as link
* move plugins to plugins folder:
  * registry
  * helm
    * helm-controller
      * https://github.com/k3s-io/helm-controller/releases
  * trivy-operator
  * external loadbalancer [!]
    * metallb objects
    * cilium objects
  * application catalog [!]
    * config store in db
    * config panel for URLS
    * integration links on dashboard
    * application catalog menu
      * namespace list
      * metadata list
      * app data menu
        * show metadata links
    * Hierarchical Namespaces
      * https://kubernetes.io/blog/2020/08/14/introducing-hierarchical-namespaces/
    * FluxCD
      * Show objects and status
* gunicorn
  * termibal, and log           [X]
* move plugins to plugins folder:
  * registry                    [X]
  * helm                        [X]
* Show user groups on user panel
* plugins:
  * External LoadBalancer       [-]
    * ui
      * UI szétesés
      * üres lista
    * metallb                   [-]
    * cilium objektumok         [-]
  * links
  * development links
    * development info from annotations: https://ambassadorlabs.github.io/k8s-for-humans/
  * grafana
    * link
    * dashboard
  * jeager
    * include
    * link
  * loki
    * dashboard
    * link
  * detectdojo
  * dependencytrack
  * tekton
    * pipelines
    * tasks
  * fluxcd
    * git repo
    * helm reposytory
    * helm release
    * kustomize
* socket auto reconnect         [ ]
* load api-server cert from pod [X]
* pytest                        [-]
* swagger-UI                    [x]  
* opentelemetry 
  * open jaeger from UI
  * tracing instrumentors
    * database                  [x]
    * flask                     [x]
    * request                   [X]
    * logging                   [ ]
  * rutes
    * accounts.py               [ ]
    * api.py                    [ ]
    * dashboard.py              [x]
    * helm.py                   [ ]
    * limits.py                 [ ]
    * metrics.py                [ ]
    * namespaces.py             [ ]
    * networks.py               [ ]
    * nodes.py                  [ ]
    * pods.py                   [ ]
    * registry.py               [ ]
    * security.py               [ ]
    * sso.py                    [ ]
    * storages.py               [ ]
    * workloads.py              [ ]
  * plugins
    * cert_manager.py           [ ]
    * external_loadbalancer.py  [ ]
    * gateway_api.py            [ ]

