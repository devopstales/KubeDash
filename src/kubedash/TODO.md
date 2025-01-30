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
      * ipaddresspools    [X]
        * data: link back to specific tab
      * l2advertisements
        * data: link back to specific tab
      * bgpadvertisements
        * data: link back to specific tab
      * bgppeers
    * cilium objects
      * ciliumloadbalancerippools
      * ciliuml2announcementpolicies
      * ciliumbgppeeringpolicies

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