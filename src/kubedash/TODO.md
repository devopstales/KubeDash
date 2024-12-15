# TODO

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
* move plugins to plugins folder:
  * registry
  * helm
  * trivy-operator
* Show user groups on user panel.