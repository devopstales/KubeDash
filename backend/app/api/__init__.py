from flask import Flask
from flask_smorest import Api


def register_apis(app: Flask, api: Api) -> None:
    """Domain registration point — later tasks add their Api classes here.

    flask-smorest 0.47 has no Api.register: the domain Api subclass carries
    a ``blp`` (flask_smorest.Blueprint) as a CLASS attribute — the instance
    does not get an instance attribute, so ``instance.blp`` resolves to that
    class attr. We register it with a name derived from resources_namespace,
    then run the subclass's on_init — where each domain Api wires the shared
    /api/v1/* auth hook (``app/api/_authhook.py``) and whose bound methods
    become the doc-registered views."""
    from app.api.auth import AuthApi
    from app.api.clusters import ClusterApi

    for cls in (AuthApi, ClusterApi):
        instance = cls()
        name = f"api.{instance.resources_namespace}"
        instance.on_init(app)
        # register_blueprint runs the blueprint's deferred functions, which
        # bind the view functions (self = instance) into app.view_functions
        # and store their doc info for the OpenAPI spec.
        # url_prefix="/api/v1" overrides the blueprint's "/v1" so routes land
        # at /api/v1/* (the OPENAPI_URL_PREFIX is docs-only, not a route prefix).
        api.register_blueprint(instance.blp, name=name, url_prefix="/api/v1")
        # ponytail: flask-smorest 0.47 stores unbound view functions in the
        # blueprint's deferred functions — rebind them to the instance here.
        # The upgrade path is smorest's Api.register (when it ships).
        for endpoint, view_func in list(app.view_functions.items()):
            if endpoint.startswith(f"{name}.") and not hasattr(view_func, "__self__"):
                method_name = endpoint[len(name) + 1:]
                bound = getattr(instance, method_name, None)
                if bound is not None:
                    app.view_functions[endpoint] = bound
