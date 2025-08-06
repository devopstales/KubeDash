from flask_smorest import Blueprint

project_bp = Blueprint(
    "project",            # name
    __name__,             # import name
    url_prefix="/projects",  # mounted under /projects
    description="Kubernetes Project Extension API"
)

from . import routes
