from flask import Flask, Blueprint, render_template
from flask_smorest import Api
from swagger_ui_bundle import swagger_ui_path

#####################################################################
# create_app
#####################################################################
def create_app():
    app = Flask(__name__)

    # Configure Flask-Smorest
    app.config.update({
        "API_TITLE": "KubeSpace API",
        "API_VERSION": "v1",
        "OPENAPI_VERSION": "3.0.2",
        "OPENAPI_URL_PREFIX": "/api",
        "OPENAPI_SWAGGER_UI_PATH": "/swagger-ui",
        "OPENAPI_SWAGGER_UI_URL": "/api/swagger-ui/",  # serving locally
    })

    api_doc = Api()
    api_doc.init_app(app)

    from .k8s_api_extension import extension_api_root_bp, extension_api_space_bp
    api_doc.register_blueprint(extension_api_root_bp)
    api_doc.register_blueprint(extension_api_space_bp)

    # Blueprint to serve Swagger UI assets
    swagger_bp = Blueprint(
        "swagger_ui",
        __name__,
        static_folder=swagger_ui_path,
        static_url_path="",  # so assets map correctly
        template_folder=swagger_ui_path
    )

    @swagger_bp.route("/")
    def swagger_ui_index():
        # Render the index.html inside swagger_ui_bundle package
        return render_template("index.j2")

    app.register_blueprint(swagger_bp, url_prefix=app.config["OPENAPI_SWAGGER_UI_URL"].rstrip('/'))

    return app
