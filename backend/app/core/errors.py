"""OD-1 — the frozen v1 error contract.

Every KubeDash API error leaves through this hierarchy and the ``{error:
{code, message, details?}}`` envelope (``KubeDashHttpError.as_dict``). The
14 stable codes below are frozen: Tasks 4-6 raise these, and Task 8's
frontend switches on ``error.code``. New code = new version.

Smorest 0.47 ships no ``HttpError`` symbol, so the base extends
``werkzeug.exceptions.HTTPException`` directly — that is the type Flask's
error-handler dispatch keys on, and ``code``/``name`` are set per subclass.
"""
from werkzeug.exceptions import HTTPException


class KubeDashHttpError(HTTPException):
    """Base for every stable-code error. Subclasses set ``code`` and ``error_code``."""

    error_code: str = "ERROR"

    def __init__(self, message: str, details: dict[str, object] | None = None):
        self.details = details
        super().__init__(description=message)

    @property
    def message(self) -> str:
        return self.description or ""

    def as_dict(self) -> dict[str, object]:
        d: dict[str, object] = {"code": self.error_code, "message": self.message}
        if self.details:
            d["details"] = self.details
        return d


class UnauthorizedError(KubeDashHttpError):
    code = 401
    name = "Unauthorized"
    error_code = "UNAUTHORIZED"


class InvalidCredentialsError(UnauthorizedError):
    """Local password login (ADR-0021): wrong password OR unknown email —
    ONE code for both (no user enumeration), including SSO-sourced rows."""
    code = 401
    name = "Invalid Credentials"
    error_code = "INVALID_CREDENTIALS"


class LocalAuthDisabledError(KubeDashHttpError):
    """Local password login attempted with no bootstrap admin configured
    (ADR-0021): both bootstrap env vars unset."""
    code = 403
    name = "Local Auth Disabled"
    error_code = "LOCAL_AUTH_DISABLED"


class StateMismatchError(UnauthorizedError):
    """Dedicated carrier for the OIDC callback's ``consume_state`` failure:
    the factory's error handler maps THIS class (not plain UnauthorizedError)
    to 400 STATE_MISMATCH, keeping 401 UNAUTHORIZED for real auth failures."""

    code = 400
    name = "State Mismatch"
    error_code = "STATE_MISMATCH"


class RbacDeniedError(KubeDashHttpError):
    code = 403
    name = "RBAC Denied"
    error_code = "RBAC_DENIED"


class ClusterNotFoundError(KubeDashHttpError):
    code = 404
    name = "Cluster Not Found"
    error_code = "CLUSTER_NOT_FOUND"


class ResourceKindNotSupportedError(KubeDashHttpError):
    code = 404
    name = "Resource Kind Not Supported"
    error_code = "RESOURCE_KIND_NOT_SUPPORTED"


class ClusterUnreachableError(KubeDashHttpError):
    code = 502
    name = "Cluster Unreachable"
    error_code = "CLUSTER_UNREACHABLE"


class ClusterAlreadyExistsError(KubeDashHttpError):
    code = 409
    name = "Cluster Already Exists"
    error_code = "CLUSTER_ALREADY_EXISTS"


class InvalidKubeconfigError(KubeDashHttpError):
    code = 422
    name = "Invalid Kubeconfig"
    error_code = "INVALID_KUBECONFIG"


class BuiltinTemplateProtectedError(KubeDashHttpError):
    """ADR-0013: a builtin role template cannot be mutated or deleted."""

    code = 409
    name = "Builtin Template Protected"
    error_code = "BUILTIN_TEMPLATE_PROTECTED"


class NoBindingsError(KubeDashHttpError):
    """ADR-0013: no cluster binding exists for the user (e.g. kubeconfig
    download with zero bindings)."""

    code = 404
    name = "No Bindings"
    error_code = "NO_BINDINGS"


class NotImplementedError_(KubeDashHttpError):
    code = 501
    name = "Not Implemented"
    error_code = "NOT_IMPLEMENTED"


class InternalError(KubeDashHttpError):
    code = 500
    name = "Internal Error"
    error_code = "INTERNAL_ERROR"


#: Every stable code, one class each — the count is a contract. ADR-0021
#: (OD-B) adds the two local-auth codes; ADR-0013 (user-management) adds the
#: two template/binding codes — 14 total.
CODES: tuple[type[KubeDashHttpError], ...] = (
    UnauthorizedError,
    InvalidCredentialsError,
    LocalAuthDisabledError,
    StateMismatchError,
    RbacDeniedError,
    ClusterNotFoundError,
    ResourceKindNotSupportedError,
    ClusterUnreachableError,
    ClusterAlreadyExistsError,
    InvalidKubeconfigError,
    NotImplementedError_,
    InternalError,
    BuiltinTemplateProtectedError,
    NoBindingsError,
)

#: HTTP status of a bare (non-state) 401 auth failure.
UNAUTHORIZED_STATUS = 401
