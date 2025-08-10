try:
    from importlib.metadata import version, PackageNotFoundError
except ImportError:
    from importlib_metadata import version, PackageNotFoundError  # For Python < 3.8

try:
    __version__ = version("kubedash")
except PackageNotFoundError:
    __version__ = "unknown"  # fallback for dev environments
