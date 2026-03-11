#!/usr/bin/env python3
"""
Helm operations for AI Chat plugin.

Provides functions for common Helm operations that can be called via MCP tools.
"""

import subprocess
import json
from typing import List, Dict, Optional, Any

from lib.helper_functions import get_logger

logger = get_logger()


def _run_helm_command(args: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    """
    Run a Helm command.

    Args:
        args: Command arguments (without 'helm' prefix)
        timeout: Command timeout in seconds

    Returns:
        CompletedProcess instance

    Raises:
        RuntimeError: On command failure
    """
    cmd = ["helm"] + args
    logger.debug("Running Helm command: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result
    except subprocess.TimeoutExpired:
        logger.error("Helm command timed out after %ds: %s", timeout, " ".join(cmd))
        raise RuntimeError(f"Helm command timed out after {timeout} seconds")
    except FileNotFoundError:
        logger.error("Helm binary not found")
        raise RuntimeError("Helm binary not found. Please install Helm.")
    except Exception as e:
        logger.error("Failed to run Helm command: %s", e)
        raise RuntimeError(f"Helm command failed: {e}")


def list_releases(namespace: Optional[str] = None, all_namespaces: bool = False) -> List[Dict[str, Any]]:
    """
    List Helm releases.

    Args:
        namespace: Optional namespace to filter releases
        all_namespaces: List releases across all namespaces

    Returns:
        List of release dictionaries
    """
    args = ["list", "-o", "json"]

    if all_namespaces:
        args.append("-A")
    elif namespace:
        args.extend(["-n", namespace])

    result = _run_helm_command(args)

    if result.returncode != 0:
        if "nothing deployed" in result.stderr.lower():
            logger.debug("No Helm releases found")
            return []
        logger.error("Helm list failed: %s", result.stderr)
        raise RuntimeError(f"Helm list failed: {result.stderr}")

    try:
        releases = json.loads(result.stdout)
        if not isinstance(releases, list):
            releases = [releases]

        logger.debug("Listed %d Helm releases", len(releases))
        return releases

    except json.JSONDecodeError as e:
        logger.error("Failed to parse Helm output: %s", e)
        raise RuntimeError("Failed to parse Helm output")


def install_release(
    name: str,
    chart: str,
    namespace: str,
    values: Optional[Dict[str, Any]] = None,
    version: Optional[str] = None,
    wait: bool = True,
) -> Dict[str, Any]:
    """
    Install a Helm release.

    Args:
        name: Release name
        chart: Chart name or path
        namespace: Namespace to install to
        values: Optional values dictionary
        version: Optional chart version
        wait: Wait for resources to be ready

    Returns:
        Installation result
    """
    args = [
        "install",
        name,
        chart,
        "-n", namespace,
        "--create-namespace",
    ]

    if values:
        for key, value in values.items():
            args.extend(["--set", f"{key}={value}"])

    if version:
        args.extend(["--version", version])

    if wait:
        args.append("--wait")
        args.extend(["--timeout", "5m"])

    result = _run_helm_command(args, timeout=300)

    if result.returncode != 0:
        logger.error("Helm install failed: %s", result.stderr)
        raise RuntimeError(f"Helm install failed: {result.stderr}")

    logger.info("Installed Helm release: %s/%s", namespace, name)
    return {
        'status': 'installed',
        'name': name,
        'chart': chart,
        'namespace': namespace,
    }


def uninstall_release(name: str, namespace: str) -> Dict[str, Any]:
    """
    Uninstall a Helm release.

    Args:
        name: Release name
        namespace: Release namespace

    Returns:
        Uninstallation result
    """
    args = ["uninstall", name, "-n", namespace]

    result = _run_helm_command(args)

    if result.returncode != 0:
        logger.error("Helm uninstall failed: %s", result.stderr)
        raise RuntimeError(f"Helm uninstall failed: {result.stderr}")

    logger.info("Uninstalled Helm release: %s/%s", namespace, name)
    return {
        'status': 'uninstalled',
        'name': name,
        'namespace': namespace,
    }


def upgrade_release(
    name: str,
    chart: str,
    namespace: str,
    values: Optional[Dict[str, Any]] = None,
    version: Optional[str] = None,
    wait: bool = True,
) -> Dict[str, Any]:
    """
    Upgrade a Helm release.

    Args:
        name: Release name
        chart: Chart name or path
        namespace: Release namespace
        values: Optional values dictionary
        version: Optional chart version
        wait: Wait for resources to be ready

    Returns:
        Upgrade result
    """
    args = [
        "upgrade",
        name,
        chart,
        "-n", namespace,
    ]

    if values:
        for key, value in values.items():
            args.extend(["--set", f"{key}={value}"])

    if version:
        args.extend(["--version", version])

    if wait:
        args.append("--wait")
        args.extend(["--timeout", "5m"])

    result = _run_helm_command(args, timeout=300)

    if result.returncode != 0:
        logger.error("Helm upgrade failed: %s", result.stderr)
        raise RuntimeError(f"Helm upgrade failed: {result.stderr}")

    logger.info("Upgraded Helm release: %s/%s", namespace, name)
    return {
        'status': 'upgraded',
        'name': name,
        'chart': chart,
        'namespace': namespace,
    }


def get_release_status(name: str, namespace: str) -> Dict[str, Any]:
    """
    Get status of a Helm release.

    Args:
        name: Release name
        namespace: Release namespace

    Returns:
        Release status dictionary
    """
    args = ["status", name, "-n", namespace, "-o", "json"]

    result = _run_helm_command(args)

    if result.returncode != 0:
        if "not found" in result.stderr.lower():
            logger.warning("Helm release %s/%s not found", namespace, name)
            raise RuntimeError(f"Helm release '{name}' not found in namespace '{namespace}'")
        logger.error("Helm status failed: %s", result.stderr)
        raise RuntimeError(f"Helm status failed: {result.stderr}")

    try:
        status = json.loads(result.stdout)
        logger.debug("Got status for Helm release: %s/%s", namespace, name)
        return status
    except json.JSONDecodeError as e:
        logger.error("Failed to parse Helm status output: %s", e)
        raise RuntimeError("Failed to parse Helm status output")


def get_release_history(name: str, namespace: str) -> List[Dict[str, Any]]:
    """
    Get revision history of a Helm release.

    Args:
        name: Release name
        namespace: Release namespace

    Returns:
        List of revision dictionaries
    """
    args = ["history", name, "-n", namespace, "-o", "json"]

    result = _run_helm_command(args)

    if result.returncode != 0:
        if "not found" in result.stderr.lower():
            logger.warning("Helm release %s/%s not found", namespace, name)
            raise RuntimeError(f"Helm release '{name}' not found in namespace '{namespace}'")
        logger.error("Helm history failed: %s", result.stderr)
        raise RuntimeError(f"Helm history failed: {result.stderr}")

    try:
        history = json.loads(result.stdout)
        if not isinstance(history, list):
            history = [history]

        logger.debug("Got history for Helm release: %s/%s (%d revisions)", namespace, name, len(history))
        return history

    except json.JSONDecodeError as e:
        logger.error("Failed to parse Helm history output: %s", e)
        raise RuntimeError("Failed to parse Helm history output")


def rollback_release(name: str, namespace: str, revision: Optional[int] = None) -> Dict[str, Any]:
    """
    Rollback a Helm release to a previous revision.

    Args:
        name: Release name
        namespace: Release namespace
        revision: Optional revision number (defaults to previous revision)

    Returns:
        Rollback result
    """
    args = ["rollback", name, "-n", namespace]

    if revision:
        args.append(str(revision))

    result = _run_helm_command(args, timeout=300)

    if result.returncode != 0:
        logger.error("Helm rollback failed: %s", result.stderr)
        raise RuntimeError(f"Helm rollback failed: {result.stderr}")

    logger.info("Rolled back Helm release: %s/%s to revision %s", namespace, name, revision or "previous")
    return {
        'status': 'rolled_back',
        'name': name,
        'namespace': namespace,
        'revision': revision,
    }


def get_values(name: str, namespace: str, all_values: bool = False) -> Dict[str, Any]:
    """
    Get values of a Helm release.

    Args:
        name: Release name
        namespace: Release namespace
        all_values: Get all values including defaults

    Returns:
        Values dictionary
    """
    args = ["get", "values", name, "-n", namespace, "-o", "json"]

    if all_values:
        args.append("--all")

    result = _run_helm_command(args)

    if result.returncode != 0:
        if "not found" in result.stderr.lower():
            logger.warning("Helm release %s/%s not found", namespace, name)
            raise RuntimeError(f"Helm release '{name}' not found in namespace '{namespace}'")
        logger.error("Helm get values failed: %s", result.stderr)
        raise RuntimeError(f"Helm get values failed: {result.stderr}")

    try:
        values = json.loads(result.stdout)
        logger.debug("Got values for Helm release: %s/%s", namespace, name)
        return values
    except json.JSONDecodeError as e:
        logger.error("Failed to parse Helm values output: %s", e)
        raise RuntimeError("Failed to parse Helm values output")
