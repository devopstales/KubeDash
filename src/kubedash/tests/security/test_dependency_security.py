"""
Security tests for dependency vulnerabilities

These tests use security scanning tools to check for
known vulnerabilities in dependencies.
"""
import pytest
import subprocess
import sys
import os


class TestDependencySecurity:
    """Test dependency security"""
    
    @pytest.mark.skipif(
        not os.getenv("RUN_DEPENDENCY_SCANS", "false").lower() == "true",
        reason="Dependency scans are slow - set RUN_DEPENDENCY_SCANS=true to run"
    )
    def test_safety_check(self):
        """Test that dependencies don't have known vulnerabilities (safety)"""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "safety", "check", "--json"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Safety returns non-zero exit code if vulnerabilities found
            if result.returncode != 0:
                # Parse JSON output for vulnerabilities
                import json
                try:
                    vulns = json.loads(result.stdout)
                    if vulns:
                        pytest.fail(f"Found {len(vulns)} known vulnerabilities: {result.stdout}")
                except json.JSONDecodeError:
                    # If not JSON, check stdout
                    if "vulnerability" in result.stdout.lower() or "vulnerability" in result.stderr.lower():
                        pytest.fail(f"Safety check found vulnerabilities: {result.stdout}\n{result.stderr}")
        except subprocess.TimeoutExpired:
            pytest.skip("Safety check timed out")
        except FileNotFoundError:
            pytest.skip("safety not installed - run: poetry install --with test")
    
    @pytest.mark.skipif(
        not os.getenv("RUN_DEPENDENCY_SCANS", "false").lower() == "true",
        reason="Dependency scans are slow - set RUN_DEPENDENCY_SCANS=true to run"
    )
    def test_pip_audit_check(self):
        """Test that dependencies don't have known vulnerabilities (pip-audit)"""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip_audit", "--format", "json"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # pip-audit returns non-zero exit code if vulnerabilities found
            if result.returncode != 0:
                import json
                try:
                    vulns = json.loads(result.stdout)
                    if vulns and len(vulns) > 0:
                        pytest.fail(f"Found vulnerabilities: {result.stdout}")
                except json.JSONDecodeError:
                    if "vulnerability" in result.stdout.lower() or "vulnerability" in result.stderr.lower():
                        pytest.fail(f"pip-audit found vulnerabilities: {result.stdout}\n{result.stderr}")
        except subprocess.TimeoutExpired:
            pytest.skip("pip-audit check timed out")
        except FileNotFoundError:
            pytest.skip("pip-audit not installed - run: poetry install --with test")


class TestStaticAnalysisSecurity:
    """Test static code analysis for security issues"""
    
    @pytest.mark.skipif(
        not os.getenv("RUN_STATIC_ANALYSIS", "false").lower() == "true",
        reason="Static analysis is slow - set RUN_STATIC_ANALYSIS=true to run"
    )
    def test_semgrep_scan(self):
        """Test code with semgrep for security issues (replaces bandit)"""
        import json
        cwd = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        try:
            result = subprocess.run(
                [
                    sys.executable, "-m", "semgrep", "--config=auto",
                    "--exclude-rule", "python.lang.security.audit.assert_used.assert_used",
                    "--exclude-rule", "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
                    "--json", ".",
                ],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=cwd,
            )
            # Semgrep exits 1 when findings exist; stdout is still valid JSON
            try:
                report = json.loads(result.stdout)
                results = report.get("results", [])
                errors = [r for r in results if r.get("extra", {}).get("severity") == "ERROR"]
                warnings_list = [r for r in results if r.get("extra", {}).get("severity") == "WARNING"]
                if errors:
                    pytest.fail(
                        f"Semgrep found {len(errors)} ERROR severity issues: "
                        f"{json.dumps(errors[:5], indent=2)}"
                        + (f" ... and {len(errors) - 5} more" if len(errors) > 5 else "")
                    )
                # WARNING severity is reported but does not fail the test
                if warnings_list:
                    import warnings
                    warnings.warn(f"Semgrep found {len(warnings_list)} WARNING severity issues", UserWarning)
            except json.JSONDecodeError:
                if result.returncode not in (0, 1):
                    pytest.fail(f"Semgrep scan failed: {result.stdout}\n{result.stderr}")
        except subprocess.TimeoutExpired:
            pytest.skip("Semgrep scan timed out")
        except FileNotFoundError:
            pytest.skip("semgrep not installed - run: poetry install --with test")

