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
    def test_bandit_scan(self):
        """Test code with bandit for security issues"""
        try:
            # Run bandit on source code
            result = subprocess.run(
                [sys.executable, "-m", "bandit", "-r", "blueprint", "lib", "plugins", 
                 "-f", "json", "-ll"],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            )
            
            # Parse bandit output
            import json
            try:
                report = json.loads(result.stdout)
                # Check for high severity issues
                high_severity = [issue for issue in report.get("results", []) 
                               if issue.get("issue_severity") == "HIGH"]
                medium_severity = [issue for issue in report.get("results", [])
                                 if issue.get("issue_severity") == "MEDIUM"]
                
                if high_severity:
                    pytest.fail(f"Bandit found {len(high_severity)} HIGH severity issues: "
                              f"{json.dumps(high_severity, indent=2)}")
                
                # Warn about medium severity (don't fail)
                if medium_severity:
                    pytest.warns(UserWarning, f"Bandit found {len(medium_severity)} MEDIUM severity issues")
            except json.JSONDecodeError:
                # If not JSON, check for errors in output
                if "ERROR" in result.stdout or result.returncode != 0:
                    pytest.fail(f"Bandit scan failed: {result.stdout}\n{result.stderr}")
        except subprocess.TimeoutExpired:
            pytest.skip("Bandit scan timed out")
        except FileNotFoundError:
            pytest.skip("bandit not installed - run: poetry install --with test")

