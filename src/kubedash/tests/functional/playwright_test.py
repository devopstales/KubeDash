"""
Functional tests using Playwright for end-to-end browser testing

Note: These tests require Playwright browsers to be installed.
Run `playwright install` to install browser binaries.
"""
import os
import pytest

# Try to import playwright, skip tests if not available
try:
    from playwright.sync_api import Playwright, expect, sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    pytestmark = pytest.mark.skip(reason="Playwright not installed")


@pytest.fixture(scope="function")
def playwright_browser():
    """Fixture to provide Playwright browser instance"""
    if not PLAYWRIGHT_AVAILABLE:
        pytest.skip("Playwright not installed")
    
    try:
        with sync_playwright() as playwright:
            # Use headless mode by default for CI/testing
            # Set PLAYWRIGHT_HEADED=1 environment variable to run with visible browser
            headless = os.getenv("PLAYWRIGHT_HEADED", "false").lower() != "true"
            browser = playwright.firefox.launch(headless=headless)
            yield browser
            browser.close()
    except Exception as e:
        pytest.skip(f"Playwright browser not available: {e}. Run 'playwright install' to install browsers.")


@pytest.mark.skipif(not PLAYWRIGHT_AVAILABLE, reason="Playwright not installed")
@pytest.mark.skip(reason="Requires running application server - use integration tests instead")
def test_login(playwright_browser):
    """Test login flow using Playwright
    
    Note: This test requires:
    1. Playwright browsers installed (run `playwright install`)
    2. The application running on http://127.0.0.1:8765/
    3. A test user with username/password: pytest/pytest
    
    This test is skipped by default as it requires a running server.
    For functional testing without a server, use the Flask test client in integration tests.
    """
    context = playwright_browser.new_context()
    page = context.new_page()
    
    try:
        # Navigate to login page
        # Note: This assumes the app is running on localhost:8765
        # In CI, this might need to be configured differently
        page.goto("http://127.0.0.1:8765/", timeout=10000)
        
        # Fill in login form
        page.get_by_placeholder("Username").click()
        page.get_by_placeholder("Username").fill("pytest")
        page.get_by_placeholder("Password").click()
        page.get_by_placeholder("Password").fill("pytest")
        page.get_by_role("button", name="Sign in").click()
        
        # Wait for navigation and verify successful login
        # Verify successful login by checking for dashboard breadcrumb
        expect(page.get_by_label("breadcrumb").get_by_role("listitem")).to_contain_text("Dashboard", timeout=10000)
    finally:
        context.close()