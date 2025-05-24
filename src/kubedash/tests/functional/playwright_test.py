# https://playwright.dev/python/docs/intro
import re

from playwright.sync_api import Playwright, expect, sync_playwright


def test_login(playwright: Playwright) -> None:
    browser = playwright.firefox.launch(headless=False)
    context = browser.new_context()
    page = context.new_page()
    page.goto("http://127.0.0.1:8000/")
    page.get_by_placeholder("Username").click()
    page.get_by_placeholder("Username").fill("pytest")
    page.get_by_placeholder("Password").click()
    page.get_by_placeholder("Password").fill("pytest")
    page.get_by_role("button", name="Sign in").click()
    expect(page.get_by_label("breadcrumb").get_by_role("listitem")).to_contain_text("Dashboard")

    # ---------------------
    context.close()
    browser.close()


with sync_playwright() as playwright:
    test_login(playwright)