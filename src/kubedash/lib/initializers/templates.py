#!/usr/bin/env python3
"""Jinja2 template filters initialization for KubeDash."""

from flask import Flask


def add_custom_jinja2_filters(app: Flask):
    """Add custom Jinja2 filers."""
    app.logger.info("Adding custom Jinja2 filters")

    from lib.custom_jinja2 import j2_b64decode, j2_b64encode, split_uppercase, check_url_exists

    app.add_template_filter(j2_b64decode)
    app.add_template_filter(j2_b64encode)
    app.add_template_filter(split_uppercase)
    app.add_template_filter(check_url_exists)
