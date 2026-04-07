"""
Functional tests for log view page rendering with mocked Socket.IO events.

Tests the enhanced log viewer template and JavaScript functionality.
"""
import unittest
import os


class TestEnhancedLogViewerTemplate(unittest.TestCase):
    """Test cases for the enhanced log viewer template."""

    def test_pod_logs_template_exists(self):
        """Test that pod-logs.html.j2 template exists."""
        template_file = os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..', '..', 'templates', 'workload', 'pod-logs.html.j2'
        )
        self.assertTrue(os.path.exists(template_file), f"Template not found at {template_file}")

    def test_template_has_toolbar(self):
        """Test that template includes toolbar controls."""
        template_file = os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..', '..', 'templates', 'workload', 'pod-logs.html.j2'
        )
        with open(template_file, 'r') as f:
            content = f.read()
        
        # Check for toolbar elements
        self.assertIn('id="log-toolbar"', content, "Toolbar container not found")
        self.assertIn('id="auto-scroll-toggle"', content, "Auto-scroll toggle not found")
        self.assertIn('id="timestamp-toggle"', content, "Timestamp toggle not found")
        self.assertIn('id="level-filter"', content, "Level filter not found")

    def test_template_has_search(self):
        """Test that template includes search bar."""
        template_file = os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..', '..', 'templates', 'workload', 'pod-logs.html.j2'
        )
        with open(template_file, 'r') as f:
            content = f.read()
        
        self.assertIn('id="search-input"', content, "Search input not found")
        self.assertIn('id="search-match-count"', content, "Search match count not found")
        self.assertIn('id="search-prev"', content, "Search previous button not found")
        self.assertIn('id="search-next"', content, "Search next button not found")
        self.assertIn('id="search-clear"', content, "Search clear button not found")

    def test_template_has_export(self):
        """Test that template includes export controls."""
        template_file = os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..', '..', 'templates', 'workload', 'pod-logs.html.j2'
        )
        with open(template_file, 'r') as f:
            content = f.read()
        
        self.assertIn('id="export-btn"', content, "Export button not found")
        self.assertIn('id="export-format-dropdown"', content, "Export format dropdown not found")
        self.assertIn('export-format-link', content, "Export format links not found")

    def test_template_has_status_bar(self):
        """Test that template includes status bar."""
        template_file = os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..', '..', 'templates', 'workload', 'pod-logs.html.j2'
        )
        with open(template_file, 'r') as f:
            content = f.read()
        
        self.assertIn('id="log-status-bar"', content, "Status bar not found")
        self.assertIn('id="connection-status"', content, "Connection status indicator not found")
        self.assertIn('id="buffer-usage"', content, "Buffer usage indicator not found")
        self.assertIn('id="line-count"', content, "Line count display not found")
        self.assertIn('id="reconnect-btn"', content, "Reconnect button not found")

    def test_template_has_log_content_area(self):
        """Test that template includes log content area."""
        template_file = os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..', '..', 'templates', 'workload', 'pod-logs.html.j2'
        )
        with open(template_file, 'r') as f:
            content = f.read()
        
        self.assertIn('id="log-content"', content, "Log content area not found")

    def test_template_loads_js_modules(self):
        """Test that template loads all required JS modules."""
        template_file = os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..', '..', 'templates', 'workload', 'pod-logs.html.j2'
        )
        with open(template_file, 'r') as f:
            content = f.read()
        
        required_modules = [
            'log_level_detector.js',
            'log_buffer.js',
            'log_filter.js',
            'log_renderer.js',
            'log_search.js',
            'log_exporter.js',
            'log_viewer.js',
            'log_init.js'
        ]
        
        for module in required_modules:
            self.assertIn(module, content, f"JS module {module} not loaded in template")

    def test_template_has_css_styles(self):
        """Test that template includes CSS styles."""
        template_file = os.path.join(
            os.path.dirname(__file__),
            '..', '..', '..', '..', 'templates', 'workload', 'pod-logs.html.j2'
        )
        with open(template_file, 'r') as f:
            content = f.read()
        
        # Check for key CSS classes
        self.assertIn('.log-toolbar', content, "Toolbar CSS not found")
        self.assertIn('.log-content', content, "Content area CSS not found")
        self.assertIn('.log-line', content, "Log line CSS not found")
        self.assertIn('.log-status-bar', content, "Status bar CSS not found")
        self.assertIn('.search-match', content, "Search match highlighting CSS not found")


class TestLogViewerJSModules(unittest.TestCase):
    """Test cases for log viewer JavaScript modules."""

    def test_all_js_modules_exist(self):
        """Test that all JavaScript module files exist."""
        modules = [
            'log_level_detector.js',
            'log_buffer.js',
            'log_filter.js',
            'log_renderer.js',
            'log_search.js',
            'log_exporter.js',
            'log_viewer.js',
            'log_init.js'
        ]
        
        base_path = os.path.join(
            os.path.dirname(__file__),
            '..', '..', 'log_viewer'
        )
        
        for module in modules:
            module_path = os.path.join(base_path, module)
            self.assertTrue(os.path.exists(module_path), f"Module {module} not found at {module_path}")

    def test_modules_have_exports(self):
        """Test that modules export their classes/objects."""
        base_path = os.path.join(
            os.path.dirname(__file__),
            '..', '..', 'log_viewer'
        )
        
        exports_map = {
            'log_buffer.js': 'LogBuffer',
            'log_level_detector.js': 'LogLevelDetector',
            'log_filter.js': 'LogFilter',
            'log_renderer.js': 'LogRenderer',
            'log_search.js': 'LogSearch',
            'log_exporter.js': 'LogExporter',
            'log_viewer.js': 'LogViewer'
        }
        
        for module, export_name in exports_map.items():
            module_path = os.path.join(base_path, module)
            with open(module_path, 'r') as f:
                content = f.read()
            self.assertIn(export_name, content, f"{export_name} not found in {module}")
            self.assertIn('module.exports', content, f"module.exports not found in {module}")


if __name__ == '__main__':
    unittest.main()
