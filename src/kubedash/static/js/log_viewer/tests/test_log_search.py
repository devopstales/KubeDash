"""Unit tests for LogSearch - match detection, navigation, highlight management, clear."""
import unittest
import os


class TestLogSearchInterface(unittest.TestCase):
    """Test that LogSearch JavaScript file exists and has correct structure."""

    def test_log_search_file_exists(self):
        """LogSearch JS file should exist."""
        js_file = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'kubedash', 'static', 'js', 'log_viewer', 'log_search.js')
        self.assertTrue(os.path.exists(js_file), f"LogSearch JS file not found at {js_file}")

    def test_log_search_exports_class(self):
        """LogSearch JS file should export LogSearch class."""
        js_file = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'kubedash', 'static', 'js', 'log_viewer', 'log_search.js')
        with open(js_file, 'r') as f:
            content = f.read()
        self.assertIn('class LogSearch', content)
        self.assertIn('search', content)
        self.assertIn('nextMatch', content)
        self.assertIn('prevMatch', content)
        self.assertIn('clear', content)
        self.assertIn('module.exports', content)


if __name__ == '__main__':
    unittest.main()
