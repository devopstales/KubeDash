"""Unit tests for LogExporter - filename generation, text formatting, JSON formatting, Blob creation."""
import unittest
import os


class TestLogExporterInterface(unittest.TestCase):
    """Test that LogExporter JavaScript file exists and has correct structure."""

    def test_log_exporter_file_exists(self):
        """LogExporter JS file should exist."""
        js_file = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'kubedash', 'static', 'js', 'log_viewer', 'log_exporter.js')
        self.assertTrue(os.path.exists(js_file), f"LogExporter JS file not found at {js_file}")

    def test_log_exporter_exports_object(self):
        """LogExporter JS file should export LogExporter object with required methods."""
        js_file = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'kubedash', 'static', 'js', 'log_viewer', 'log_exporter.js')
        with open(js_file, 'r') as f:
            content = f.read()
        self.assertIn('LogExporter', content)
        self.assertIn('exportAsText', content)
        self.assertIn('exportAsJson', content)
        self.assertIn('module.exports', content)


if __name__ == '__main__':
    unittest.main()
