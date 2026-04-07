"""Unit tests for LogLevelDetector - pattern matching for common log formats."""
import unittest
import os


class TestLogLevelDetectorInterface(unittest.TestCase):
    """Test that LogLevelDetector JavaScript file exists and has correct structure."""

    def test_log_level_detector_file_exists(self):
        """LogLevelDetector JS file should exist."""
        js_file = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'kubedash', 'static', 'js', 'log_viewer', 'log_level_detector.js')
        self.assertTrue(os.path.exists(js_file), f"LogLevelDetector JS file not found at {js_file}")

    def test_log_level_detector_exports_object(self):
        """LogLevelDetector JS file should export LogLevelDetector object."""
        js_file = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'kubedash', 'static', 'js', 'log_viewer', 'log_level_detector.js')
        with open(js_file, 'r') as f:
            content = f.read()
        self.assertIn('LogLevelDetector', content)
        self.assertIn('detect', content)
        self.assertIn('module.exports', content)


if __name__ == '__main__':
    unittest.main()
