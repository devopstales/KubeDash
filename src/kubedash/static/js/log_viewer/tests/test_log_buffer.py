"""Unit tests for LogBuffer - circular buffer with eviction tracking."""
import unittest
import sys
import os

# Add the log_viewer directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'kubedash', 'static', 'js', 'log_viewer'))

# We'll test the JavaScript module using Node.js
# This Python test file validates the interface contract

class TestLogBufferInterface(unittest.TestCase):
    """Test that LogBuffer JavaScript file exists and has correct structure."""

    def test_log_buffer_file_exists(self):
        """LogBuffer JS file should exist."""
        js_file = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'kubedash', 'static', 'js', 'log_viewer', 'log_buffer.js')
        self.assertTrue(os.path.exists(js_file), f"LogBuffer JS file not found at {js_file}")

    def test_log_buffer_exports_class(self):
        """LogBuffer JS file should export LogBuffer class."""
        js_file = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'kubedash', 'static', 'js', 'log_viewer', 'log_buffer.js')
        with open(js_file, 'r') as f:
            content = f.read()
        self.assertIn('class LogBuffer', content)
        self.assertIn('module.exports', content)


if __name__ == '__main__':
    unittest.main()
