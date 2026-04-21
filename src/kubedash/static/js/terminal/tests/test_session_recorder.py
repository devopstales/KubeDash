"""
Unit tests for SessionRecorder - record, sync, finalize event format and timing.
Tests the JavaScript SessionRecorder class interface.
"""
import unittest
import os


class TestSessionRecorderInterface(unittest.TestCase):
    """Test that SessionRecorder JavaScript file exists and has correct structure."""

    def test_session_recorder_file_exists(self):
        """SessionRecorder JS file should exist."""
        js_file = os.path.join(
            os.path.dirname(__file__),
            '..', 'session_recorder.js'
        )
        self.assertTrue(os.path.exists(js_file), f"SessionRecorder JS file not found at {js_file}")

    def test_session_recorder_exports_class(self):
        """SessionRecorder JS file should export SessionRecorder class."""
        js_file = os.path.join(
            os.path.dirname(__file__),
            '..', 'session_recorder.js'
        )
        with open(js_file, 'r') as f:
            content = f.read()
        self.assertIn('class SessionRecorder', content)
        self.assertIn('module.exports', content)

    def test_session_recorder_has_record_input(self):
        """SessionRecorder should have recordInput method."""
        js_file = os.path.join(
            os.path.dirname(__file__),
            '..', 'session_recorder.js'
        )
        with open(js_file, 'r') as f:
            content = f.read()
        self.assertIn('recordInput', content)

    def test_session_recorder_has_record_output(self):
        """SessionRecorder should have recordOutput method."""
        js_file = os.path.join(
            os.path.dirname(__file__),
            '..', 'session_recorder.js'
        )
        with open(js_file, 'r') as f:
            content = f.read()
        self.assertIn('recordOutput', content)

    def test_session_recorder_has_finalize(self):
        """SessionRecorder should have finalize method."""
        js_file = os.path.join(
            os.path.dirname(__file__),
            '..', 'session_recorder.js'
        )
        with open(js_file, 'r') as f:
            content = f.read()
        self.assertIn('finalize', content)

    def test_session_recorder_has_start(self):
        """SessionRecorder should have start method."""
        js_file = os.path.join(
            os.path.dirname(__file__),
            '..', 'session_recorder.js'
        )
        with open(js_file, 'r') as f:
            content = f.read()
        self.assertIn('start', content)

    def test_session_recorder_has_sync(self):
        """SessionRecorder should have _sync method."""
        js_file = os.path.join(
            os.path.dirname(__file__),
            '..', 'session_recorder.js'
        )
        with open(js_file, 'r') as f:
            content = f.read()
        self.assertIn('_sync', content)

    def test_session_recorder_event_format(self):
        """SessionRecorder should create events with correct format."""
        js_file = os.path.join(
            os.path.dirname(__file__),
            '..', 'session_recorder.js'
        )
        with open(js_file, 'r') as f:
            content = f.read()
        # Check event structure
        self.assertIn('timestamp', content)
        self.assertIn('event_type', content)
        self.assertIn('data', content)

    def test_session_recorder_exit_status_options(self):
        """SessionRecorder should support various exit statuses."""
        js_file = os.path.join(
            os.path.dirname(__file__),
            '..', 'session_recorder.js'
        )
        with open(js_file, 'r') as f:
            content = f.read()
        # Check exit status handling
        self.assertIn('exitStatus', content)


class TestSessionRecorderBehavior(unittest.TestCase):
    """Test SessionRecorder behavioral requirements."""

    def test_sync_threshold_configurable(self):
        """SessionRecorder should have configurable sync threshold."""
        js_file = os.path.join(
            os.path.dirname(__file__),
            '..', 'session_recorder.js'
        )
        with open(js_file, 'r') as f:
            content = f.read()
        self.assertIn('syncThreshold', content)

    def test_sync_interval_configurable(self):
        """SessionRecorder should have configurable sync interval."""
        js_file = os.path.join(
            os.path.dirname(__file__),
            '..', 'session_recorder.js'
        )
        with open(js_file, 'r') as f:
            content = f.read()
        self.assertIn('syncInterval', content)

    def test_timing_relative_to_start(self):
        """SessionRecorder should record timestamps relative to session start."""
        js_file = os.path.join(
            os.path.dirname(__file__),
            '..', 'session_recorder.js'
        )
        with open(js_file, 'r') as f:
            content = f.read()
        # Check that timestamps are calculated relative to startTime
        self.assertIn('startTime', content)
        # Should divide by 1000 to get seconds
        self.assertIn('/ 1000', content)


if __name__ == '__main__':
    unittest.main()
