/**
 * SessionRecorder - Captures terminal I/O events with timestamps for audit and replay.
 * 
 * Records input and output events with relative timestamps (seconds from session start).
 * Batches events for efficient sync (every 10 seconds or 100 events).
 * Finalizes on session end with exit status.
 */
class SessionRecorder {
  constructor(options = {}) {
    this.sessionId = null;
    this.startTime = null;
    this.events = [];
    this.syncInterval = options.syncInterval || 10000; // 10 seconds
    this.syncThreshold = options.syncThreshold || 100; // 100 events
    this.syncTimer = null;
    this.onSync = options.onSync || null; // Callback when sync happens
    this.onFinalize = options.onFinalize || null; // Callback when finalized
    this.isRecording = false;
    this.finalized = false;
  }

  /**
   * Start recording a new session.
   * @param {string} sessionId - Session identifier
   */
  start(sessionId) {
    this.sessionId = sessionId;
    this.startTime = Date.now();
    this.events = [];
    this.isRecording = true;
    this.finalized = false;

    // Start periodic sync
    this._startSyncTimer();
  }

  /**
   * Record an input event (user keystroke).
   * @param {string} data - Input text
   */
  recordInput(data) {
    if (!this.isRecording) return;
    this._addEvent('input', data);
  }

  /**
   * Record an output event (terminal output).
   * @param {string} data - Output text
   */
  recordOutput(data) {
    if (!this.isRecording) return;
    this._addEvent('output', data);
  }

  /**
   * Add an event to the buffer and trigger sync if threshold reached.
   * @param {string} type - 'input' or 'output'
   * @param {string} data - Event data
   * @private
   */
  _addEvent(type, data) {
    const timestamp = (Date.now() - this.startTime) / 1000; // seconds from start
    this.events.push({
      timestamp: parseFloat(timestamp.toFixed(3)),
      event_type: type,
      data: data
    });

    // Sync if threshold reached
    if (this.events.length >= this.syncThreshold) {
      this._sync();
    }
  }

  /**
   * Start the periodic sync timer.
   * @private
   */
  _startSyncTimer() {
    this._stopSyncTimer();
    this.syncTimer = setInterval(() => {
      if (this.events.length > 0) {
        this._sync();
      }
    }, this.syncInterval);
  }

  /**
   * Stop the periodic sync timer.
   * @private
   */
  _stopSyncTimer() {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
      this.syncTimer = null;
    }
  }

  /**
   * Sync pending events to server.
   * @private
   */
  async _sync() {
    if (this.events.length === 0 || !this.sessionId) return;

    const eventsToSync = [...this.events];
    this.events = [];

    if (this.onSync) {
      this.onSync(this.sessionId, eventsToSync);
    }
  }

  /**
   * Finalize the recording - sync remaining events and mark complete.
   * @param {string} exitStatus - 'normal', 'timeout', 'error', 'user-disconnect', 'connection-lost'
   * @param {object} metadata - Additional session metadata
   */
  async finalize(exitStatus = 'normal', metadata = {}) {
    if (this.finalized) return;

    // Sync remaining events
    await this._sync();

    // Stop timer
    this._stopSyncTimer();

    // Mark as finalized
    this.isRecording = false;
    this.finalized = true;

    // Calculate duration
    const durationMs = Date.now() - this.startTime;

    if (this.onFinalize) {
      this.onFinalize(this.sessionId, {
        exitStatus,
        durationMs,
        endTime: new Date().toISOString(),
        ...metadata
      });
    }
  }

  /**
   * Get all recorded events (for testing/debugging).
   * @returns {Array}
   */
  getEvents() {
    return [...this.events];
  }

  /**
   * Get event count.
   * @returns {number}
   */
  getEventCount() {
    return this.events.length;
  }

  /**
   * Clear all recorded events (for testing).
   */
  clear() {
    this.events = [];
  }

  /**
   * Check if currently recording.
   * @returns {boolean}
   */
  isCurrentlyRecording() {
    return this.isRecording;
  }
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { SessionRecorder };
}
