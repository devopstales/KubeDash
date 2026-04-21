/**
 * TerminalTab - Single terminal tab wrapping xterm.js with Socket.IO connection.
 * 
 * Manages:
 * - xterm.js terminal instance with addons (Fit, WebLinks)
 * - Socket.IO connection to /exec namespace
 * - Input/output loop via pod_exec, response, exec-input, closed, stop events
 * - SessionRecorder for audit
 * - Timeout timer for session expiration
 * - Connection state tracking
 */
class TerminalTab {
  constructor(container, options = {}) {
    this.container = container;
    this.podName = options.podName || '';
    this.namespace = options.namespace || 'default';
    this.containerName = options.containerName || '';
    this.settings = options.settings || null;
    this.term = null;
    this.socket = null;
    this.recorder = null;
    this.fitAddon = null;
    this.webLinksAddon = null;
    this.state = 'disconnected'; // disconnected | connecting | connected | error | expired
    this.onStateChange = options.onStateChange || null;
    this.onClose = options.onClose || null;
    this.timeoutTimer = null;
    this.timeoutWarningTimer = null;
    this.maxSessionMinutes = options.maxSessionMinutes || 30;
    this.warningBeforeMinutes = options.warningBeforeMinutes || 5;
    this._customKeyEventHandler = null;

    this._initialize();
  }

  /**
   * Initialize the terminal and connect.
   * @private
   */
  _initialize() {
    // Get xterm options from settings or defaults
    const xtermOptions = this.settings 
      ? this.settings.getXtermOptions() 
      : {
          fontSize: 14,
          cursorStyle: 'block',
          cursorBlink: true,
          scrollback: 5000,
          theme: { background: '#0d1117', foreground: '#c9d1d9' }
        };

    // Create terminal
    this.term = new Terminal(xtermOptions);

    // Load addons
    this.fitAddon = new FitAddon.FitAddon();
    this.webLinksAddon = new WebLinksAddon.WebLinksAddon();
    this.term.loadAddon(this.fitAddon);
    this.term.loadAddon(this.webLinksAddon);

    // Open terminal
    this.term.open(this.container);
    this.fitAddon.fit();

    // Welcome message
    this.term.writeln('Welcome to KubeDash Terminal!');
    this.term.writeln('Connecting to ' + this.podName + '...');
    this.term.writeln('');

    // Create session recorder
    this.recorder = new SessionRecorder({
      onSync: (sessionId, events) => this._syncEvents(sessionId, events),
      onFinalize: (sessionId, metadata) => this._finalizeSession(sessionId, metadata)
    });

    // Setup input handler
    this._setupInputHandler();

    // Setup resize handler
    this._setupResizeHandler();
  }

  /**
   * Setup keyboard input handler to send to server.
   * @private
   */
  _setupInputHandler() {
    // Key events
    this.term.onKey(e => {
      if (this.socket && this.socket.connected) {
        this.socket.emit('exec-input', { input: e.key });
        this.recorder.recordInput(e.key);
      }
    });

    // Paste events
    if (this.term.element) {
      this.term.element.addEventListener('paste', (e) => {
        const text = (e.clipboardData || window.clipboardData).getData('text/plain');
        if (text && this.socket && this.socket.connected) {
          this.socket.emit('exec-input', { input: text });
          this.recorder.recordInput(text);
        }
        e.preventDefault();
      });
    }
  }

  /**
   * Setup window resize handler for terminal fitting.
   * @private
   */
  _setupResizeHandler() {
    window.addEventListener('resize', () => {
      if (this.fitAddon && this.state === 'connected') {
        this.fitAddon.fit();
      }
    });
  }

  /**
   * Connect to the pod's exec stream.
   * @param {string} podName - Pod name
   * @param {string} containerName - Container name
   * @param {string} namespace - Kubernetes namespace
   */
  connect(podName, containerName, namespace) {
    this.podName = podName || this.podName;
    this.containerName = containerName || this.containerName;
    this.namespace = namespace || this.namespace;

    if (!this.podName || !this.containerName) {
      this.term.writeln('Error: Missing pod or container name.');
      return;
    }

    // Reset terminal
    this.term.reset();
    this.term.writeln('Connecting to ' + this.podName + ' (' + this.containerName + ')...');
    this.term.writeln('');

    // Connect socket
    this.socket = io('/exec');
    this.state = 'connecting';
    this._notifyStateChange();

    // Setup socket listeners
    this._setupSocketListeners();

    // Start timeout timer
    this._startTimeoutTimer();
  }

  /**
   * Setup Socket.IO event listeners.
   * @private
   */
  _setupSocketListeners() {
    this.socket.on('connect', () => {
      this.state = 'connected';
      this._notifyStateChange();
      this.term.writeln('Connected. Starting shell...');
      this.term.writeln('');

      // Send exec request using 'message' event (matches backend handler)
      this.socket.emit('message', this.podName, this.containerName);

      // Start session recording
      this.recorder.start('session-' + Date.now());
    });

    this.socket.on('response', (msg) => {
      this.term.write(msg.output || '');
      this.recorder.recordOutput(msg.output || '');
    });

    this.socket.on('closed', (msg) => {
      this.state = 'disconnected';
      this._notifyStateChange();
      this.term.writeln('');
      this.term.writeln('Session closed: ' + (msg && msg.message ? msg.message : 'Stream ended.'));
      this.recorder.finalize('normal');
      if (this.onClose) {
        this.onClose(this);
      }
    });

    this.socket.on('disconnect', () => {
      this.state = 'error';
      this._notifyStateChange();
      this.term.writeln('');
      this.term.writeln('Connection lost.');
    });

    this.socket.on('connect_error', (err) => {
      console.error('Socket connection error:', err);
      this.state = 'error';
      this._notifyStateChange();
    });
  }

  /**
   * Disconnect from the exec stream.
   */
  disconnect() {
    if (this.socket) {
      this.socket.emit('stop');
      this.socket.disconnect();
      this.socket = null;
    }

    this.state = 'disconnected';
    this._notifyStateChange();
    this._stopTimeoutTimer();
    this.recorder.finalize('user-disconnect');
  }

  /**
   * Clear the terminal screen.
   */
  clear() {
    if (this.term) {
      this.term.clear();
    }
  }

  /**
   * Fit terminal to container size.
   */
  fit() {
    if (this.fitAddon) {
      this.fitAddon.fit();
    }
  }

  /**
   * Start timeout timer for session expiration.
   * @private
   */
  _startTimeoutTimer() {
    this._stopTimeoutTimer();
    const maxMs = this.maxSessionMinutes * 60 * 1000;
    const warningMs = (this.maxSessionMinutes - this.warningBeforeMinutes) * 60 * 1000;

    // Warning timer
    this.timeoutWarningTimer = setTimeout(() => {
      this._showTimeoutWarning();
    }, warningMs);

    // Expiration timer
    this.timeoutTimer = setTimeout(() => {
      this._handleExpiration();
    }, maxMs);
  }

  /**
   * Stop timeout timers.
   * @private
   */
  _stopTimeoutTimer() {
    if (this.timeoutTimer) {
      clearTimeout(this.timeoutTimer);
      this.timeoutTimer = null;
    }
    if (this.timeoutWarningTimer) {
      clearTimeout(this.timeoutWarningTimer);
      this.timeoutWarningTimer = null;
    }
  }

  /**
   * Show timeout warning banner.
   * @private
   */
  _showTimeoutWarning() {
    const warningEl = document.getElementById('timeout-warning');
    if (warningEl) {
      warningEl.style.display = 'block';
      // Update countdown (simplified)
      const countdownEl = document.getElementById('timeout-countdown');
      if (countdownEl) {
        countdownEl.textContent = this.warningBeforeMinutes + ':00';
      }
    }
  }

  /**
   * Handle session expiration.
   * @private
   */
  _handleExpiration() {
    this.state = 'expired';
    this._notifyStateChange();
    this.term.writeln('');
    this.term.writeln('Session expired due to inactivity timeout.');
    this.term.writeln('Click Reconnect to start a new session.');
    this.recorder.finalize('timeout');
    this._stopTimeoutTimer();
  }

  /**
   * Sync events to server (placeholder - actual implementation uses API endpoint).
   * @param {string} sessionId - Session ID
   * @param {Array} events - Events to sync
   * @private
   */
  async _syncEvents(sessionId, events) {
    // TODO: Implement POST /api/v1/exec/sessions/<id>/events
    // For now, just log
    console.log('Syncing ' + events.length + ' events for session ' + sessionId);
  }

  /**
   * Finalize session on server (placeholder).
   * @param {string} sessionId - Session ID
   * @param {object} metadata - Session metadata
   * @private
   */
  async _finalizeSession(sessionId, metadata) {
    // TODO: Implement PUT /api/v1/exec/sessions/<id>/metadata
    console.log('Finalizing session ' + sessionId + ':', metadata);
  }

  /**
   * Notify state change callback.
   * @private
   */
  _notifyStateChange() {
    if (this.onStateChange) {
      this.onStateChange(this.state);
    }
  }

  /**
   * Get terminal size (cols, rows).
   * @returns {object}
   */
  getSize() {
    return this.term ? { cols: this.term.cols, rows: this.term.rows } : { cols: 0, rows: 0 };
  }

  /**
   * Destroy the terminal and clean up.
   */
  destroy() {
    this.disconnect();
    if (this.term) {
      this.term.dispose();
      this.term = null;
    }
    this._stopTimeoutTimer();
  }
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { TerminalTab };
}
