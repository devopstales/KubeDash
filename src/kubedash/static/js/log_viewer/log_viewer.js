/**
 * LogViewer - Main controller connecting Socket.IO /log events to buffer, filter, and renderer.
 */
class LogViewer {
  constructor(options) {
    this.socket = io('/log');
    this.buffer = new LogBuffer(options.maxLines || 10000);
    this.renderer = new LogRenderer(options.container, {
      showTimestamps: options.showTimestamps !== false
    });
    this.filter = new LogFilter();
    this.search = null; // Will be set by setSearch()
    this.autoScroll = options.autoScroll !== false;
    this.showTimestamps = options.showTimestamps !== false;
    this.connectionState = 'disconnected';
    this.podName = options.podName || '';
    this.namespace = options.namespace || '';
    this.currentContainer = '';
    this.onStateChange = options.onStateChange || null;
    this.onBufferUpdate = options.onBufferUpdate || null;

    this._setupSocketListeners();
    this._setupAutoScroll();
  }

  /**
   * Set up Socket.IO event listeners.
   * @private
   */
  _setupSocketListeners() {
    this.socket.on('connect', () => {
      this.connectionState = 'connecting';
      this._notifyStateChange();
    });

    this.socket.on('response', (msg) => {
      if (this.connectionState !== 'streaming') {
        this.connectionState = 'streaming';
        this._notifyStateChange();
      }
      this._onLogLine(msg.data);
    });

    this.socket.on('disconnect', () => {
      this.connectionState = 'disconnected';
      this._notifyStateChange();
    });

    this.socket.on('connect_error', (err) => {
      console.error('Socket.IO connection error:', err);
      this.connectionState = 'error';
      this._notifyStateChange();
    });
  }

  /**
   * Set up auto-scroll behavior based on user scroll position.
   * @private
   */
  _setupAutoScroll() {
    const container = this.renderer.container;

    container.addEventListener('scroll', () => {
      const isAtBottom = container.scrollHeight - container.scrollTop - container.clientHeight < 50;
      this.renderer.setAutoScroll(isAtBottom && this.autoScroll);
    });
  }

  /**
   * Connect to a specific pod's log stream.
   * @param {string} podName - Pod name
   * @param {string} container - Container name
   * @param {string} namespace - Kubernetes namespace
   */
  connect(podName, container, namespace) {
    this.podName = podName || this.podName;
    this.currentContainer = container;
    this.namespace = namespace || this.namespace;

    // Send log request via Socket.IO message event
    this.socket.emit('message', this.podName, this.currentContainer);
    this.connectionState = 'connecting';
    this._notifyStateChange();
  }

  /**
   * Disconnect from the current log stream.
   */
  disconnect() {
    this.socket.disconnect();
    this.connectionState = 'disconnected';
    this._notifyStateChange();
  }

  /**
   * Reconnect to the current log stream.
   */
  reconnect() {
    if (this.podName && this.currentContainer) {
      this.socket.connect();
      this.connect(this.podName, this.currentContainer, this.namespace);
    }
  }

  /**
   * Handle a new log line from the stream.
   * @param {string} data - Raw log line text
   * @private
   */
  _onLogLine(data) {
    const entry = this.buffer.add(data, {
      pod: this.podName,
      container: this.currentContainer
    });

    if (this.filter.matches(entry)) {
      entry.visible = true;
      this.renderer.append(entry);
    } else {
      entry.visible = false;
    }

    if (this.onBufferUpdate) {
      this.onBufferUpdate(this.buffer);
    }
  }

  /**
   * Apply the current filter and re-render.
   */
  applyFilter() {
    const filtered = this.buffer.getFilteredLines(this.filter);
    for (const entry of this.buffer.lines) {
      entry.visible = this.filter.matches(entry);
    }
    this.renderer.renderAll(filtered);

    if (this.search && this.search.active) {
      this.search._applyHighlights();
    }

    if (this.onBufferUpdate) {
      this.onBufferUpdate(this.buffer);
    }
  }

  /**
   * Set the log level filter.
   * @param {Array<string>} levels - Array of levels to show
   */
  setLevels(levels) {
    this.filter.setLevels(levels);
    this.applyFilter();
  }

  /**
   * Set auto-scroll toggle.
   * @param {boolean} enabled
   */
  setAutoScroll(enabled) {
    this.autoScroll = enabled;
    this.renderer.setAutoScroll(enabled);
  }

  /**
   * Set timestamp visibility.
   * @param {boolean} show
   */
  setTimestampVisibility(show) {
    this.showTimestamps = show;
    this.renderer.setTimestampVisibility(show);
  }

  /**
   * Set the search instance.
   * @param {LogSearch} searchInstance
   */
  setSearch(searchInstance) {
    this.search = searchInstance;
  }

  /**
   * Clear the buffer and rendered content.
   */
  clear() {
    this.buffer.clear();
    this.renderer.clear();
    if (this.onBufferUpdate) {
      this.onBufferUpdate(this.buffer);
    }
  }

  /**
   * Get current connection state.
   * @returns {string}
   */
  getState() {
    return this.connectionState;
  }

  /**
   * Notify state change callback.
   * @private
   */
  _notifyStateChange() {
    if (this.onStateChange) {
      this.onStateChange(this.connectionState);
    }
  }

  /**
   * Get buffer utilization info.
   * @returns {object}
   */
  getBufferUtilization() {
    return this.buffer.getUtilization();
  }
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { LogViewer };
}
