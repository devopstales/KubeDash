/**
 * MultiPodAggregator - Coordinates multiple LogViewer instances for a workload,
 * merges output into a single chronological view with pod name prefix and color coding.
 */
class MultiPodAggregator {
  constructor(options = {}) {
    this.container = options.container;
    this.namespace = options.namespace || 'default';
    this.workloadKind = options.workloadKind;
    this.workloadName = options.workloadName;
    this.maxLines = options.maxLines || 10000;
    
    // State
    this.viewers = {};  // podName -> LogViewer instance (conceptual, we manage sockets directly)
    this.mergedBuffer = new LogBuffer(this.maxLines);
    this.renderer = new LogRenderer(this.container, options.rendererOptions);
    this.filter = new LogFilter();
    this.search = null;
    this.autoScroll = true;
    this.showTimestamps = true;
    this.podColors = {};
    this.podMeta = {};  // podName -> { namespace, containers, status }
    this.autoDiscoveryEnabled = options.autoDiscovery !== false;
    this.autoDiscoveryInterval = options.autoDiscoveryInterval || 30000; // 30s
    this.autoDiscoveryTimer = null;
    this.socket = io('/log');
    this.onStateChange = options.onStateChange || null;
    this.onBufferUpdate = options.onBufferUpdate || null;
    this.connectionStates = {};  // podName -> connection state
    
    this._setupSocketListeners();
  }

  /**
   * Set up Socket.IO event listeners for multi-pod streaming.
   * @private
   */
  _setupSocketListeners() {
    // Multi-pod uses the same /log namespace but manages multiple streams
    this.socket.on('connect', () => {
      this._notifyStateChange();
    });

    this.socket.on('response', (msg) => {
      // Response includes pod metadata in msg.pod and msg.container
      this._onLogLine(msg.data, msg.pod, msg.container);
    });

    this.socket.on('disconnect', () => {
      this._notifyStateChange();
    });
  }

  /**
   * Initialize the aggregator by fetching pods and starting streams.
   * @param {string} workloadKind - Kubernetes workload kind
   * @param {string} workloadName - Workload name
   * @param {string} namespace - Namespace
   */
  async initialize(workloadKind, workloadName, namespace) {
    this.workloadKind = workloadKind;
    this.workloadName = workloadName;
    this.namespace = namespace;

    try {
      // Fetch pods for this workload
      const pods = await this._fetchWorkloadPods();
      
      // Start streaming for each pod
      for (const pod of pods) {
        await this.addPod(pod);
      }

      // Start auto-discovery if enabled
      if (this.autoDiscoveryEnabled) {
        this._startAutoDiscovery();
      }
    } catch (error) {
      console.error('Failed to initialize multi-pod aggregator:', error);
      if (this.onStateChange) {
        this.onStateChange('error');
      }
    }
  }

  /**
   * Fetch pods for the current workload.
   * @returns {Array} Array of pod objects
   * @private
   */
  async _fetchWorkloadPods() {
    const url = `/api/v1/workloads/${this.workloadKind}/${this.workloadName}/pods?namespace=${encodeURIComponent(this.namespace)}`;
    const response = await fetch(url, {
      headers: { 'Accept': 'application/json' }
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch workload pods: ${response.status}`);
    }

    const payload = await response.json();
    return payload.data || [];
  }

  /**
   * Add a pod to the aggregator and start streaming its logs.
   * @param {object} podMeta - Pod metadata from API
   */
  async addPod(podMeta) {
    const podName = podMeta.name;
    if (this.viewers[podName]) {
      return; // Already streaming
    }

    // Store pod metadata
    this.podMeta[podName] = {
      namespace: podMeta.namespace || this.namespace,
      containers: podMeta.containers || [],
      initContainers: podMeta.init_containers || [],
      status: podMeta.status
    };

    // Assign a color to this pod
    this._getPodColor(podName);

    // Start log stream for first container
    const container = (podMeta.containers && podMeta.containers[0]) || 
                      (podMeta.init_containers && podMeta.init_containers[0]);
    
    if (container) {
      this._startPodStream(podName, container, podMeta.namespace || this.namespace);
    }
  }

  /**
   * Start streaming logs for a specific pod.
   * @param {string} podName - Pod name
   * @param {string} container - Container name
   * @param {string} namespace - Namespace
   * @private
   */
  _startPodStream(podName, container, namespace) {
    // Use join_pod_logs event with pod metadata
    this.socket.emit('join_pod_logs', {
      podName: podName,
      container: container,
      namespace: namespace,
      tail_lines: 100
    });

    this.viewers[podName] = {
      podName,
      container,
      namespace,
      state: 'connecting'
    };

    this.connectionStates[podName] = 'connecting';
  }

  /**
   * Handle a new log line from any pod.
   * @param {string} data - Raw log line text
   * @param {string} podName - Pod name
   * @param {string} container - Container name
   * @private
   */
  _onLogLine(data, podName, container) {
    const entry = this.mergedBuffer.add(data, {
      pod: podName,
      container: container
    });

    // Ensure pod has a color
    this._getPodColor(podName);

    // Apply filter
    if (this.filter.matches(entry)) {
      entry.visible = true;
      this.renderer.append(entry);
    } else {
      entry.visible = false;
    }

    if (this.onBufferUpdate) {
      this.onBufferUpdate(this.mergedBuffer);
    }
  }

  /**
   * Get a consistent color for a pod name.
   * @param {string} podName
   * @returns {string} CSS color string
   * @private
   */
  _getPodColor(podName) {
    if (!this.podColors[podName]) {
      const colors = [
        '#42a5f5', '#66bb6a', '#ffa726', '#ef5350', '#ab47bc',
        '#26c6da', '#ec407a', '#9ccc65', '#ffca28', '#7e57c2'
      ];
      const idx = Object.keys(this.podColors).length % colors.length;
      this.podColors[podName] = colors[idx];
    }
    return this.podColors[podName];
  }

  /**
   * Start auto-discovery polling for new pods.
   * @private
   */
  _startAutoDiscovery() {
    this._stopAutoDiscovery();
    this.autoDiscoveryTimer = setInterval(async () => {
      try {
        const pods = await this._fetchWorkloadPods();
        const knownPods = new Set(Object.keys(this.viewers));
        
        // Find new pods
        for (const pod of pods) {
          if (!knownPods.has(pod.name)) {
            console.log(`Discovered new pod: ${pod.name}`);
            await this.addPod(pod);
          }
        }
      } catch (error) {
        console.error('Auto-discovery poll failed:', error);
      }
    }, this.autoDiscoveryInterval);
  }

  /**
   * Stop auto-discovery polling.
   */
  _stopAutoDiscovery() {
    if (this.autoDiscoveryTimer) {
      clearInterval(this.autoDiscoveryTimer);
      this.autoDiscoveryTimer = null;
    }
  }

  /**
   * Toggle auto-discovery on/off.
   * @param {boolean} enabled
   */
  setAutoDiscovery(enabled) {
    this.autoDiscoveryEnabled = enabled;
    if (enabled) {
      this._startAutoDiscovery();
    } else {
      this._stopAutoDiscovery();
    }
  }

  /**
   * Apply the current filter and re-render.
   */
  applyFilter() {
    const filtered = this.mergedBuffer.getFilteredLines(this.filter);
    for (const entry of this.mergedBuffer.lines) {
      entry.visible = this.filter.matches(entry);
    }
    this.renderer.renderAll(filtered);

    if (this.search && this.search.active) {
      this.search._applyHighlights();
    }

    if (this.onBufferUpdate) {
      this.onBufferUpdate(this.mergedBuffer);
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
   * Get buffer utilization info.
   * @returns {object}
   */
  getBufferUtilization() {
    return this.mergedBuffer.getUtilization();
  }

  /**
   * Get per-pod log level statistics.
   * @returns {object} Map of podName -> { DEBUG: n, INFO: n, ... }
   */
  getPodLevelStats() {
    const stats = {};
    for (const entry of this.mergedBuffer.lines) {
      if (!stats[entry.pod]) {
        stats[entry.pod] = { DEBUG: 0, INFO: 0, WARN: 0, ERROR: 0, FATAL: 0, UNKNOWN: 0 };
      }
      if (stats[entry.pod][entry.level] !== undefined) {
        stats[entry.pod][entry.level]++;
      }
    }
    return stats;
  }

  /**
   * Get list of all pods being streamed.
   * @returns {Array} Array of pod metadata objects
   */
  getStreamingPods() {
    return Object.entries(this.viewers).map(([name, viewer]) => ({
      name,
      ...this.podMeta[name],
      color: this.podColors[name],
      state: this.connectionStates[name] || 'unknown'
    }));
  }

  /**
   * Clear all buffers and rendered content.
   */
  clear() {
    this.mergedBuffer.clear();
    this.renderer.clear();
    this.viewers = {};
    this.podMeta = {};
    this.connectionStates = {};
    this._stopAutoDiscovery();
    
    if (this.onBufferUpdate) {
      this.onBufferUpdate(this.mergedBuffer);
    }
  }

  /**
   * Notify state change callback.
   * @private
   */
  _notifyStateChange() {
    if (this.onStateChange) {
      const states = Object.values(this.connectionStates);
      const hasError = states.includes('error');
      const allConnected = states.length > 0 && states.every(s => s === 'streaming' || s === 'connecting');
      
      if (hasError) {
        this.onStateChange('error');
      } else if (allConnected) {
        this.onStateChange('streaming');
      } else {
        this.onStateChange('connecting');
      }
    }
  }
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { MultiPodAggregator };
}
