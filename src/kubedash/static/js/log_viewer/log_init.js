/**
 * LogInit - Initialization script that reads config from template data attributes,
 * instantiates LogViewer, and wires up toolbar controls.
 */
(function() {
  'use strict';

  let logViewer = null;
  let logSearch = null;
  let exportFormat = 'text';

  /**
   * Initialize the log viewer on DOMContentLoaded.
   */
  function init() {
    const card = document.querySelector('.log-viewer-card');
    if (!card) return;

    // Read config from data attributes
    const podName = card.dataset.podName || '';
    const namespace = card.dataset.namespace || '';
    const initialContainer = card.dataset.initialContainer || '';
    const featureEnabled = card.dataset.featureEnabled === 'true';

    if (!featureEnabled) {
      console.warn('Enhanced log viewer is disabled via feature flag.');
      return;
    }

    // Get DOM elements
    const container = document.getElementById('log-content');
    const statusEl = document.getElementById('connection-status');
    const bufferUsageEl = document.getElementById('buffer-usage');
    const lineCountEl = document.getElementById('line-count');
    const reconnectBtn = document.getElementById('reconnect-btn');
    const containerSelect = document.getElementById('container-select');
    const autoScrollToggle = document.getElementById('auto-scroll-toggle');
    const timestampToggle = document.getElementById('timestamp-toggle');
    const searchInput = document.getElementById('search-input');
    const searchMatchCount = document.getElementById('search-match-count');
    const searchPrev = document.getElementById('search-prev');
    const searchNext = document.getElementById('search-next');
    const searchClear = document.getElementById('search-clear');
    const exportBtn = document.getElementById('export-btn');
    const exportFormatDropdown = document.getElementById('export-format-dropdown');

    if (!container) return;

    // Load user preferences from localStorage
    const prefs = loadPreferences();

    // Create LogViewer instance
    logViewer = new LogViewer({
      container: container,
      podName: podName,
      namespace: namespace,
      maxLines: prefs.maxBufferLines,
      autoScroll: prefs.defaultAutoScroll,
      showTimestamps: prefs.defaultShowTimestamps,
      onStateChange: (state) => updateConnectionState(state, statusEl, reconnectBtn),
      onBufferUpdate: (buffer) => updateBufferDisplay(buffer, bufferUsageEl, lineCountEl)
    });

    // Create LogSearch instance
    logSearch = new LogSearch(logViewer.buffer, logViewer.renderer);
    logViewer.setSearch(logSearch);

    // Set initial toggle states
    if (autoScrollToggle) {
      autoScrollToggle.checked = prefs.defaultAutoScroll;
    }
    if (timestampToggle) {
      timestampToggle.checked = prefs.defaultShowTimestamps;
    }

    // Wire up toolbar controls
    wireToolbar(containerSelect, autoScrollToggle, timestampToggle,
                searchInput, searchMatchCount, searchPrev, searchNext, searchClear,
                exportBtn, exportFormatDropdown);

    // Load containers and start streaming
    loadContainers(podName, namespace, initialContainer, containerSelect);
  }

  /**
   * Load container list from API and populate dropdown.
   */
  async function loadContainers(podName, namespace, initialContainer, containerSelect) {
    try {
      const url = `/api/v1/workloads/pods/${encodeURIComponent(podName)}/containers?namespace=${encodeURIComponent(namespace)}`;
      const response = await fetch(url, {
        headers: { 'Accept': 'application/json' }
      });

      if (!response.ok) {
        throw new Error(`Container fetch failed: ${response.status}`);
      }

      const payload = await response.json();
      const containers = (payload.data && payload.data.containers) || [];
      const initContainers = (payload.data && payload.data.init_containers) || [];

      buildContainerOptions(containerSelect, containers, initContainers);

      const desired = initialContainer || (containers[0] || initContainers[0] || '');
      if (desired) {
        containerSelect.value = desired;
        logViewer.connect(podName, desired, namespace);
      }
    } catch (error) {
      containerSelect.innerHTML = '';
      const option = document.createElement('option');
      option.value = '';
      option.textContent = 'Failed to load containers';
      option.disabled = true;
      option.selected = true;
      containerSelect.appendChild(option);
      console.error('Failed to load containers:', error);
    }
  }

  /**
   * Build container select dropdown options.
   */
  function buildContainerOptions(select, containers, initContainers) {
    select.innerHTML = '';

    if ((!containers || containers.length === 0) && (!initContainers || initContainers.length === 0)) {
      const option = document.createElement('option');
      option.value = '';
      option.textContent = 'No containers found';
      option.disabled = true;
      option.selected = true;
      select.appendChild(option);
      return;
    }

    if (initContainers && initContainers.length > 0) {
      const initGroup = document.createElement('optgroup');
      initGroup.label = 'Init containers';
      initContainers.forEach(name => {
        const option = document.createElement('option');
        option.value = name;
        option.textContent = name;
        initGroup.appendChild(option);
      });
      select.appendChild(initGroup);
    }

    if (containers && containers.length > 0) {
      const mainGroup = document.createElement('optgroup');
      mainGroup.label = 'Containers';
      containers.forEach(name => {
        const option = document.createElement('option');
        option.value = name;
        option.textContent = name;
        mainGroup.appendChild(option);
      });
      select.appendChild(mainGroup);
    }
  }

  /**
   * Wire up all toolbar controls.
   */
  function wireToolbar(containerSelect, autoScrollToggle, timestampToggle,
                       searchInput, searchMatchCount, searchPrev, searchNext, searchClear,
                       exportBtn, exportFormatDropdown) {
    // Container select
    if (containerSelect) {
      containerSelect.addEventListener('change', (e) => {
        if (logViewer && e.target.value) {
          logViewer.clear();
          logViewer.connect(logViewer.podName, e.target.value, logViewer.namespace);
        }
      });
    }

    // Auto-scroll toggle
    if (autoScrollToggle) {
      autoScrollToggle.addEventListener('change', (e) => {
        if (logViewer) {
          logViewer.setAutoScroll(e.target.checked);
          savePreference('defaultAutoScroll', e.target.checked);
        }
      });
    }

    // Timestamp toggle
    if (timestampToggle) {
      timestampToggle.addEventListener('change', (e) => {
        if (logViewer) {
          logViewer.setTimestampVisibility(e.target.checked);
          savePreference('defaultShowTimestamps', e.target.checked);
        }
      });
    }

    // Level filter checkboxes
    const levelCheckboxes = document.querySelectorAll('.level-cb');
    levelCheckboxes.forEach(cb => {
      cb.addEventListener('change', () => {
        if (!logViewer) return;
        const activeLevels = [];
        levelCheckboxes.forEach(c => {
          if (c.checked) activeLevels.push(c.value);
        });
        logViewer.setLevels(activeLevels);
        updateFilterButtonLabel(activeLevels);
      });
    });

    // Search input with debounce
    let searchTimeout = null;
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
          const query = e.target.value.trim();
          if (query) {
            logSearch.search(query);
            searchMatchCount.textContent = `${logSearch.matches.length} matches`;
            searchClear.disabled = false;
            searchPrev.disabled = logSearch.matches.length === 0;
            searchNext.disabled = logSearch.matches.length === 0;
          } else {
            logSearch.clear();
            searchMatchCount.textContent = '';
            searchClear.disabled = true;
            searchPrev.disabled = true;
            searchNext.disabled = true;
          }
        }, 300);
      });

      searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          if (e.shiftKey) {
            logSearch.prevMatch();
          } else {
            logSearch.nextMatch();
          }
          searchMatchCount.textContent = logSearch.matches.length > 0
            ? `${logSearch.currentMatchIndex + 1}/${logSearch.matches.length}`
            : '0 matches';
        }
      });
    }

    // Search navigation
    if (searchPrev) {
      searchPrev.addEventListener('click', () => {
        logSearch.prevMatch();
        searchMatchCount.textContent = logSearch.matches.length > 0
          ? `${logSearch.currentMatchIndex + 1}/${logSearch.matches.length}`
          : '0 matches';
      });
    }

    if (searchNext) {
      searchNext.addEventListener('click', () => {
        logSearch.nextMatch();
        searchMatchCount.textContent = logSearch.matches.length > 0
          ? `${logSearch.currentMatchIndex + 1}/${logSearch.matches.length}`
          : '0 matches';
      });
    }

    if (searchClear) {
      searchClear.addEventListener('click', () => {
        logSearch.clear();
        searchInput.value = '';
        searchMatchCount.textContent = '';
        searchClear.disabled = true;
        searchPrev.disabled = true;
        searchNext.disabled = true;
      });
    }

    // Export button
    if (exportBtn) {
      exportBtn.addEventListener('click', () => {
        if (!logViewer) return;
        const entries = logViewer.buffer.getFilteredLines(logViewer.filter);
        const filename = generateExportFilename(logViewer.podName);

        if (exportFormat === 'json') {
          LogExporter.exportAsJson(entries, { filename });
        } else {
          LogExporter.exportAsText(entries, {
            filename,
            timestamps: true,
            tsFormat: 'iso'
          });
        }
      });
    }

    // Export format selection
    if (exportFormatDropdown) {
      const formatLinks = exportFormatDropdown.querySelectorAll('.export-format-link');
      formatLinks.forEach(link => {
        link.addEventListener('click', (e) => {
          e.preventDefault();
          exportFormat = e.target.dataset.format;
          exportFormatDropdown.textContent = exportFormat === 'json' ? 'JSON' : 'Text';
        });
      });
    }

    // Reconnect button
    const reconnectBtn = document.getElementById('reconnect-btn');
    if (reconnectBtn) {
      reconnectBtn.addEventListener('click', () => {
        if (logViewer) {
          logViewer.reconnect();
        }
      });
    }
  }

  /**
   * Update connection state UI.
   */
  function updateConnectionState(state, statusEl, reconnectBtn) {
    const stateLabels = {
      connecting: 'Connecting...',
      streaming: 'Streaming',
      disconnected: 'Disconnected',
      error: 'Connection Error',
      completed: 'Completed'
    };

    statusEl.className = `status-indicator status-${state}`;
    statusEl.textContent = stateLabels[state] || state;

    if (reconnectBtn) {
      reconnectBtn.style.display = (state === 'disconnected' || state === 'error') ? 'inline' : 'none';
    }
  }

  /**
   * Update buffer utilization display.
   */
  function updateBufferDisplay(buffer, bufferUsageEl, lineCountEl) {
    const util = buffer.getUtilization();

    if (bufferUsageEl) {
      const pct = Math.round(util.usage * 100);
      bufferUsageEl.textContent = `${util.current} / ${util.max} lines`;
      bufferUsageEl.className = 'buffer-usage';
      if (util.usage > 0.9) {
        bufferUsageEl.classList.add('critical');
      } else if (util.usage > 0.8) {
        bufferUsageEl.classList.add('warning');
      }
    }

    if (lineCountEl) {
      lineCountEl.textContent = `Total: ${util.totalReceived} | Evicted: ${util.evicted}`;
    }
  }

  /**
   * Update the filter button label based on active levels.
   */
  function updateFilterButtonLabel(activeLevels) {
    const btn = document.querySelector('#level-filter button');
    if (!btn) return;

    const allLevels = ['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL', 'UNKNOWN'];
    if (activeLevels.length === allLevels.length) {
      btn.textContent = 'All Levels';
    } else if (activeLevels.length === 0) {
      btn.textContent = 'None';
    } else {
      btn.textContent = `${activeLevels.length} level${activeLevels.length > 1 ? 's' : ''}`;
    }
  }

  /**
   * Generate a filename for log export.
   */
  function generateExportFilename(podName) {
    const now = new Date();
    const ts = now.toISOString().replace(/[:.]/g, '-').substring(0, 19);
    return `${podName || 'logs'}-${ts}.log`;
  }

  /**
   * Load user preferences from localStorage.
   */
  function loadPreferences() {
    try {
      const stored = localStorage.getItem('kubedash-log-viewer-prefs');
      if (stored) {
        return JSON.parse(stored);
      }
    } catch (e) {
      // Ignore storage errors
    }

    return {
      maxBufferLines: 10000,
      defaultAutoScroll: true,
      defaultShowTimestamps: true,
      favoriteLogLevels: ['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL', 'UNKNOWN']
    };
  }

  /**
   * Save a single preference to localStorage.
   */
  function savePreference(key, value) {
    try {
      const prefs = loadPreferences();
      prefs[key] = value;
      localStorage.setItem('kubedash-log-viewer-prefs', JSON.stringify(prefs));
    } catch (e) {
      // Ignore storage errors
    }
  }

  // Initialize on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
