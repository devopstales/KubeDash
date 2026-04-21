/**
 * TerminalInit - Initialization script that reads config from template data attributes,
 * instantiates TerminalTab, and wires up UI controls.
 */
(function() {
  'use strict';

  let terminalTab = null;
  let settings = null;

  /**
   * Initialize the terminal on DOMContentLoaded.
   */
  function init() {
    const wrapper = document.querySelector('.terminal-wrapper');
    if (!wrapper) return;

    // Read config from data attributes
    const podName = wrapper.dataset.podName || '';
    const namespace = wrapper.dataset.namespace || '';
    const initialContainer = wrapper.dataset.initialContainer || '';
    const featureEnabled = wrapper.dataset.featureEnabled === 'true';

    if (!featureEnabled) {
      console.warn('Interactive terminal is disabled via feature flag.');
      return;
    }

    // Load settings
    settings = new TerminalSettings();

    // Get terminal container
    const terminalContainer = document.getElementById('terminal');
    if (!terminalContainer) return;

    // Create TerminalTab
    terminalTab = new TerminalTab(terminalContainer, {
      podName: podName,
      namespace: namespace,
      containerName: initialContainer,
      settings: settings,
      maxSessionMinutes: 30,
      warningBeforeMinutes: 5,
      onStateChange: (state) => updateConnectionState(state),
      onClose: (tab) => handleTabClose(tab)
    });

    // Wire up UI controls
    wireControls();

    // Load containers and start session
    loadContainers(podName, namespace, initialContainer);

    // Initial fit after a short delay (allows DOM to settle)
    setTimeout(() => {
      if (terminalTab) {
        terminalTab.fit();
      }
    }, 200);
  }

  /**
   * Load container list from API and populate dropdown.
   */
  async function loadContainers(podName, namespace, initialContainer) {
    const containerSelect = document.getElementById('container-select');
    if (!containerSelect) return;

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
        terminalTab.connect(podName, desired, namespace);
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
   * Wire up all UI controls.
   */
  function wireControls() {
    const containerSelect = document.getElementById('container-select');
    const disconnectBtn = document.getElementById('disconnect-btn');
    const clearBtn = document.getElementById('clear-btn');
    const fullscreenBtn = document.getElementById('fullscreen-btn');

    // Container select
    if (containerSelect) {
      containerSelect.addEventListener('change', (e) => {
        if (terminalTab && e.target.value) {
          terminalTab.disconnect();
          terminalTab.connect(terminalTab.podName, e.target.value, terminalTab.namespace);
        }
      });
    }

    // Disconnect button
    if (disconnectBtn) {
      disconnectBtn.addEventListener('click', () => {
        if (terminalTab) {
          terminalTab.disconnect();
        }
      });
    }

    // Clear button
    if (clearBtn) {
      clearBtn.addEventListener('click', () => {
        if (terminalTab) {
          terminalTab.clear();
        }
      });
    }

    // Fullscreen button
    if (fullscreenBtn) {
      fullscreenBtn.addEventListener('click', () => {
        const wrapper = document.querySelector('.terminal-wrapper');
        if (wrapper) {
          if (document.fullscreenElement) {
            document.exitFullscreen();
          } else {
            wrapper.requestFullscreen().catch(err => {
              console.error('Fullscreen error:', err);
            });
          }
        }
      });
    }

    // Update terminal size display on resize
    window.addEventListener('resize', () => {
      if (terminalTab) {
        const size = terminalTab.getSize();
        const sizeEl = document.getElementById('terminal-size');
        if (sizeEl) {
          sizeEl.textContent = `${size.cols}x${size.rows}`;
        }
      }
    });
  }

  /**
   * Update connection state UI.
   */
  function updateConnectionState(state) {
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.querySelector('.status-text');
    
    if (!statusDot || !statusText) return;

    const stateConfig = {
      connecting: { class: 'status-connecting', text: 'Connecting...' },
      connected: { class: 'status-connected', text: 'Connected' },
      disconnected: { class: 'status-disconnected', text: 'Disconnected' },
      error: { class: 'status-error', text: 'Connection Error' },
      expired: { class: 'status-disconnected', text: 'Session Expired' }
    };

    const config = stateConfig[state] || stateConfig.disconnected;
    statusDot.className = `status-dot ${config.class}`;
    statusText.textContent = config.text;

    // Update container info
    if (terminalTab && terminalTab.containerName) {
      const containerInfoEl = document.getElementById('container-info');
      if (containerInfoEl) {
        containerInfoEl.textContent = `(${terminalTab.containerName})`;
      }
    }
  }

  /**
   * Handle terminal tab close.
   */
  function handleTabClose(tab) {
    console.log('Terminal tab closed:', tab.podName);
    // For single-tab mode, just update state
    updateConnectionState('disconnected');
  }

  // Initialize on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
