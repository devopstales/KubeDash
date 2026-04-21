/**
 * TerminalManager - Manages multiple TerminalTab instances (open, close, reorder, activate, limit enforcement).
 */
class TerminalManager {
  constructor(options = {}) {
    this.tabs = [];
    this.activeTabIndex = -1;
    this.maxTabs = options.maxTabs || 8;
    this.tabBarContainer = options.tabBarContainer;
    this.terminalContainer = options.terminalContainer;
    this.settings = options.settings || null;
    this.onTabChange = options.onTabChange || null;
    this.onAllTabsClosed = options.onAllTabsClosed || null;

    this._setupTabBarEvents();
  }

  /**
   * Open a new terminal tab.
   * @param {object} options - { podName, namespace, containerName }
   * @returns {TerminalTab|null}
   */
  openTab(options) {
    if (this.tabs.length >= this.maxTabs) {
      alert(`Maximum of ${this.maxTabs} tabs reached. Close a tab to open a new one.`);
      return null;
    }

    // Create tab element
    const tabEl = this._createTabElement(options.podName);
    this.tabBarContainer.appendChild(tabEl);

    // Create terminal container
    const termContainer = document.createElement('div');
    termContainer.className = 'terminal-tab-content';
    termContainer.id = `terminal-tab-${Date.now()}`;
    termContainer.style.display = 'none';
    this.terminalContainer.appendChild(termContainer);

    // Create TerminalTab instance
    const tab = new TerminalTab(termContainer, {
      ...options,
      settings: this.settings,
      onStateChange: (state) => this._updateTabStatus(tabEl, state),
      onClose: () => this.closeTab(this.tabs.findIndex(t => t === tab))
    });

    this.tabs.push({
      element: tabEl,
      terminal: tab,
      container: termContainer,
      podName: options.podName,
      namespace: options.namespace,
      containerName: options.containerName
    });

    // Activate the new tab
    this.activateTab(this.tabs.length - 1);

    // Connect to pod
    tab.connect(options.podName, options.containerName, options.namespace);

    return tab;
  }

  /**
   * Close a tab by index.
   * @param {number} index - Tab index
   */
  closeTab(index) {
    if (index < 0 || index >= this.tabs.length) return;

    const tab = this.tabs[index];

    // Confirm if session is active
    if (tab.terminal && tab.terminal.state === 'connected') {
      if (!confirm(`Close terminal for ${tab.podName}? Active session will be terminated.`)) {
        return;
      }
    }

    // Destroy terminal
    if (tab.terminal) {
      tab.terminal.destroy();
    }

    // Remove DOM elements
    tab.element.remove();
    tab.container.remove();

    // Remove from array
    this.tabs.splice(index, 1);

    // Adjust active tab index
    if (this.tabs.length === 0) {
      this.activeTabIndex = -1;
      if (this.onAllTabsClosed) {
        this.onAllTabsClosed();
      }
    } else if (index <= this.activeTabIndex) {
      this.activeTabIndex = Math.max(0, this.activeTabIndex - 1);
      this.activateTab(this.activeTabIndex);
    }
  }

  /**
   * Activate a tab by index.
   * @param {number} index - Tab index
   */
  activateTab(index) {
    if (index < 0 || index >= this.tabs.length) return;

    // Deactivate current tab
    if (this.activeTabIndex >= 0 && this.activeTabIndex < this.tabs.length) {
      this.tabs[this.activeTabIndex].element.classList.remove('active');
      this.tabs[this.activeTabIndex].container.style.display = 'none';
    }

    // Activate new tab
    this.activeTabIndex = index;
    this.tabs[index].element.classList.add('active');
    this.tabs[index].container.style.display = 'block';

    // Fit terminal
    if (this.tabs[index].terminal) {
      this.tabs[index].terminal.fit();
    }

    if (this.onTabChange) {
      this.onTabChange(index, this.tabs[index]);
    }
  }

  /**
   * Create a tab DOM element.
   * @param {string} podName - Pod name for display
   * @returns {HTMLElement}
   * @private
   */
  _createTabElement(podName) {
    const tab = document.createElement('div');
    tab.className = 'terminal-tab';
    tab.innerHTML = `
      <span class="tab-status"></span>
      <span class="tab-name" title="${podName}">${podName}</span>
      <button class="tab-close" title="Close tab">&times;</button>
    `;

    // Tab click - activate
    tab.addEventListener('click', (e) => {
      if (!e.target.classList.contains('tab-close')) {
        const index = this.tabs.findIndex(t => t.element === tab);
        if (index !== -1) {
          this.activateTab(index);
        }
      }
    });

    // Close button click
    tab.querySelector('.tab-close').addEventListener('click', (e) => {
      e.stopPropagation();
      const index = this.tabs.findIndex(t => t.element === tab);
      if (index !== -1) {
        this.closeTab(index);
      }
    });

    return tab;
  }

  /**
   * Update tab status indicator.
   * @param {HTMLElement} tabEl - Tab element
   * @param {string} state - Connection state
   * @private
   */
  _updateTabStatus(tabEl, state) {
    const statusEl = tabEl.querySelector('.tab-status');
    if (!statusEl) return;

    const stateClasses = {
      connecting: 'status-connecting',
      connected: 'status-connected',
      disconnected: 'status-disconnected',
      error: 'status-error',
      expired: 'status-expired'
    };

    statusEl.className = `tab-status ${stateClasses[state] || ''}`;
  }

  /**
   * Setup tab bar events (drag and drop reorder, etc.).
   * @private
   */
  _setupTabBarEvents() {
    // Future: Implement drag and drop reordering
  }

  /**
   * Get the active tab.
   * @returns {object|null}
   */
  getActiveTab() {
    if (this.activeTabIndex >= 0 && this.activeTabIndex < this.tabs.length) {
      return this.tabs[this.activeTabIndex];
    }
    return null;
  }

  /**
   * Get all tabs.
   * @returns {Array}
   */
  getTabs() {
    return [...this.tabs];
  }

  /**
   * Get tab count.
   * @returns {number}
   */
  getTabCount() {
    return this.tabs.length;
  }

  /**
   * Close all tabs.
   */
  closeAll() {
    for (let i = this.tabs.length - 1; i >= 0; i--) {
      this.closeTab(i);
    }
  }
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { TerminalManager };
}
