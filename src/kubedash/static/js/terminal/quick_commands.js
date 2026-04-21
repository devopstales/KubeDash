/**
 * QuickCommandManager - Manages preset and custom quick commands for terminal.
 * 
 * Features:
 * - Default preset library categorized by Filesystem, System Info, Logs, Debugging, Network
 * - User can add, edit, remove custom commands
 * - Commands saved to localStorage with optional server sync
 * - One-click execution (inserts command into terminal with newline)
 */
class QuickCommandManager {
  constructor(options = {}) {
    this.storageKey = 'kubedash-terminal-quick-commands';
    this.onExecute = options.onExecute || null; // Callback when command is executed
    this.presets = this._getDefaultPresets();
    this.customCommands = [];
    this._loadCustomCommands();
  }

  /**
   * Get all available commands (presets + custom).
   * @returns {Array} Array of command objects
   */
  getAllCommands() {
    return [
      ...this.presets.map(cmd => ({ ...cmd, isPreset: true })),
      ...this.customCommands.map(cmd => ({ ...cmd, isPreset: false }))
    ];
  }

  /**
   * Get commands by category.
   * @param {string} category - Category name
   * @returns {Array}
   */
  getByCategory(category) {
    return this.getAllCommands().filter(cmd => cmd.category === category);
  }

  /**
   * Get all unique categories.
   * @returns {Array<string>}
   */
  getCategories() {
    const categories = new Set();
    this.getAllCommands().forEach(cmd => categories.add(cmd.category));
    return Array.from(categories);
  }

  /**
   * Execute a command (send to terminal).
   * @param {string} command - Command text
   */
  execute(command) {
    if (this.onExecute && command) {
      this.onExecute(command);
    }
  }

  /**
   * Add a custom command.
   * @param {object} cmd - { name, command, category, description }
   * @returns {string} Command ID
   */
  addCustomCommand(cmd) {
    const newCmd = {
      id: 'custom-' + Date.now(),
      name: cmd.name || 'Untitled',
      command: cmd.command || '',
      category: cmd.category || 'Custom',
      description: cmd.description || ''
    };
    this.customCommands.push(newCmd);
    this._saveCustomCommands();
    return newCmd.id;
  }

  /**
   * Update a custom command.
   * @param {string} id - Command ID
   * @param {object} updates - Updated fields
   */
  updateCustomCommand(id, updates) {
    const idx = this.customCommands.findIndex(c => c.id === id);
    if (idx !== -1) {
      this.customCommands[idx] = { ...this.customCommands[idx], ...updates };
      this._saveCustomCommands();
    }
  }

  /**
   * Delete a custom command.
   * @param {string} id - Command ID
   */
  deleteCustomCommand(id) {
    this.customCommands = this.customCommands.filter(c => c.id !== id);
    this._saveCustomCommands();
  }

  /**
   * Load custom commands from localStorage.
   * @private
   */
  _loadCustomCommands() {
    try {
      const stored = localStorage.getItem(this.storageKey);
      if (stored) {
        this.customCommands = JSON.parse(stored);
      }
    } catch (e) {
      console.warn('Failed to load custom commands:', e);
      this.customCommands = [];
    }
  }

  /**
   * Save custom commands to localStorage.
   * @private
   */
  _saveCustomCommands() {
    try {
      localStorage.setItem(this.storageKey, JSON.stringify(this.customCommands));
    } catch (e) {
      console.warn('Failed to save custom commands:', e);
    }
  }

  /**
   * Get default preset commands.
   * @private
   */
  _getDefaultPresets() {
    return [
      // Filesystem
      { id: 'preset-ls', name: 'List Files', command: 'ls -la\n', category: 'Filesystem', description: 'List files with details' },
      { id: 'preset-pwd', name: 'Working Directory', command: 'pwd\n', category: 'Filesystem', description: 'Show current directory' },
      { id: 'preset-df', name: 'Disk Usage', command: 'df -h\n', category: 'Filesystem', description: 'Show disk space' },
      { id: 'preset-find-large', name: 'Find Large Files', command: 'find . -type f -size +100M\n', category: 'Filesystem', description: 'Find files > 100MB' },

      // System Info
      { id: 'preset-uname', name: 'System Info', command: 'uname -a\n', category: 'System Info', description: 'Show system information' },
      { id: 'preset-top', name: 'Top Processes', command: 'top -b -n 1 | head -20\n', category: 'System Info', description: 'Show top processes' },
      { id: 'preset-free', name: 'Memory Info', command: 'free -h\n', category: 'System Info', description: 'Show memory usage' },
      { id: 'preset-uptime', name: 'Uptime', command: 'uptime\n', category: 'System Info', description: 'Show system uptime' },

      // Logs
      { id: 'preset-tail-log', name: 'Tail Log', command: 'tail -f /var/log/syslog\n', category: 'Logs', description: 'Tail syslog' },
      { id: 'preset-grep-error', name: 'Grep Errors', command: 'grep -i error /var/log/syslog | tail -50\n', category: 'Logs', description: 'Find recent errors' },
      { id: 'preset-dmesg', name: 'Kernel Messages', command: 'dmesg | tail -50\n', category: 'Logs', description: 'Show recent kernel messages' },

      // Debugging
      { id: 'preset-env', name: 'Environment Variables', command: 'env | sort\n', category: 'Debugging', description: 'Show environment variables' },
      { id: 'preset-ps', name: 'Process List', command: 'ps aux\n', category: 'Debugging', description: 'Show all processes' },
      { id: 'preset-netstat', name: 'Network Connections', command: 'netstat -tulpn 2>/dev/null || ss -tulpn\n', category: 'Debugging', description: 'Show listening ports' },

      // Network
      { id: 'preset-curl-localhost', name: 'Test Localhost', command: 'curl -s http://localhost:8080/healthz\n', category: 'Network', description: 'Test localhost service' },
      { id: 'preset-dns-lookup', name: 'DNS Lookup', command: 'nslookup kubernetes.default.svc.cluster.local\n', category: 'Network', description: 'Test DNS resolution' },
      { id: 'preset-ping', name: 'Ping Gateway', command: 'ping -c 4 10.0.0.1\n', category: 'Network', description: 'Test network connectivity' }
    ];
  }
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { QuickCommandManager };
}
