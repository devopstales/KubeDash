/**
 * LogFilter - Level filtering and custom regex filtering for log entries.
 */
class LogFilter {
  constructor() {
    this.activeLevels = new Set(['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL', 'UNKNOWN']);
    this.textPattern = null;
    this.caseSensitive = false;
  }

  /**
   * Set which log levels are visible.
   * @param {Array<string>} levels - Array of level strings to show
   */
  setLevels(levels) {
    this.activeLevels = new Set(levels);
  }

  /**
   * Set a text search pattern for filtering.
   * @param {string|null} pattern - Regex pattern string or null to clear
   * @param {boolean} caseSensitive - Whether to match case
   */
  setSearchPattern(pattern, caseSensitive = false) {
    if (!pattern) {
      this.textPattern = null;
      return;
    }
    try {
      const flags = caseSensitive ? 'g' : 'gi';
      this.textPattern = new RegExp(pattern, flags);
      this.caseSensitive = caseSensitive;
    } catch (e) {
      // Invalid regex, ignore
      this.textPattern = null;
    }
  }

  /**
   * Check if an entry matches the current filter.
   * @param {object} entry - Log entry with level and line properties
   * @returns {boolean} Whether the entry should be visible
   */
  matches(entry) {
    if (!this.activeLevels.has(entry.level)) {
      return false;
    }
    if (this.textPattern) {
      // Reset lastIndex for global regexes
      this.textPattern.lastIndex = 0;
      if (!this.textPattern.test(entry.line)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Get the currently active levels.
   * @returns {Set<string>}
   */
  getActiveLevels() {
    return new Set(this.activeLevels);
  }

  /**
   * Check if a specific level is currently active.
   * @param {string} level - Level to check
   * @returns {boolean}
   */
  isLevelActive(level) {
    return this.activeLevels.has(level);
  }

  /**
   * Toggle a specific level on or off.
   * @param {string} level - Level to toggle
   */
  toggleLevel(level) {
    if (this.activeLevels.has(level)) {
      this.activeLevels.delete(level);
    } else {
      this.activeLevels.add(level);
    }
  }

  /**
   * Clear all filters (show everything).
   */
  clear() {
    this.activeLevels = new Set(['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL', 'UNKNOWN']);
    this.textPattern = null;
  }

  /**
   * Check if any filter is active (not showing all).
   * @returns {boolean}
   */
  hasActiveFilter() {
    const allLevels = ['DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL', 'UNKNOWN'];
    if (this.activeLevels.size !== allLevels.length) {
      return true;
    }
    return this.textPattern !== null;
  }
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { LogFilter };
}
