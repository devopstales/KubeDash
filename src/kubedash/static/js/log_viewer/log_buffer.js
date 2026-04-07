/**
 * LogBuffer - Circular buffer for log lines with configurable max size and eviction tracking.
 */
class LogBuffer {
  constructor(maxLines = 10000) {
    this.lines = [];
    this.maxLines = maxLines;
    this.totalReceived = 0;
    this.evicted = 0;
  }

  /**
   * Add a log line to the buffer.
   * @param {string|object} data - Raw log text or object with text/line property
   * @param {object} meta - Optional metadata (pod, container, etc.)
   * @returns {object} The created log entry
   */
  add(data, meta = {}) {
    const text = typeof data === 'string' ? data : (data.text || data.line || '');
    const entry = {
      index: this.totalReceived,
      timestamp: Date.now(),
      line: text,
      level: LogLevelDetector.detect(text),
      pod: meta.pod || null,
      container: meta.container || null,
      visible: true,
      domElement: null
    };

    if (this.lines.length >= this.maxLines) {
      this.lines.shift();
      this.evicted++;
    }
    this.lines.push(entry);
    this.totalReceived++;
    return entry;
  }

  /**
   * Get lines matching the provided filter.
   * @param {object|null} filter - Filter object with matches(entry) method, or null for all
   * @returns {Array} Filtered log entries
   */
  getFilteredLines(filter = null) {
    if (!filter) {
      return [...this.lines];
    }
    return this.lines.filter(entry => filter.matches(entry));
  }

  /**
   * Get all lines in the buffer.
   * @returns {Array} All log entries
   */
  getAllLines() {
    return [...this.lines];
  }

  /**
   * Get buffer utilization info.
   * @returns {object} { current, max, usage, evicted, totalReceived }
   */
  getUtilization() {
    return {
      current: this.lines.length,
      max: this.maxLines,
      usage: this.maxLines > 0 ? (this.lines.length / this.maxLines) : 0,
      evicted: this.evicted,
      totalReceived: this.totalReceived
    };
  }

  /**
   * Clear all entries from the buffer.
   */
  clear() {
    this.lines = [];
    this.totalReceived = 0;
    this.evicted = 0;
  }

  /**
   * Get entry by index.
   * @param {number} index - Entry index
   * @returns {object|null} The entry or null if not found
   */
  getByIndex(index) {
    return this.lines[index] || null;
  }

  /**
   * Get entries within a range of indices.
   * @param {number} start - Start index (inclusive)
   * @param {number} end - End index (exclusive)
   * @returns {Array} Entries in range
   */
  getRange(start, end) {
    return this.lines.slice(start, end);
  }

  /**
   * Prepend entries to the beginning of the buffer (for loading older lines).
   * @param {Array} entries - Entries to prepend
   */
  prepend(entries) {
    const space = this.maxLines - this.lines.length;
    const toAdd = entries.slice(-space);
    this.lines = [...toAdd, ...this.lines];
    this.totalReceived += entries.length;
    if (entries.length > space) {
      this.evicted += entries.length - space;
    }
  }
}

// Export for testing and module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { LogBuffer };
}
