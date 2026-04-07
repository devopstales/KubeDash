/**
 * LogExporter - Client-side export of log buffer as text or JSON with Blob-based download.
 */
const LogExporter = {
  /**
   * Export log entries as plain text.
   * @param {Array} entries - Array of log entries from LogBuffer
   * @param {object} options - Export options
   * @param {string} options.filename - Output filename
   * @param {boolean} options.timestamps - Include timestamps
   * @param {string} options.tsFormat - Timestamp format ('iso', 'local', 'unix')
   */
  exportAsText(entries, options = {}) {
    const filename = options.filename || this._generateFilename('log');
    const lines = entries
      .filter(e => e.visible !== false)
      .map(e => this._formatTextLine(e, options));

    const blob = new Blob([lines.join('\n')], { type: 'text/plain;charset=utf-8' });
    this._download(blob, filename);
  },

  /**
   * Export log entries as JSON Lines (JSONL).
   * @param {Array} entries - Array of log entries from LogBuffer
   * @param {object} options - Export options
   * @param {string} options.filename - Output filename
   */
  exportAsJson(entries, options = {}) {
    const filename = options.filename || this._generateFilename('jsonl');
    const lines = entries
      .filter(e => e.visible !== false)
      .map(e => this._formatJsonLine(e));

    const blob = new Blob([lines.join('\n')], { type: 'application/jsonl;charset=utf-8' });
    this._download(blob, filename);
  },

  /**
   * Format a single entry as a text line.
   * @param {object} entry - Log entry
   * @param {object} options - Format options
   * @returns {string}
   * @private
   */
  _formatTextLine(entry, options) {
    const parts = [];

    if (options.timestamps) {
      const ts = this._formatTimestamp(entry.timestamp, options.tsFormat);
      if (ts) parts.push(ts);
    }

    if (entry.pod) {
      parts.push(`[${entry.pod}]`);
    }

    if (entry.container) {
      parts.push(`[${entry.container}]`);
    }

    parts.push(entry.line);
    return parts.join(' ');
  },

  /**
   * Format a single entry as a JSON line.
   * @param {object} entry - Log entry
   * @returns {string}
   * @private
   */
  _formatJsonLine(entry) {
    return JSON.stringify({
      timestamp: entry.timestamp,
      pod: entry.pod,
      container: entry.container,
      message: entry.line,
      level: entry.level
    });
  },

  /**
   * Format a timestamp according to the specified format.
   * @param {number} ts - Unix timestamp in ms
   * @param {string} format - Format type
   * @returns {string}
   * @private
   */
  _formatTimestamp(ts, format = 'iso') {
    if (!ts) return '';

    const d = new Date(ts);
    switch (format) {
      case 'iso':
        return d.toISOString();
      case 'local':
        return d.toLocaleString();
      case 'unix':
        return String(Math.floor(ts / 1000));
      default:
        return d.toISOString();
    }
  },

  /**
   * Trigger a file download from a Blob.
   * @param {Blob} blob - Blob to download
   * @param {string} filename - Filename for the download
   * @private
   */
  _download(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();

    // Cleanup
    setTimeout(() => {
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }, 100);
  },

  /**
   * Generate a default filename with timestamp.
   * @param {string} extension - File extension (without dot)
   * @returns {string}
   * @private
   */
  _generateFilename(extension = 'log') {
    const now = new Date();
    const ts = now.toISOString().replace(/[:.]/g, '-').substring(0, 19);
    return `kubedash-logs-${ts}.${extension}`;
  }
};

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { LogExporter };
}
