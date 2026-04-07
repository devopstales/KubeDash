/**
 * LogRenderer - DOM-based renderer for log lines with styled output,
 * auto-scroll logic, and search highlighting.
 */
class LogRenderer {
  constructor(containerEl, options = {}) {
    this.container = containerEl;
    this.showTimestamps = options.showTimestamps !== false;
    this.virtualScroll = options.virtualScroll || false;
    this.podColors = {};
    this.autoScrollEnabled = true;
    this.maxDomNodes = 5000;
    this.domNodeCount = 0;
  }

  /**
   * Append a single log entry to the DOM.
   * @param {object} entry - Log entry from LogBuffer
   */
  append(entry) {
    if (!entry.visible) return;
    const el = this.createLineElement(entry);
    entry.domElement = el;
    this.container.appendChild(el);
    this.domNodeCount++;

    // Enforce DOM node cap
    if (this.domNodeCount > this.maxDomNodes) {
      const firstChild = this.container.firstChild;
      if (firstChild) {
        this.container.removeChild(firstChild);
        this.domNodeCount--;
      }
    }

    if (this.autoScrollEnabled) {
      this.scrollToBottom();
    }
  }

  /**
   * Re-render all visible entries (e.g., after filter change).
   * @param {Array} entries - Filtered entries to render
   */
  renderAll(entries) {
    // Clear existing content
    this.container.innerHTML = '';
    this.domNodeCount = 0;

    // Use DocumentFragment for performance
    const fragment = document.createDocumentFragment();
    const renderEntries = entries.slice(-this.maxDomNodes);

    for (const entry of renderEntries) {
      const el = this.createLineElement(entry);
      entry.domElement = el;
      fragment.appendChild(el);
    }

    this.container.appendChild(fragment);
    this.domNodeCount = renderEntries.length;

    if (this.autoScrollEnabled) {
      this.scrollToBottom();
    }
  }

  /**
   * Create a DOM element for a log line.
   * @param {object} entry - Log entry
   * @returns {HTMLDivElement}
   */
  createLineElement(entry) {
    const row = document.createElement('div');
    row.className = `log-line level-${entry.level.toLowerCase()}`;
    row.dataset.level = entry.level;
    row.dataset.index = entry.index;

    if (this.showTimestamps) {
      const ts = document.createElement('span');
      ts.className = 'log-timestamp';
      ts.textContent = this.formatTimestamp(entry.timestamp);
      row.appendChild(ts);
    }

    if (entry.pod) {
      const pod = document.createElement('span');
      pod.className = 'log-pod-name';
      pod.style.color = this.getPodColor(entry.pod);
      pod.textContent = `[${entry.pod}] `;
      row.appendChild(pod);
    }

    const msg = document.createElement('span');
    msg.className = 'log-message';
    msg.textContent = entry.line;
    row.appendChild(msg);

    return row;
  }

  /**
   * Toggle timestamp visibility.
   * @param {boolean} show - Whether to show timestamps
   */
  setTimestampVisibility(show) {
    this.showTimestamps = show;
    const timestamps = this.container.querySelectorAll('.log-timestamp');
    timestamps.forEach(ts => {
      ts.classList.toggle('hidden', !show);
    });
  }

  /**
   * Enable or disable auto-scroll.
   * @param {boolean} enabled
   */
  setAutoScroll(enabled) {
    this.autoScrollEnabled = enabled;
  }

  /**
   * Scroll the container to the bottom.
   */
  scrollToBottom() {
    this.container.scrollTop = this.container.scrollHeight;
  }

  /**
   * Clear search highlights from all lines.
   */
  clearSearchHighlights() {
    const highlighted = this.container.querySelectorAll('.search-match, .search-match-current');
    highlighted.forEach(el => {
      const parent = el.parentNode;
      if (parent) {
        parent.replaceChild(document.createTextNode(el.textContent), el);
        parent.normalize();
      }
    });
  }

  /**
   * Highlight search matches in the DOM.
   * @param {Array} matches - Array of { lineIndex, matchIndex } objects
   * @param {number} currentMatchIndex - Index of the currently selected match
   */
  highlightMatches(matches, currentMatchIndex = -1) {
    this.clearSearchHighlights();

    if (!matches || matches.length === 0) return;

    for (const match of matches) {
      const entry = this.container.querySelector(`.log-line[data-index="${match.lineIndex}"] .log-message`);
      if (!entry) continue;

      const text = entry.textContent;
      const regex = this._lastSearchRegex || /()/gi;
      regex.lastIndex = 0;

      const fragment = document.createDocumentFragment();
      let lastIndex = 0;
      let m;

      while ((m = regex.exec(text)) !== null) {
        // Text before match
        if (m.index > lastIndex) {
          fragment.appendChild(document.createTextNode(text.slice(lastIndex, m.index)));
        }

        // Match text
        const span = document.createElement('span');
        span.className = 'search-match';
        if (match.matchIndex === currentMatchIndex) {
          span.classList.add('search-match-current');
        }
        span.textContent = m[0];
        fragment.appendChild(span);

        lastIndex = regex.lastIndex;
        if (!regex.global) break;
      }

      // Remaining text
      if (lastIndex < text.length) {
        fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
      }

      entry.innerHTML = '';
      entry.appendChild(fragment);
    }
  }

  /**
   * Store the last used search regex for highlighting.
   * @param {RegExp} regex
   */
  set lastSearchRegex(regex) {
    this._lastSearchRegex = regex;
  }

  /**
   * Get a consistent color for a pod name.
   * @param {string} podName
   * @returns {string} CSS color string
   */
  getPodColor(podName) {
    if (!this.podColors[podName]) {
      const colors = ['#42a5f5', '#66bb6a', '#ffa726', '#ef5350', '#ab47bc', '#26c6da', '#ec407a', '#9ccc65'];
      const idx = Object.keys(this.podColors).length % colors.length;
      this.podColors[podName] = colors[idx];
    }
    return this.podColors[podName];
  }

  /**
   * Format a timestamp for display.
   * @param {number} ts - Unix timestamp in ms
   * @returns {string}
   */
  formatTimestamp(ts) {
    const d = new Date(ts);
    return d.toISOString().replace('T', ' ').substring(0, 23);
  }

  /**
   * Clear all rendered content.
   */
  clear() {
    this.container.innerHTML = '';
    this.domNodeCount = 0;
    this.podColors = {};
  }
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { LogRenderer };
}
