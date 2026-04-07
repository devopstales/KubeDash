/**
 * LogSearch - Client-side full-text search across log buffer with match highlighting,
 * navigation, and count display.
 */
class LogSearch {
  constructor(buffer, renderer) {
    this.buffer = buffer;
    this.renderer = renderer;
    this.active = false;
    this.currentMatchIndex = -1;
    this.matches = [];
    this.lastQuery = '';
    this.lastCaseSensitive = false;
  }

  /**
   * Search for a query across the buffer.
   * @param {string} query - Search query string
   * @param {boolean} caseSensitive - Whether to match case
   */
  search(query, caseSensitive = false) {
    if (!query || query.trim() === '') {
      this.clear();
      return;
    }

    this.active = true;
    this.lastQuery = query;
    this.lastCaseSensitive = caseSensitive;
    this.currentMatchIndex = 0;
    this.matches = [];

    const flags = caseSensitive ? 'g' : 'gi';
    const escapedQuery = this.escapeRegex(query);
    const regex = new RegExp(escapedQuery, flags);

    for (let i = 0; i < this.buffer.lines.length; i++) {
      const line = this.buffer.lines[i];
      const text = line.line;
      let match;

      // Reset regex lastIndex for global regexes
      regex.lastIndex = 0;
      while ((match = regex.exec(text)) !== null) {
        this.matches.push({
          lineIndex: i,
          matchIndex: this.matches.length,
          startIndex: match.index,
          endIndex: regex.lastIndex
        });

        // Avoid infinite loops on zero-width matches
        if (match.index === regex.lastIndex) {
          regex.lastIndex++;
        }
      }
    }

    // Store regex for highlighting
    this.renderer.lastSearchRegex = new RegExp(escapedQuery, flags);

    // Apply highlights
    this._applyHighlights();
  }

  /**
   * Navigate to the next match.
   */
  nextMatch() {
    if (this.matches.length === 0) return;

    this.currentMatchIndex = (this.currentMatchIndex + 1) % this.matches.length;
    this._scrollToCurrentMatch();
    this._updateHighlight();
  }

  /**
   * Navigate to the previous match.
   */
  prevMatch() {
    if (this.matches.length === 0) return;

    this.currentMatchIndex = (this.currentMatchIndex - 1 + this.matches.length) % this.matches.length;
    this._scrollToCurrentMatch();
    this._updateHighlight();
  }

  /**
   * Clear search and remove all highlights.
   */
  clear() {
    this.active = false;
    this.currentMatchIndex = -1;
    this.matches = [];
    this.lastQuery = '';
    this.renderer.clearSearchHighlights();
  }

  /**
   * Apply highlights to the DOM.
   * @package
   */
  _applyHighlights() {
    this.renderer.highlightMatches(this.matches, this.currentMatchIndex);
  }

  /**
   * Update the current match highlight.
   * @private
   */
  _updateHighlight() {
    this.renderer.highlightMatches(this.matches, this.currentMatchIndex);
  }

  /**
   * Scroll the container to show the current match.
   * @private
   */
  _scrollToCurrentMatch() {
    if (this.currentMatchIndex < 0 || this.currentMatchIndex >= this.matches.length) return;

    const match = this.matches[this.currentMatchIndex];
    const entry = this.buffer.getByIndex(match.lineIndex);
    if (!entry || !entry.domElement) return;

    // Scroll element into view
    entry.domElement.scrollIntoView({
      behavior: 'smooth',
      block: 'center'
    });
  }

  /**
   * Escape special regex characters in a string.
   * @param {string} str
   * @returns {string}
   */
  escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /**
   * Get match count info.
   * @returns {object} { total, current }
   */
  getMatchInfo() {
    return {
      total: this.matches.length,
      current: this.matches.length > 0 ? this.currentMatchIndex + 1 : 0
    };
  }
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { LogSearch };
}
