/**
 * TerminalSettings - Load/save user terminal preferences to localStorage.
 * 
 * Settings managed:
 * - fontSize: Terminal font size in pixels (default: 14, range: 10-20)
 * - fontFamily: Terminal font family (default: monospace)
 * - cursorStyle: 'block' | 'underline' | 'bar' (default: 'block')
 * - cursorBlink: Whether cursor blinks (default: true)
 * - scrollback: Max scrollback lines (default: 5000, range: 1000-50000)
 * - bellStyle: 'none' | 'sound' | 'visual' (default: 'none')
 * - maxTabs: Maximum concurrent tabs (default: 8)
 */
class TerminalSettings {
  constructor() {
    this.storageKey = 'kubedash-terminal-settings';
    this.defaults = {
      fontSize: 14,
      fontFamily: "'Cascadia Code', 'Fira Code', 'JetBrains Mono', 'Courier New', monospace",
      cursorStyle: 'block',
      cursorBlink: true,
      scrollback: 5000,
      bellStyle: 'none',
      maxTabs: 8
    };
  }

  /**
   * Load all settings, merging with defaults.
   * @returns {object} Settings object
   */
  load() {
    try {
      const stored = localStorage.getItem(this.storageKey);
      if (stored) {
        const parsed = JSON.parse(stored);
        return { ...this.defaults, ...parsed };
      }
    } catch (e) {
      console.warn('Failed to load terminal settings:', e);
    }
    return { ...this.defaults };
  }

  /**
   * Save a single setting.
   * @param {string} key - Setting name
   * @param {*} value - Setting value
   */
  save(key, value) {
    try {
      const settings = this.load();
      settings[key] = value;
      localStorage.setItem(this.storageKey, JSON.stringify(settings));
    } catch (e) {
      console.warn('Failed to save terminal setting:', e);
    }
  }

  /**
   * Get a single setting value.
   * @param {string} key - Setting name
   * @param {*} defaultValue - Fallback value
   * @returns {*}
   */
  get(key, defaultValue) {
    const settings = this.load();
    return settings[key] !== undefined ? settings[key] : (defaultValue !== undefined ? defaultValue : this.defaults[key]);
  }

  /**
   * Reset all settings to defaults.
   */
  reset() {
    try {
      localStorage.removeItem(this.storageKey);
    } catch (e) {
      console.warn('Failed to reset terminal settings:', e);
    }
  }

  /**
   * Get xterm.js options object from current settings.
   * @returns {object} Options for new Terminal()
   */
  getXtermOptions() {
    const settings = this.load();
    return {
      fontSize: settings.fontSize,
      fontFamily: settings.fontFamily,
      cursorStyle: settings.cursorStyle,
      cursorBlink: settings.cursorBlink,
      scrollback: settings.scrollback,
      bellStyle: settings.bellStyle,
      theme: {
        background: '#0d1117',
        foreground: '#c9d1d9',
        cursor: '#c9d1d9',
        cursorAccent: '#0d1117',
        selectionBackground: 'rgba(187, 128, 9, 0.3)',
        black: '#0d1117',
        red: '#f85149',
        green: '#3fb950',
        yellow: '#d29922',
        blue: '#58a6ff',
        magenta: '#bc8cff',
        cyan: '#39c5cf',
        white: '#c9d1d9',
        brightBlack: '#484f58',
        brightRed: '#ff7b72',
        brightGreen: '#56d364',
        brightYellow: '#e3b341',
        brightBlue: '#79c0ff',
        brightMagenta: '#d2a8ff',
        brightCyan: '#56d4dd',
        brightWhite: '#f0f6fc'
      }
    };
  }
}

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { TerminalSettings };
}
