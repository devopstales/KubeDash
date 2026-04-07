/**
 * LogLevelDetector - Static utility for detecting log levels from line text.
 * Supports common log formats including JSON, plain text, and structured logs.
 */
const LogLevelDetector = {
  PATTERNS: {
    FATAL: /^(DEBUG\s+)?(FATAL|PANIC|CRIT|CRITICAL|F\s)/i,
    ERROR: /^(DEBUG\s+)?(ERROR|ERR|E\s|Exception|Traceback|Traceback \(most recent call last\))/i,
    WARN: /^(DEBUG\s+)?(WARN|WARNING|W\s)/i,
    INFO: /^(DEBUG\s+)?(INFO|INF|I\s|NOTICE|N\s)/i,
    DEBUG: /^(DEBUG|DBG|D\s)/i,
  },

  /**
   * Detect log level from a line of text.
   * @param {string} line - The log line to analyze
   * @returns {string} One of: FATAL, ERROR, WARN, INFO, DEBUG, UNKNOWN
   */
  detect(line) {
    if (!line || typeof line !== 'string') {
      return 'UNKNOWN';
    }

    // Check patterns in order of severity (highest first)
    for (const [level, regex] of Object.entries(this.PATTERNS)) {
      if (regex.test(line)) {
        return level;
      }
    }

    // Try JSON format with level field
    if (line.trimStart().startsWith('{')) {
      try {
        const parsed = JSON.parse(line);
        const levelField = parsed.level || parsed.severity || parsed.log_level || parsed.lvl;
        if (levelField) {
          const normalized = String(levelField).toUpperCase();
          if (normalized.includes('FATAL') || normalized.includes('PANIC') || normalized.includes('CRIT')) return 'FATAL';
          if (normalized.includes('ERROR') || normalized.includes('ERR')) return 'ERROR';
          if (normalized.includes('WARN')) return 'WARN';
          if (normalized.includes('INFO')) return 'INFO';
          if (normalized.includes('DEBUG')) return 'DEBUG';
        }
      } catch (e) {
        // Not valid JSON, continue
      }
    }

    // Check for stack traces or error-like patterns anywhere in line
    if (/Exception|Error:|fatal|panic|critical/i.test(line)) {
      return 'ERROR';
    }

    return 'UNKNOWN';
  }
};

// Export for testing
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { LogLevelDetector };
}
