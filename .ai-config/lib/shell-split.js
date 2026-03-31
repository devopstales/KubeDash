'use strict';

/**
 * Split a shell command into top-level segments on && and ; (respecting quotes).
 */
function splitShellSegments(cmd) {
  if (!cmd || !String(cmd).trim()) return [];
  const input = String(cmd);
  const segments = [];
  let current = '';
  let depth = 0;
  let quote = null;

  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i];

    if (quote) {
      current += ch;
      if (ch === quote && input[i - 1] !== '\\') quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === '(') {
      depth += 1;
      current += ch;
      continue;
    }
    if (ch === ')') {
      depth -= 1;
      current += ch;
      continue;
    }

    if (depth === 0 && ch === '&' && input[i + 1] === '&') {
      if (current.trim()) segments.push(current.trim());
      current = '';
      i += 1;
      continue;
    }
    if (depth === 0 && ch === ';') {
      if (current.trim()) segments.push(current.trim());
      current = '';
      continue;
    }
    current += ch;
  }
  if (current.trim()) segments.push(current.trim());
  return segments.length ? segments : [input.trim()];
}

module.exports = { splitShellSegments };
