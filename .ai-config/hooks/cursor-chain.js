/**
 * Helpers for Cursor IDE hook entrypoints: chain run-with-flags children.
 */
'use strict';

const { spawnSync } = require('child_process');
const path = require('path');

const MAX = 1024 * 1024;

function getRunWithFlagsPath() {
  return path.join(__dirname, 'run-with-flags.js');
}

/**
 * @param {string} raw stdin
 * @param {Array<[string, string, string]>} steps [hookId, relFromProjectRoot, profilesCsv]
 */
function chainRunWithFlags(raw, steps) {
  const rwf = getRunWithFlagsPath();
  let cur = raw;
  for (const [hookId, relScript, profiles] of steps) {
    const r = spawnSync(process.execPath, [rwf, hookId, relScript, profiles], {
      input: cur,
      encoding: 'utf8',
      maxBuffer: MAX,
    });
    if (r.status === 2) process.exit(2);
    cur = typeof r.stdout === 'string' ? r.stdout : cur;
  }
  return cur;
}

function readStdin() {
  return new Promise((resolve) => {
    let raw = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => {
      if (raw.length < MAX) raw += c;
    });
    process.stdin.on('end', () => resolve(raw));
  });
}

module.exports = { chainRunWithFlags, readStdin, MAX };
