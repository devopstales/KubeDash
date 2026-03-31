'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

function listAliases(opts = {}) {
  const limit = opts.limit || 20;
  const f = path.join(os.homedir(), '.claude', 'session-aliases.json');
  if (!fs.existsSync(f)) return [];
  try {
    const j = JSON.parse(fs.readFileSync(f, 'utf8'));
    const entries = Object.entries(j || {}).map(([name, v]) => ({ name, ...v }));
    return entries.slice(0, limit);
  } catch {
    return [];
  }
}

module.exports = { listAliases };
