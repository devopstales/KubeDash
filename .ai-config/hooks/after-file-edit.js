#!/usr/bin/env node
/**
 * Cursor afterFileEdit: format, typecheck, console warn, quality gate.
 */
'use strict';

const { spawnSync } = require('child_process');
const path = require('path');
const { readStdin } = require('./cursor-chain.js');

readStdin().then((raw) => {
  const scripts = [
    'post-edit-format.js',
    'post-edit-typecheck.js',
    'post-edit-console-warn.js',
    'quality-gate.js',
  ];
  let cur = raw;
  for (const s of scripts) {
    const r = spawnSync(process.execPath, [path.join(__dirname, s)], {
      input: cur,
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
    });
    if (typeof r.stdout === 'string' && r.stdout.length) cur = r.stdout;
  }
  process.stdout.write(cur);
});
