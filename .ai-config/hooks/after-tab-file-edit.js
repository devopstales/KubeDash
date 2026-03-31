#!/usr/bin/env node
'use strict';

const { spawnSync } = require('child_process');
const path = require('path');

let data = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => {
  if (data.length < 1024 * 1024) data += c;
});
process.stdin.on('end', () => {
  const r = spawnSync(process.execPath, [path.join(__dirname, 'post-edit-format.js')], {
    input: data,
    encoding: 'utf8',
    maxBuffer: 1024 * 1024,
  });
  process.stdout.write(typeof r.stdout === 'string' && r.stdout.length ? r.stdout : data);
});
