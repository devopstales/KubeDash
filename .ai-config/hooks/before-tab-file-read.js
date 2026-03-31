#!/usr/bin/env node
'use strict';

let data = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => {
  if (data.length < 1024 * 1024) data += c;
});
process.stdin.on('end', () => {
  try {
    const input = JSON.parse(data);
    const p = String(input.tool_input?.file_path || input.file_path || '');
    if (/\.(env|pem|key)$/i.test(p) || /credentials/i.test(p)) {
      process.stderr.write(`[Hook] Tab read blocked suggestion for: ${p}\n`);
    }
  } catch {
    /* ignore */
  }
  process.stdout.write(data);
});
