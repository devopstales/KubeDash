#!/usr/bin/env node
/**
 * Cursor beforeSubmitPrompt — flag obvious secret patterns in user text.
 */
'use strict';

let data = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => {
  if (data.length < 1024 * 1024) data += c;
});
process.stdin.on('end', () => {
  try {
    const input = JSON.parse(data);
    const text = JSON.stringify(input);
    if (/\bsk-[a-zA-Z0-9]{20,}\b/.test(text) || /\bghp_[a-zA-Z0-9]+\b/.test(text) || /\bAKIA[0-9A-Z]{16}\b/.test(text)) {
      process.stderr.write('[Hook] WARNING: prompt may contain secret-like tokens — review before sending.\n');
    }
  } catch {
    /* ignore */
  }
  process.stdout.write(data);
});
