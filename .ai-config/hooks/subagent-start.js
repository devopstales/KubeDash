#!/usr/bin/env node
'use strict';

let data = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => {
  if (data.length < 1024 * 1024) data += c;
});
process.stdin.on('end', () => {
  process.stderr.write('[Hook] subagentStart\n');
  process.stdout.write(data);
});
