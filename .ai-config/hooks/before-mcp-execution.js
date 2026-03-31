#!/usr/bin/env node
'use strict';

const { chainRunWithFlags, readStdin } = require('./cursor-chain.js');

readStdin().then((raw) => {
  const out = chainRunWithFlags(raw, [
    ['pre:mcp-health-check', '.ai-config/hooks/mcp-health-check.js', 'standard,strict'],
  ]);
  process.stdout.write(out);
});
