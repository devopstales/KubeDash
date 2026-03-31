#!/usr/bin/env node
/**
 * Cursor afterShellExecution: PR logging + optional async build follow-up.
 */
'use strict';

const { chainRunWithFlags, readStdin } = require('./cursor-chain.js');

readStdin().then((raw) => {
  const out = chainRunWithFlags(raw, [
    ['post:bash:pr-created', '.ai-config/hooks/post-bash-pr-created.js', 'standard,strict'],
    ['post:bash:build-complete', '.ai-config/hooks/post-bash-build-complete.js', 'standard,strict'],
  ]);
  process.stdout.write(out);
});
