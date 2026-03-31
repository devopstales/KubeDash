#!/usr/bin/env node
/**
 * Cursor beforeShellExecution: tmux / dev-server / git-push guardrails (chained).
 */
'use strict';

const { chainRunWithFlags, readStdin } = require('./cursor-chain.js');

readStdin().then((raw) => {
  const out = chainRunWithFlags(raw, [
    ['pre:bash:dev-server-block', '.ai-config/hooks/pre-bash-dev-server-block.js', 'standard'],
    ['pre:bash:tmux-reminder', '.ai-config/hooks/pre-bash-tmux-reminder.js', 'strict'],
    ['pre:bash:git-push-reminder', '.ai-config/hooks/pre-bash-git-push-reminder.js', 'strict'],
  ]);
  process.stdout.write(out);
});
