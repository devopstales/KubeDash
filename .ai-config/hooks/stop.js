#!/usr/bin/env node
/**
 * Cursor stop: console audit, session persistence, evaluation, cost.
 */
'use strict';

const { chainRunWithFlags, readStdin } = require('./cursor-chain.js');

readStdin().then((raw) => {
  const out = chainRunWithFlags(raw, [
    ['stop:check-console-log', '.ai-config/hooks/check-console-log.js', 'standard,strict'],
    ['stop:session-end', '.ai-config/hooks/session-end.js', 'minimal,standard,strict'],
    ['stop:evaluate-session', '.ai-config/hooks/evaluate-session.js', 'minimal,standard,strict'],
    ['stop:cost-tracker', '.ai-config/hooks/cost-tracker.js', 'minimal,standard,strict'],
  ]);
  process.stdout.write(out);
});
