'use strict';

const fs = require('fs');
const path = require('path');

function detectLockfile(cwd = process.cwd()) {
  if (fs.existsSync(path.join(cwd, 'pnpm-lock.yaml'))) return 'pnpm';
  if (fs.existsSync(path.join(cwd, 'yarn.lock'))) return 'yarn';
  if (fs.existsSync(path.join(cwd, 'package-lock.json'))) return 'npm';
  if (fs.existsSync(path.join(cwd, 'bun.lockb')) || fs.existsSync(path.join(cwd, 'bun.lock')))
    return 'bun';
  return null;
}

function getPackageManager() {
  const lock = detectLockfile();
  if (lock) {
    return { name: lock, source: 'lockfile' };
  }
  if (fs.existsSync(path.join(process.cwd(), 'package.json'))) {
    return { name: 'npm', source: 'package.json' };
  }
  return { name: 'npm', source: 'default' };
}

function getSelectionPrompt() {
  return '[SessionStart] Set package manager: npm, pnpm, yarn, or bun (add lockfile to pin).';
}

module.exports = { getPackageManager, getSelectionPrompt };
