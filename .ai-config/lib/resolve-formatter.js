'use strict';

const fs = require('fs');
const path = require('path');

function findProjectRoot(startDir) {
  let dir = path.resolve(startDir);
  for (;;) {
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return path.resolve(startDir);
}

function detectFormatter(projectRoot) {
  if (fs.existsSync(path.join(projectRoot, 'biome.json')) ||
      fs.existsSync(path.join(projectRoot, 'biome.jsonc'))) {
    return 'biome';
  }
  if (
    fs.existsSync(path.join(projectRoot, '.prettierrc')) ||
    fs.existsSync(path.join(projectRoot, '.prettierrc.json')) ||
    fs.existsSync(path.join(projectRoot, 'prettier.config.js')) ||
    fs.existsSync(path.join(projectRoot, 'prettier.config.cjs'))
  ) {
    return 'prettier';
  }
  const pkgPath = path.join(projectRoot, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      if (deps['@biomejs/biome'] || deps['@biomejs/cli']) return 'biome';
      if (deps.prettier) return 'prettier';
    } catch {
      /* ignore */
    }
  }
  return null;
}

function resolveFormatterBin(projectRoot, formatter) {
  const binDir = path.join(projectRoot, 'node_modules', '.bin');
  if (formatter === 'biome') {
    const bin = path.join(binDir, process.platform === 'win32' ? 'biome.cmd' : 'biome');
    if (fs.existsSync(bin)) return { bin, prefix: [] };
    return { bin: 'npx', prefix: ['@biomejs/biome'] };
  }
  if (formatter === 'prettier') {
    const bin = path.join(binDir, process.platform === 'win32' ? 'prettier.cmd' : 'prettier');
    if (fs.existsSync(bin)) return { bin, prefix: [] };
    return { bin: 'npx', prefix: ['prettier'] };
  }
  return null;
}

module.exports = { findProjectRoot, detectFormatter, resolveFormatterBin };
