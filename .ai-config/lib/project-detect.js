'use strict';

const fs = require('fs');
const path = require('path');

function detectProjectType(cwd = process.cwd()) {
  const languages = [];
  const frameworks = [];
  if (fs.existsSync(path.join(cwd, 'package.json'))) {
    languages.push('javascript');
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(cwd, 'package.json'), 'utf8'));
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };
      if (deps.react) frameworks.push('react');
      if (deps.next) frameworks.push('next');
      if (deps.vue) frameworks.push('vue');
      if (deps['@angular/core']) frameworks.push('angular');
    } catch {
      /* ignore */
    }
  }
  if (fs.existsSync(path.join(cwd, 'Cargo.toml'))) languages.push('rust');
  if (fs.existsSync(path.join(cwd, 'go.mod'))) languages.push('go');
  if (fs.existsSync(path.join(cwd, 'pyproject.toml')) || fs.existsSync(path.join(cwd, 'setup.py')))
    languages.push('python');
  return { languages, frameworks };
}

module.exports = { detectProjectType };
