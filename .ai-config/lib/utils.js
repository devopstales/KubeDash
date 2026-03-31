/**
 * Shared utilities for hooks (minimal self-contained implementation).
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync, spawnSync } = require('child_process');

function getClaudeDir() {
  return path.join(os.homedir(), '.claude');
}

function getSessionsDir() {
  return path.join(getClaudeDir(), 'sessions');
}

function getLearnedSkillsDir() {
  return path.join(getClaudeDir(), 'learned-skills');
}

function getTempDir() {
  return os.tmpdir();
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function readFile(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch {
    return null;
  }
}

function writeFile(filePath, content) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, content, 'utf8');
}

function appendFile(filePath, content) {
  ensureDir(path.dirname(filePath));
  fs.appendFileSync(filePath, content, 'utf8');
}

function stripAnsi(text) {
  if (!text) return '';
  // eslint-disable-next-line no-control-regex
  return String(text).replace(/\u001b\[[0-9;]*m/g, '');
}

function log(msg) {
  process.stderr.write(`${msg}\n`);
}

function output(msg) {
  process.stdout.write(msg);
}

function getDateString() {
  const d = new Date();
  return d.toISOString().slice(0, 10);
}

function getDateTimeString() {
  return new Date().toISOString();
}

function getTimeString() {
  const d = new Date();
  return d.toTimeString().slice(0, 8);
}

function getSessionIdShort() {
  return String(process.pid).slice(-6);
}

function getProjectName() {
  try {
    const pkg = path.join(process.cwd(), 'package.json');
    if (fs.existsSync(pkg)) {
      const j = JSON.parse(readFile(pkg) || '{}');
      if (j.name) return String(j.name);
    }
  } catch {
    /* ignore */
  }
  return path.basename(process.cwd());
}

function runCommand(cmd) {
  try {
    const out = execFileSync('/bin/sh', ['-c', cmd], {
      encoding: 'utf8',
      maxBuffer: 2 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { success: true, output: String(out).trim() };
  } catch (e) {
    const out = e.stdout != null ? String(e.stdout) : '';
    return { success: false, output: out.trim() };
  }
}

/**
 * @param {string} dir
 * @param {string} pattern glob-like *suffix
 * @param {{ maxAge?: number }} [opts]
 */
function findFiles(dir, pattern, opts = {}) {
  if (!fs.existsSync(dir)) return [];
  const maxAgeDays = opts.maxAge;
  const now = Date.now();
  const results = [];
  let files;
  try {
    files = fs.readdirSync(dir);
  } catch {
    return [];
  }
  const star = pattern.indexOf('*');
  const suffix = star >= 0 ? pattern.slice(star + 1) : pattern;
  for (const name of files) {
    if (suffix && !name.endsWith(suffix)) continue;
    const full = path.join(dir, name);
    let st;
    try {
      st = fs.statSync(full);
    } catch {
      continue;
    }
    if (!st.isFile()) continue;
    if (maxAgeDays != null) {
      const ageMs = now - st.mtimeMs;
      if (ageMs > maxAgeDays * 24 * 60 * 60 * 1000) continue;
    }
    results.push({ path: full, name, mtime: st.mtimeMs });
  }
  results.sort((a, b) => b.mtime - a.mtime);
  return results;
}

function countInFile(filePath, regex) {
  const content = readFile(filePath);
  if (!content) return 0;
  let n = 0;
  content.replace(regex, () => {
    n += 1;
    return '';
  });
  return n;
}

function isGitRepo() {
  try {
    const r = spawnSync('git', ['rev-parse', '--is-inside-work-tree'], {
      encoding: 'utf8',
      cwd: process.cwd(),
    });
    return r.status === 0 && String(r.stdout).trim() === 'true';
  } catch {
    return false;
  }
}

function getGitModifiedFiles() {
  try {
    const r = spawnSync('git', ['diff', '--name-only', 'HEAD'], {
      encoding: 'utf8',
      cwd: process.cwd(),
    });
    if (r.status !== 0) return [];
    return String(r.stdout || '')
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

module.exports = {
  getClaudeDir,
  getSessionsDir,
  getLearnedSkillsDir,
  getTempDir,
  ensureDir,
  readFile,
  writeFile,
  appendFile,
  stripAnsi,
  log,
  output,
  getDateString,
  getDateTimeString,
  getTimeString,
  getSessionIdShort,
  getProjectName,
  runCommand,
  findFiles,
  countInFile,
  isGitRepo,
  getGitModifiedFiles,
};
