#!/usr/bin/env node
// fe-airgap-check — ADR-0020's frontend proof: the built bundle must carry no
// loadable external reference.
//
//   node scripts/fe-airgap-check.mjs <distDir> [--allow "a,b,c"]
//
// Scans every file under <distDir>: text files as UTF-8, binary files only
// when the extension is .svg (fonts/rasters cannot carry a loadable URL
// reference; M3). Flagged: any https?:// and any //cdn. reference whose
// host is not allowed. --allow adds a SUBSTRING allow-list (extends the
// default, never replaces it). One line per offender on stdout, exit 1;
// else exit 0. Taskfile-free by contract: CI calls this exact CLI.
import { readFileSync, readdirSync } from 'node:fs';

// Default allow-list — pinned by the pre-flight scan of the real
// frontend/dist (TICKET-18, I-NEW-3). Every entry is a namespace URI,
// message-text URL, or dev placeholder: matched by https?:// but never
// loaded at runtime (no <script src>, <link href>, @import, or fetch
// targets it).
const DEFAULT_ALLOW = [
  // XML/SVG/XMLNS/XSLT namespace URIs: identifiers passed to createElementNS
  // / setAttributeNS (inlined CoreUI SVG assets + React DOM), not fetched.
  'www.w3.org',
  // React error-message docs URL (https://react.dev/errors/<code>): built
  // into the error path, not fetched.
  'react.dev',
  // React error-message doc URLs (react-router data-router guidance +
  // dev-mode checkPropTypes pointer): user-facing message text.
  'reactrouter.com',
  'fb.me',
  // core-js browser-compat warning + LICENSE attribution: message text.
  'zloirock',
  // Vite build placeholder + CoreUI template header comment in index.html
  // (attribution / install docs), never a loadable reference.
  'coreui',
  // Dev-mode defaults/placeholders in the bundle:
  //   http://localhost — react-router dev-mode origin fallback
  //   https://api.example:6443 — API-base input placeholder
  'localhost',
  'api.example',
  // core-js self-test URL strings (new URL('https://a...'), 'https://x', ...):
  // the self-test's host is 'a', so the allow key is that host.
  'https://a',
  // Same self-test block's remaining literals: new URL('https://x') and
  // new URL('https://тест') (IDN host check).
  'https://x',
  'https://тест',
  // Project docs/repo nav links (AppHeader/AppFooter) — target=_blank message-text
  // links, not loadable CDN refs (no <script>/<link>/@import/fetch targets them).
  'devopstales.github.io',
  'github.com/devopstales',
];

// The two air-gap regexes (I8 precision: protocol-relative non-CDN URLs are
// OUT of scope).
const RE_HTTP = /https?:\/\/[^\s"'<>()\\]+/g;
const RE_CDN = /\/\/cdn\.[^\s"'<>()\\]+/g;

function parseArgs(argv) {
  let dist = '';
  const allow = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--allow') {
      allow.push(...(argv[++i] ?? '').split(',').map((s) => s.trim()).filter(Boolean));
    } else if (!dist) {
      dist = argv[i];
    }
  }
  if (!dist) {
    console.error('usage: fe-airgap-check.mjs <distDir> [--allow "a,b,c"]');
    process.exit(2);
  }
  return { dist, allow };
}

function scanFile(abs, rel, allowList) {
  // ponytail: non-strict UTF-8 for every text file (bad bytes decode to
  // U+FFFD, so a lone bad byte can hide a match). Ceiling: a Latin-1-encoded
  // asset; upgrade = fall back to latin-1 decode when strict UTF-8 fails.
  const text = new TextDecoder('utf-8', { fatal: false }).decode(readFileSync(abs));
  const offenders = [];
  for (const [idx, line] of text.split('\n').entries()) {
    const hits = [];
    for (const re of [RE_HTTP, RE_CDN]) {
      re.lastIndex = 0;
      for (let m; (m = re.exec(line));) hits.push(m[0]);
    }
    for (const url of hits) {
      if (allowList.some((a) => url.includes(a))) continue;
      offenders.push(`${rel}:${idx + 1}: ${url}`);
    }
  }
  return offenders;
}

const { dist, allow } = parseArgs(process.argv.slice(2));
const allowList = [...DEFAULT_ALLOW, ...allow];

function* walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = `${dir}/${entry.name}`;
    if (entry.isDirectory()) yield* walk(p);
    else if (entry.isFile()) yield p;
  }
}

const offenders = [];
for (const p of walk(dist)) {
  const name = p.split('/').pop() ?? p;
  const lower = name.toLowerCase();
  // M3: a non-.svg binary file cannot carry a loadable URL reference
  // (fonts/rasters). Text is scanned as UTF-8; .svg is scanned regardless.
  if (!lower.endsWith('.svg') && readFileSync(p).includes(0)) continue;
  const rel = p.startsWith(`${dist}/`) ? p.slice(dist.length + 1) : name;
  offenders.push(...scanFile(p, rel, allowList));
}

for (const o of new Set(offenders)) console.log(o);
if (offenders.length) process.exit(1);
