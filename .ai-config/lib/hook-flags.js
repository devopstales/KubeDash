'use strict';

/**
 * ECC_DISABLED_HOOKS=comma,separated,hookIds
 * ECC_HOOK_PROFILE=minimal|standard|strict — hooks may list allowed profiles via opts.profiles
 */
function parseDisabled() {
  const raw = process.env.ECC_DISABLED_HOOKS || '';
  return new Set(
    raw
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
  );
}

function isHookEnabled(hookId, opts = {}) {
  if (parseDisabled().has(hookId)) return false;

  const profilesCsv = opts.profiles || '';
  const allowed = profilesCsv.split(',').map((s) => s.trim()).filter(Boolean);
  if (allowed.length === 0) return true;

  const profile = (process.env.ECC_HOOK_PROFILE || 'standard').toLowerCase();
  return allowed.includes(profile);
}

module.exports = { isHookEnabled };
