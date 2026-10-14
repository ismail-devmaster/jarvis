// SINGLE SOURCE OF TRUTH for ALLOW / ASK / DENY
// Node-safe runtime module (no Vite/browser APIs)

export const ALLOW = 'ALLOW';
export const ASK = 'ASK';
export const DENY = 'DENY';

export function guardToolCall({ tool, op, args, target, risk }) {
  const cmd = typeof args?.command === 'string' ? args.command : '';
  const cwd = typeof args?.cwd === 'string' ? args.cwd : (target || '/home/ismabeast');
  // Source of truth: destructive / privileged = DENY, state-change = ASK, safe read/execute = ALLOW
  const destructive = /\b(rm|rmdir|del|format|mkfs|dd|shutdown|reboot)\b/.test(cmd);
  const stateChange = /\b(git\s+commit|npm\s+install|yarn|pip|apt|brew)\b/.test(cmd) || /\b(init|add\b|commit\b)\b/.test(cmd);
  if (destructive) return DENY;
  if (stateChange) return ASK;
  return ALLOW;
}
export function auditAction(tool, target, status, err, durationMs) {
  console.log('[AUDIT]', tool, target, status, durationMs || 0);
  return { tool, target, status, err: err ? '['+err+']' : '', durationMs };
}
export function redact(t) {
  return (t || '').includes('secret') || (t || '').includes('key') ? '[REDACTED]' : t;
}
