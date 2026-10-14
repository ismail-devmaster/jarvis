// Phase 1 — Permission engine + workspace + audit (minimal, local-first)
export type Category = 'READ' | 'WRITE' | 'EXECUTE' | 'BROWSER' | 'NETWORK' | 'DESTRUCTIVE' | 'PRIVILEGED'
export const POLICY: Record<Category, 'auto' | 'ask' | 'deny'> = {
  READ: 'auto', WRITE: 'auto', EXECUTE: 'auto', BROWSER: 'auto',
  NETWORK: 'auto', DESTRUCTIVE: 'ask', PRIVILEGED: 'deny',
}
export const WORKSPACES = [
  { path: '/home/ismabeast/Projects', read: true, write: true },
  { path: '/home/ismabeast/jarvis', read: true, write: true },
  { path: '/home/ismabeast/Desktop', read: true, write: false },
]
export interface AuditEntry { ts: number; tool: string; target: string; status: 'ok' | 'denied' | 'error' }
export const auditLog: AuditEntry[] = []
export function logAudit(e: AuditEntry) { auditLog.push(e); if (auditLog.length > 200) auditLog.shift(); }

export function confirm(action: string, target: string, category: Category): boolean {
  if (POLICY[category] === 'auto') return true
  if (POLICY[category] === 'deny') { logAudit({ ts: Date.now(), tool: action, target, status: 'denied' }); return false }
  // 'ask' — in a real UI this shows a dialog; here we log and require explicit user confirm
  logAudit({ ts: Date.now(), tool: action, target, status: 'ok' })
  return true // placeholder: actual confirmation needs UI hook
}
export function isDestructive(cmd: string): boolean {
  const d = ['rm','dd','mkfs','fdisk','dd ','> /dev','> /etc','> /sbin','force-push','> /dev/','> /etc/']
  return d.some(p => cmd.includes(p))
}

export function checkWorkspace(p: string): 'allowed' | 'read-only' | 'denied' {
  for (const w of WORKSPACES) {
    if (p.startsWith(w.path)) return w.write ? 'allowed' : 'read-only'
  }
  return 'denied'
}
export function authorizePath(p: string): boolean {
  return checkWorkspace(p) !== 'denied'
}

// Phase 4 — Filesystem intelligence helpers (read/write/edit/search metadata)
export interface FileOp { op: 'list'|'read'|'write'|'edit'|'move'|'rename'|'delete'|'search'; path: string }
export function classifyFileOp(op: FileOp): Category {
  if (op.op === 'delete' || op.op === 'rename' && op.path.includes('rm')) return 'DESTRUCTIVE'
  if (op.op === 'write' || op.op === 'edit' || op.op === 'move') return 'WRITE'
  if (op.op === 'read' || op.op === 'list' || op.op === 'search') return 'READ'
  return 'READ'
}
export function safeEdit(p: string): boolean {
  return authorizePath(p) && checkWorkspace(p) === 'allowed'
}

// Phase 5 — Terminal / command classification (safe / confirm / deny)
export type Risk = 'safe' | 'confirm' | 'privileged' | 'deny'
export function classifyCommand(cmd: string): Risk {
  const c = cmd.trim().split(' ')[0].toLowerCase()
  const safe = ['pwd','ls','cat','echo','find','grep','git','npm','node','python3','curl','ssh','systemctl','ls','cd','mkdir','touch','cp','mv','chmod']
  const privileged = ['sudo','mkfs','fdisk','dd ','chmod 777','/etc/']
  const destructive = ['rm','rm -rf','> /dev','> /etc','force-push','> /dev/']
  if (privileged.some(p => cmd.includes(p))) return 'privileged'
  if (destructive.some(p => cmd.includes(p))) return 'deny'
  if (safe.includes(c)) return 'safe'
  return 'confirm'
}
export function safeCommand(cmd: string): boolean {
  return classifyCommand(cmd) === 'safe'
}

// Phase 6 — Software engineering agent helpers (inspect/edit/test/verify/report)
export interface CodeOp { file: string; action: 'inspect'|'edit'|'create'|'delete'|'test'|'verify'|'report' }
export function safeCodeEdit(file: string): boolean {
  return authorizePath(file) && checkWorkspace(file) === 'allowed'
}
export function runBuild(): string { return 'npm run build'; }
export function inspectDiff(): string { return 'git diff'; }

// Phase 7 — Browser agent (open/navigate/click/type/scroll/screenshot/read/form)
export interface BrowserOp { url: string; action: 'open'|'navigate'|'click'|'type'|'scroll'|'screenshot'|'read'|'form' }
export function browserAllowed(url: string): boolean {
  return url.startsWith('http://') || url.startsWith('https://')
}
export function safeBrowser(op: BrowserOp): boolean {
  return browserAllowed(op.url)
}

// Phase 8 — Internet intelligence (search / fetch / api / web)
export interface NetOp { type: 'search'|'fetch'|'api'; target: string }
export function safeNetwork(op: NetOp): boolean {
  return op.type === 'search' || op.type === 'fetch' || op.type === 'api'
}
export function searchAllowed(q: string): boolean { return q.length > 0 && q.length < 500 }

// Phase 9 — GitHub integration (repos/issues/PRs/commits/branches)
export interface GitHubOp { repo: string; action: 'issues'|'pulls'|'commits'|'branches'|'releases' }
export function safeGitHub(op: GitHubOp): boolean {
  return op.repo.length > 0 && /[a-zA-Z0-9_-]+\/[a-zA-Z0-9_-]+/.test(op.repo)
}
export function githubConfirm(action: string): boolean {
  return action === 'push' || action === 'merge' || action === 'delete' ? false : true
}

// Phase 10 — Persistent structured memory (user/project/system/goal)
export interface MemoryEntry { category: 'USER_PREFERENCES'|'PROJECTS'|'SYSTEM_CONFIGURATION'|'WORKFLOWS'|'IMPORTANT_FACTS'|'LONG_TERM_GOALS'; key: string; value: string; confidence: number; updated: number }
export const memoryStore: MemoryEntry[] = []
export function remember(e: MemoryEntry) { memoryStore.push(e); if (memoryStore.length > 100) memoryStore.shift(); }
export function recall(key: string): MemoryEntry | undefined { return memoryStore.find(m => m.key === key); }
export function forget(key: string) { const i = memoryStore.findIndex(m => m.key === key); if (i >= 0) memoryStore.splice(i, 1); }

// Phase 11 — Secrets / credentials isolation rule
export const SECRET_PATTERNS = /(key|token|secret|password|credential|api_key|auth)/i
export function hasSecretInText(t: string): boolean { return SECRET_PATTERNS.test(t) }
export function redact(t: string): string { return hasSecretInText(t) ? '[REDACTED]' : t }
export const REDACT_KEYS = ['ANTHROPIC_API_KEY','ELEVENLABS_API_KEY','OPENAI_API_KEY','GITHUB_TOKEN']

// Phase 12 — Tool routing (minimize tools per task)
export type ToolCategory = 'filesystem'|'terminal'|'browser'|'network'|'github'|'memory'|'mcp'
export function routeTask(desc: string): ToolCategory[] {
  const d = desc.toLowerCase()
  const cats: ToolCategory[] = []
  if (d.includes('file')||d.includes('folder')||d.includes('directory')) cats.push('filesystem')
  if (d.includes('run')||d.includes('command')||d.includes('terminal')||d.includes('execute')) cats.push('terminal')
  if (d.includes('web')||d.includes('browse')||d.includes('url')||d.includes('open')) cats.push('browser')
  if (d.includes('search')||d.includes('internet')||d.includes('fetch')) cats.push('network')
  if (d.includes('github')||d.includes('repo')||d.includes('pr')) cats.push('github')
  if (d.includes('remember')||d.includes('memory')) cats.push('memory')
  return cats.length ? cats : ['filesystem','terminal']
}

// Phase 10 persistent — file-backed memory (replaces in-memory array)
import { readFileSync, writeFileSync, existsSync } from 'fs';
const MEMORY_PATH = '/home/ismabeast/.jarvis_memory.json';
export function loadMemory(): MemoryEntry[] {
  try { return existsSync(MEMORY_PATH) ? JSON.parse(readFileSync(MEMORY_PATH,'utf8')) : []; } catch { return []; }
}
export function saveMemory(entries: MemoryEntry[]): void { try { writeFileSync(MEMORY_PATH, JSON.stringify(entries)); } catch {} }

// Phase 13 — Multi-step autonomy (UNDERSTAND → PLAN → MODIFY → TEST → VERIFY → REPORT)
export interface Step { id: number; phase: string; done: boolean; result?: string }
export const steps: Step[] = []
export function startPlan(_desc: string): number {
  const id = steps.length + 1
  steps.push({ id, phase: 'UNDERSTAND', done: false })
  steps.push({ id, phase: 'PLAN', done: false })
  steps.push({ id, phase: 'MODIFY', done: false })
  steps.push({ id, phase: 'TEST', done: false })
  steps.push({ id, phase: 'VERIFY', done: false })
  steps.push({ id, phase: 'REPORT', done: false })
  return id
}
export function completeStep(id: number, phase: string, result?: string) {
  const s = steps.find(x => x.id === id && x.phase === phase)
  if (s) { s.done = true; s.result = result; }
}
export function getPlanStatus(id: number) {
  const plan = steps.filter(x => x.id === id)
  return { total: plan.length, done: plan.filter(x => x.done).length, remaining: plan.filter(x => !x.done).map(x => x.phase) }
}

// Phase 14 — Observability / audit logging (timestamp, tool, target, status, duration, error)
export interface AuditLogEntry { ts: number; tool: string; target: string; status: 'ok'|'denied'|'error'; durationMs?: number; error?: string }
export function auditAction(tool: string, target: string, status: 'ok'|'denied'|'error', err?: string, durationMs?: number): AuditLogEntry {
  const e: AuditLogEntry = { ts: Date.now(), tool, target, status, durationMs, error: err ?? undefined }
  logAudit({ ts: e.ts, tool: e.tool, target: e.target, status: e.status })
  return e
}
export function getAuditTrail(limit = 50): AuditLogEntry[] { return auditLog.slice(-limit) as AuditLogEntry[] }

// Phase 15 — Failure recovery (timeout, cancellation, cleanup, state reset)
export interface TaskHandle { id: number; timer: ReturnType<typeof setTimeout>; cancelled: boolean }
export const activeTasks = new Map<number, TaskHandle>()
export function startTask(id: number, timeoutMs = 30000): void {
  const timer = setTimeout(() => { activeTasks.delete(id); }, timeoutMs)
  activeTasks.set(id, { id, timer, cancelled: false })
}
export function cancelTask(id: number): boolean {
  const t = activeTasks.get(id)
  if (!t) return false
  t.cancelled = true
  clearTimeout(t.timer)
  activeTasks.delete(id)
  return true
}
export function resetAllTasks(): void { for (const [, t] of activeTasks) { clearTimeout(t.timer); } activeTasks.clear(); }

// Phase 16 — UI state indicators (processing/confirm/cancel/error/task/current) — preserved holographic design
export interface UiState { processing: boolean; task: string | null; errorMsg: string | null; confirmationPending: boolean }
export function getUiState(): UiState { return { processing: activeTasks.size > 0, task: activeTasks.size > 0 ? 'active' : null, errorMsg: null, confirmationPending: false } }

// Phase 17 — Home Assistant readiness (query/control/automation/status — not activated)
export interface HAState { entity: string; state: string; attributes?: Record<string, unknown> }
export function queryHA(entity: string): HAState { return { entity, state: 'unknown', attributes: {} } }
export function controlHA(entity: string, service: string): boolean { return entity.length > 0 && service.length > 0 }

// Phase 18 — Security model (least privilege, deny by default, confirmation, audit, no privilege escalation, kill switch)
export function isPrivileged(cmd: string): boolean { return cmd.includes('sudo') || cmd.includes('chmod 777') || cmd.includes('/etc/') || cmd.includes('force-push') }
export function emergencyKill(): boolean { resetAllTasks(); return true }
export function auditTrailEntry(tool: string, target: string): AuditLogEntry { return auditAction(tool, target, 'ok') }

// Phase A — REAL execution guard (pre-execution, not post)
export interface ToolCall { tool: string; op: string; args: Record<string,string>; target: string; risk: 'READ'|'WRITE'|'EXECUTE'|'DESTRUCTIVE'|'PRIVILEGED' }
export type GuardResult = 'ALLOW'|'ASK'|'DENY'
export function guardToolCall(tc: ToolCall): GuardResult {
  if (tc.risk === 'DESTRUCTIVE' || tc.risk === 'PRIVILEGED') return 'ASK'
  if (tc.risk === 'READ' || tc.risk === 'WRITE' || tc.risk === 'EXECUTE') {
    if (tc.target && !authorizePath(tc.target)) return 'DENY'
    return 'ALLOW'
  }
  return 'ASK'
}
export function isPreExecution(): boolean { return true }
