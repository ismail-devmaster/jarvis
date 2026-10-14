import { createSdkMcpServer, tool } from '@anthropic-ai/claude-agent-sdk'
import { z } from 'zod'
import { readdir, readFile, writeFile, unlink, rename, mkdir, stat, lstat } from 'node:fs/promises'
import { realpath } from 'node:fs/promises'
import { join, normalize } from 'node:path'
import { guardToolCall, auditAction, redact, ALLOW, ASK, DENY } from '../shared/permissions.mjs'

export const READONLY = ['/home/ismabeast/Desktop']
export const WRITABLE = ['/home/ismabeast/Projects', '/home/ismabeast/jarvis']

const MAX_READ_BYTES = 200_000
const MAX_SEARCH_RESULTS = 100

function classifyPath(p) {
  if (!p) return 'deny'
  const norm = normalize(p).replace(/\/+$/, '') || '/'
  if (norm.startsWith('/root') || norm.startsWith('/etc') || norm.startsWith('/var') ||
      norm.startsWith('/sys') || norm.startsWith('/proc') || norm.startsWith('/dev')) return 'deny'
  if (norm.includes('/.ssh') || norm.includes('/.aws') || norm.includes('/.gnupg') ||
      norm.includes('credential') || norm.includes('/key') || norm.includes('.env') || norm.includes('secret')) return 'deny'
  if (READONLY.some(r => norm === r || norm.startsWith(r + '/'))) return 'readonly'
  if (WRITABLE.some(r => norm === r || norm.startsWith(r + '/'))) return 'writable'
  return 'deny'
}

async function resolved(p) {
  try { return await realpath(p) } catch { return normalize(p) }
}

async function guard(op, path, extra) {
  const r = await resolved(path)
  const cls = classifyPath(r)
  if (cls === 'deny') return { decision: DENY, resolved: r }
  const g = guardToolCall({ tool: 'filesystem', op, args: { path, ...extra }, target: r, risk: cls === 'writable' ? 'WRITE' : 'READ' })
  return { decision: g, resolved: r, cls }
}

export const fsServer = createSdkMcpServer({
  name: 'jarvis_filesystem',
  version: '1.0.0',
  instructions: 'Filesystem tool for JARVIS. Pre-execution guard required.',
  alwaysLoad: true,
  tools: [
    tool('list', 'List directory contents.', { path: z.string() }, async (args) => {
      const { decision, resolved: r } = await guard('list', args.path)
      if (decision === DENY) return { isError: true, content: [{ type: 'text', text: 'Denied: path not authorized.' }] }
      const entries = await readdir(r, { withFileTypes: true })
      return { content: [{ type: 'text', text: entries.map(e => (e.isDirectory() ? 'd' : '-') + ' ' + e.name).join('\n') }] }
    }),
    tool('read', 'Read a file.', { path: z.string(), limit: z.number().optional().default(5000) }, async (args) => {
      const { decision, resolved: r } = await guard('read', args.path)
      if (decision === DENY) return { isError: true, content: [{ type: 'text', text: 'Denied: path not authorized.' }] }
      const st = await stat(r)
      if (st.size > 10_000_000) return { isError: true, content: [{ type: 'text', text: 'File too large (' + st.size + ' bytes).' }] }
      const data = await readFile(r, { encoding: 'utf-8' })
      return { content: [{ type: 'text', text: data.slice(0, args.limit ?? 5000) }] }
    }),
    tool('write', 'Write a file.', { path: z.string(), content: z.string() }, async (args) => {
      const { decision, resolved: r } = await guard('write', args.path)
      if (decision === DENY) return { isError: true, content: [{ type: 'text', text: 'Denied: path not authorized.' }] }
      await writeFile(r, args.content, 'utf-8')
      auditAction('filesystem', r, 'ok', undefined, 0)
      return { content: [{ type: 'text', text: 'wrote ' + r + ' (' + Buffer.byteLength(args.content) + ' bytes)' }] }
    }),
    tool('delete', 'Delete a file.', { path: z.string() }, async (args) => {
      const { decision, resolved: r } = await guard('delete', args.path)
      if (decision === DENY) return { isError: true, content: [{ type: 'text', text: 'Denied: path not authorized.' }] }
      await unlink(r)
      auditAction('filesystem', r, 'ok', undefined, 0)
      return { content: [{ type: 'text', text: 'deleted ' + r }] }
    }),
    tool('move', 'Move/rename a file.', { src: z.string(), dst: z.string() }, async (args) => {
      const g1 = await guard('move', args.src)
      if (g1.decision === DENY) return { isError: true, content: [{ type: 'text', text: 'Denied: source not authorized.' }] }
      const g2 = await guard('move', args.dst)
      if (g2.decision === DENY) return { isError: true, content: [{ type: 'text', text: 'Denied: destination not authorized.' }] }
      await rename(g1.resolved, g2.resolved)
      auditAction('filesystem', args.src + '->' + args.dst, 'ok', undefined, 0)
      return { content: [{ type: 'text', text: 'moved' }] }
    }),
    tool('search', 'Search files by name pattern.', { path: z.string(), pattern: z.string() }, async (args) => {
      const { decision, resolved: r } = await guard('search', args.path)
      if (decision === DENY) return { isError: true, content: [{ type: 'text', text: 'Denied: path not authorized.' }] }
      const matches = []
      async function walk(dir, depth) {
        if (depth > 5 || matches.length >= MAX_SEARCH_RESULTS) return
        let entries
        try { entries = await readdir(dir, { withFileTypes: true }) } catch { return }
        for (const e of entries) {
          if (e.name.includes(args.pattern)) matches.push(join(dir, e.name))
          if (e.isDirectory()) await walk(join(dir, e.name), depth + 1)
        }
      }
      await walk(r, 0)
      auditAction('filesystem', args.path, 'ok', undefined, 0)
      return { content: [{ type: 'text', text: matches.slice(0, MAX_SEARCH_RESULTS).join('\n') || 'no matches' }] }
    }),
  ],
})
