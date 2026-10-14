import { createSdkMcpServer, tool } from '@anthropic-ai/claude-agent-sdk'
import { z } from 'zod'
import { exec } from 'node:child_process'
import { promisify } from 'node:util'

import { guardToolCall, auditAction, redact, ALLOW, ASK, DENY } from '../shared/permissions.mjs'

const execAsync = promisify(exec)

export const terminalServer = createSdkMcpServer({
  name: 'jarvis_terminal',
  version: '1.0.0',
  instructions: 'Safe terminal execution for JARVIS. Pre-execution guard required.',
  alwaysLoad: true,
  tools: [
    tool('shell', 'Execute a terminal command.', {
      command: z.string().describe('Command to run'),
      cwd: z.string().optional().default('/home/ismabeast').describe('Working directory'),
      timeout: z.number().optional().default(10000).describe('Timeout ms'),
    }, async (args) => {
      // Pre-execution guard — MUST run BEFORE spawn
      const guard = guardToolCall({ tool: 'shell', op: 'execute', args: args, target: String(args.cwd ?? ''), risk: 'EXECUTE' })
      const reqId = args._reqId || (`t-${Date.now()}`)
      if (guard === DENY) {
        auditAction('shell', args.command, 'denied', undefined, 0)
        return { isError: true, content: [{ type: 'text', text: 'Blocked by guard: destructive/privileged.' }] }
      }
      if (guard === ASK) {
        auditAction('shell', args.command, 'ask', undefined, 0)
        return { isError: true, content: [{ type: 'text', text: 'Requires confirmation: ' + args.command + ' (id=' + reqId + ')' }] }
      }

      try {
        const { stdout, stderr } = await execAsync(args.command, { cwd: args.cwd, timeout: args.timeout })
        return { content: [{ type: 'text', text: `exit 0\n${stdout}${stderr ? '\nERR:'+stderr : ''}` }] }
      } catch (err) {
        return { isError: true, content: [{ type: 'text', text: `exit ${(err).code ?? 1}\n${(err)?.message ?? String(err)}` }] }
      }
    }),
  ],
})
