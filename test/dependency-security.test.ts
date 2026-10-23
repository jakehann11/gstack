/** Offline integration checks for the dependency security overrides. No model/API calls. */
import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import Anthropic from '@anthropic-ai/sdk';
import { createSdkMcpServer, tool } from '@anthropic-ai/claude-agent-sdk';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { z } from 'zod';
import { z as z3 } from 'zod/v3';
import proxyaddr from 'proxy-addr';
import { callJudge } from './helpers/llm-judge';

describe('security dependency compatibility', () => {
  test('mapped IPv6 trust cannot make an arbitrary IPv4 peer a trusted proxy', () => {
    // GHSA-jqcg-44mw-7w3h: malformed trust prefixes used to accept every IPv4 peer.
    const request = { socket: { remoteAddress: '203.0.113.9' }, headers: { 'x-forwarded-for': '127.0.0.1' } };
    for (const subnet of ['::ffff:10.0.0.0/8', '::/1']) {
      expect(proxyaddr(request, proxyaddr.compile(subnet))).toBe('203.0.113.9');
    }
    for (const subnet of ['10.0.0.0/8', '::ffff:10.0.0.0/104']) {
      const trusted = { ...request, socket: { remoteAddress: '10.1.2.3' } };
      expect(proxyaddr(trusted, proxyaddr.compile(subnet))).toBe('127.0.0.1');
      expect(proxyaddr(request, proxyaddr.compile(subnet))).toBe('203.0.113.9');
    }
  });

  test('lockfile eliminates vulnerable archive chain and preserves pinned Agent SDK', () => {
    const lock = Bun.JSONC.parse(readFileSync(new URL('../bun.lock', import.meta.url), 'utf8'));
    const versions = Object.values(lock.packages).map((entry: any) => entry[0]);
    expect(versions).toContain('@anthropic-ai/claude-agent-sdk@0.2.117');
    expect(versions).toContain('@anthropic-ai/sdk@0.91.1');
    expect(versions).toContain('diff@8.0.3');
    expect(versions.some((v: any) => v.startsWith('extract-zip@'))).toBe(false);
    // Overrides must cover nested copies too, not merely the root installation.
    for (const [name, version] of Object.entries(lock.overrides)) {
      for (const resolved of versions as string[]) {
        if (resolved.startsWith(name + '@')) expect(resolved).toBe(`${name}@${version}`);
      }
    }
  });

  test('Agent SDK tool schema preserves constraints through the Zod 3 compatibility entry point', async () => {
    let calls = 0;
    const config = createSdkMcpServer({ name: 'offline-security-test', tools: [
      tool('double', 'Double a bounded number', { value: z3.number().int().min(0).max(10) }, async ({ value }) => {
        calls++;
        return { content: [{ type: 'text', text: String(value * 2) }] };
      }),
    ] });
    const client = new Client({ name: 'offline-test', version: '1' });
    const [a, b] = InMemoryTransport.createLinkedPair();
    try {
      await config.instance.connect(a);
      await client.connect(b);
      const list = await client.listTools();
      expect(list.tools[0].inputSchema.properties?.value).toMatchObject({ type: 'integer', minimum: 0, maximum: 10 });
      const good = await client.callTool({ name: 'double', arguments: { value: 4 } });
      expect(good.content).toEqual([{ type: 'text', text: '8' }]);
      const bad = await client.callTool({ name: 'double', arguments: { value: '4' } });
      expect(bad.isError).toBe(true);
      expect((await client.callTool({ name: 'double', arguments: { value: -1 } })).isError).toBe(true);
      expect((await client.callTool({ name: 'double', arguments: { value: 1.5 } })).isError).toBe(true);
      expect(calls).toBe(1);
    } finally {
      await client.close();
      await config.instance.close();
    }
  });

  test.each([['v3', z3], ['v4', z]] as const)('standalone MCP preserves and validates Zod %s schemas', async (_version, schema) => {
    const server = new McpServer({ name: 'offline-v3', version: '1' });
    server.registerTool('echo', { inputSchema: { text: schema.string().min(1) } }, async ({ text }) => ({
      content: [{ type: 'text', text }],
    }));
    const client = new Client({ name: 'offline-test', version: '1' });
    const [a, b] = InMemoryTransport.createLinkedPair();
    try {
      await server.connect(a);
      await client.connect(b);
      expect((await client.listTools()).tools[0].inputSchema.properties?.text).toMatchObject({ type: 'string', minLength: 1 });
      expect((await client.callTool({ name: 'echo', arguments: { text: 'hello' } })).content).toEqual([{ type: 'text', text: 'hello' }]);
      expect((await client.callTool({ name: 'echo', arguments: { text: '' } })).isError).toBe(true);
    } finally {
      await client.close();
      await server.close();
    }
  });

  test('Anthropic request serialization and rate-limit errors work with an offline transport', async () => {
    let payload: any;
    let status = 200;
    const client = new Anthropic({ apiKey: 'offline-placeholder', maxRetries: 0, fetch: async (_url, init) => {
      payload = JSON.parse(String(init?.body));
      return Response.json(status === 200 ? {
        id: 'offline', type: 'message', role: 'assistant', model: 'offline',
        content: [{ type: 'text', text: '{"score":5}' }], stop_reason: 'end_turn', stop_sequence: null,
        usage: { input_tokens: 1, output_tokens: 1 },
      } : { type: 'error', error: { type: 'rate_limit_error', message: 'offline limit' } }, { status });
    } });
    const request = { model: 'offline', max_tokens: 10, messages: [{ role: 'user' as const, content: 'test' }] };
    expect((await client.messages.create(request)).content[0]).toEqual({ type: 'text', text: '{"score":5}' });
    expect(payload).toEqual(request);
    status = 429;
    // Normalize the SDK's APIPromise thenable for Bun's rejection matcher.
    await expect(Promise.resolve(client.messages.create(request))).rejects.toMatchObject({ status: 429 });
  });

  test('native image, tokenizer, ONNX inference and archive contracts work offline under Node', () => {
    const result = spawnSync('node', [fileURLToPath(new URL('./helpers/dependency-native-probe.mjs', import.meta.url))], {
      encoding: 'utf8', timeout: 45000,
    });
    expect({ status: result.status, stderr: result.stderr, error: result.error?.message }).toEqual({ status: 0, stderr: '', error: undefined });
    expect(result.stdout).toContain('offline native compatibility passed');
  }, 50000);

  test('actual judge helper parses, rejects malformed output, and retries 429 using only mocked fetch', async () => {
    const originalFetch = globalThis.fetch;
    const originalKey = process.env.ANTHROPIC_API_KEY;
    let text = '{"score":5}';
    let rejected = 0;
    process.env.ANTHROPIC_API_KEY = 'offline-placeholder';
    globalThis.fetch = (async () => {
      if (rejected > 0) {
        rejected--;
        return Response.json({ type: 'error', error: { type: 'rate_limit_error', message: 'offline' } }, {
          status: 429, headers: { 'retry-after-ms': '1' },
        });
      }
      return Response.json({ id: 'offline', type: 'message', role: 'assistant', model: 'offline',
        content: [{ type: 'text', text }], stop_reason: 'end_turn', stop_sequence: null,
        usage: { input_tokens: 1, output_tokens: 1 },
      });
    }) as typeof fetch;
    try {
      expect(await callJudge('offline', 'offline')).toEqual({ score: 5 });
      text = 'invalid output';
      await expect(callJudge('offline', 'offline')).rejects.toThrow('Judge returned non-JSON');
      text = '{"score":4}';
      rejected = 3; // Exhaust the SDK's two internal retries, then exercise callJudge's retry.
      expect(await callJudge('offline', 'offline')).toEqual({ score: 4 });
      expect(rejected).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
      if (originalKey === undefined) delete process.env.ANTHROPIC_API_KEY;
      else process.env.ANTHROPIC_API_KEY = originalKey;
    }
  });
});
