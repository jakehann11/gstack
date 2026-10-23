import { describe, expect, test } from 'bun:test';
import { diffLines } from 'diff';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';

const diffModule = createRequire(import.meta.url).resolve('diff');

describe('diff dependency security and browse compatibility', () => {
  // Isolate parser probes so a vulnerable version cannot hang or exhaust the test runner.
  for (const separator of ['\r', '\u2028', '\u2029']) {
    test(`patch headers containing ${JSON.stringify(separator)} terminate and apply correctly`, () => {
      const script = `
        const { parsePatch, applyPatch } = require(process.argv[1]);
        const separator = JSON.parse(process.argv[2]);
        const patch = '--- before' + separator + 'suffix\\n' +
          '+++ after' + separator + 'suffix\\n@@ -1 +1 @@\\n-old\\n+new\\n';
        const parsed = parsePatch(patch);
        process.stdout.write(JSON.stringify({
          count: parsed.length,
          oldFileName: parsed[0].oldFileName,
          newFileName: parsed[0].newFileName,
          applied: applyPatch('old\\n', patch),
        }));
      `;
      const result = spawnSync('node', ['--max-old-space-size=64', '-e', script,
        diffModule, JSON.stringify(separator)], { encoding: 'utf8', timeout: 2000 });
      expect(result.error).toBeUndefined();
      expect(result.status).toBe(0);
      expect(JSON.parse(result.stdout)).toEqual({
        count: 1, oldFileName: `before${separator}suffix`,
        newFileName: `after${separator}suffix`, applied: 'new\n',
      });
    });
  }

  // Both browse consumers use only diffLines and its value/added/removed contract.
  for (const [before, after, expected] of [
    ['', '', []],
    ['', 'new\n', [{ count: 1, added: true, removed: false, value: 'new\n' }]],
    ['old\n', '', [{ count: 1, added: false, removed: true, value: 'old\n' }]],
    ['same\n', 'same\n', [{ count: 1, added: false, removed: false, value: 'same\n' }]],
    ['same\nold\n', 'same\nnew\n', [
      { count: 1, added: false, removed: false, value: 'same\n' },
      { count: 1, added: false, removed: true, value: 'old\n' },
      { count: 1, added: true, removed: false, value: 'new\n' },
    ]],
    ['café\r\n😀\r\n', 'café\r\nnew\r\n', [
      { count: 1, added: false, removed: false, value: 'café\r\n' },
      { count: 1, added: false, removed: true, value: '😀\r\n' },
      { count: 1, added: true, removed: false, value: 'new\r\n' },
    ]],
    ['no newline', 'changed', [
      { count: 1, added: false, removed: true, value: 'no newline' },
      { count: 1, added: true, removed: false, value: 'changed' },
    ]],
  ] as const) {
    test(`diffLines preserves browse output: ${JSON.stringify([before, after])}`, () => {
      expect(diffLines(before, after)).toEqual(expected);
    });
  }
});
