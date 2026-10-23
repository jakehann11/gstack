import { describe, expect, test } from 'bun:test';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import { spawnSync } from 'node:child_process';

const ROOT = resolve(import.meta.dir, '..');
const workflows = join(ROOT, '.github', 'workflows');
const bash = process.platform === 'win32'
  ? join(process.env.ProgramFiles ?? 'C:\\Program Files', 'Git', 'bin', 'bash.exe')
  : 'bash';
const load = (name: string): any => Bun.YAML.parse(readFileSync(join(workflows, name), 'utf8'));
const titleJob = load('pr-title-sync.yml').jobs.sync;

describe('workflow security boundaries', () => {
  test('all actions are immutable and checkout does not persist credentials', () => {
    for (const file of readdirSync(workflows).filter(f => f.endsWith('.yml'))) {
      const workflow = load(file);
      expect(workflow.permissions).toEqual({ contents: 'read' });
      for (const job of Object.values(workflow.jobs) as any[]) {
        for (const step of job.steps ?? []) {
          if (!step.uses) continue;
          expect(step.uses).toMatch(/^[\w.-]+\/[\w.-]+@[a-f0-9]{40}$/);
          if (step.uses.startsWith('actions/checkout@')) expect(step.with['persist-credentials']).toBe(false);
        }
      }
    }
  });

  test('paid and package-publishing jobs cannot run on a personal fork', () => {
    for (const file of ['evals.yml', 'evals-periodic.yml', 'ci-image.yml']) {
      for (const job of Object.values(load(file).jobs) as any[]) {
        expect(job.if).toContain("github.repository == 'garrytan/gstack'");
      }
    }
  });

  test('title writer checks out immutable base, skips external fork PRs', () => {
    expect(titleJob.steps[0].with.ref).toBe('${{ github.event.pull_request.base.sha }}');
    expect(titleJob.if).toContain('github.event.pull_request.head.repo.full_name == github.repository');
  });

  for (const [version, title, expected] of [
    ['2.3.4', 'feat: ordinary', 'v2.3.4 feat: ordinary'],
    ['2.3.4', 'v1.2.3 fix: ordinary', 'v2.3.4 fix: ordinary'],
    ['2.3.4', 'v2.3.4 unchanged', null],
    ['2.3.4', '$(touch TITLE_INJECTION); `touch TITLE_BACKTICK`', 'v2.3.4 $(touch TITLE_INJECTION); `touch TITLE_BACKTICK`'],
    ['2.3.4;touch VERSION_INJECTION', 'invalid', false],
  ] as const) {
    test(`trusted helper with untrusted VERSION and title: ${title}`, () => {
      const dir = mkdtempSync(join(tmpdir(), 'gstack-workflow-security-'));
      const git = (...args: string[]) => {
        const r = spawnSync('git', args, { cwd: dir, encoding: 'utf8' });
        expect(r.status).toBe(0);
        return r.stdout.trim();
      };
      git('init', '-q');
      git('config', 'user.email', 'test@example.invalid');
      git('config', 'user.name', 'Workflow Test');
      git('config', 'core.autocrlf', 'false');
      mkdirSync(join(dir, 'bin'));
      writeFileSync(join(dir, 'bin/gstack-pr-title-rewrite.sh'), readFileSync(join(ROOT, 'bin/gstack-pr-title-rewrite.sh')));
      writeFileSync(join(dir, 'VERSION'), '1.0.0\n');
      git('add', 'bin', 'VERSION'); git('commit', '-qm', 'trusted base');
      const base = git('rev-parse', 'HEAD');
      writeFileSync(join(dir, 'bin/gstack-pr-title-rewrite.sh'), '#!/bin/sh\ntouch HEAD_HELPER_EXECUTED\n');
      writeFileSync(join(dir, 'VERSION'), version + '\n');
      git('add', 'bin', 'VERSION'); git('commit', '-qm', 'untrusted PR head');
      const head = git('rev-parse', 'HEAD');
      git('checkout', '-q', base);
      git('remote', 'add', 'origin', '.');
      const script = titleJob.steps.find((s: any) => s.name === 'Rewrite PR title to match VERSION').run;
      // Exercise the real workflow script. Only the GitHub write command is mocked.
      const wrapper = 'gh() { printf "%s\\n" "$@" > gh-args; }; export -f gh\n' + script;
      const result = spawnSync(bash, ['-c', wrapper], {
        cwd: dir, encoding: 'utf8', timeout: 15000,
        env: { ...process.env, PR_HEAD_SHA: head, PR_NUM: '7', OLD_TITLE: title, GITHUB_REPOSITORY: 'owner/repo', GH_TOKEN: 'dummy' },
      });
      expect(existsSync(join(dir, 'HEAD_HELPER_EXECUTED'))).toBe(false);
      expect(existsSync(join(dir, 'TITLE_INJECTION'))).toBe(false);
      expect(existsSync(join(dir, 'TITLE_BACKTICK'))).toBe(false);
      expect(existsSync(join(dir, 'VERSION_INJECTION'))).toBe(false);
      if (expected === false) {
        expect(result.status).not.toBe(0);
        expect(existsSync(join(dir, 'gh-args'))).toBe(false);
      } else {
        expect(result.stderr.includes('error:')).toBe(false);
        expect(result.status).toBe(0);
        if (expected === null) expect(existsSync(join(dir, 'gh-args'))).toBe(false);
        else expect(readFileSync(join(dir, 'gh-args'), 'utf8')).toBe(`pr\nedit\n7\n--repo\nowner/repo\n--title\n${expected}\n`);
      }
    }, 30000);
  }

  test('version gate does not interpolate PR values or outputs into shell source', () => {
    for (const step of load('version-gate.yml').jobs.check.steps) {
      expect(step.run ?? '').not.toContain('${{');
    }
  });
});
