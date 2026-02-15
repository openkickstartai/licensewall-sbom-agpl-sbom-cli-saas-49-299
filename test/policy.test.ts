import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { loadPolicy, evaluatePolicy, Policy, PolicyResult } from '../src/policy.js';
import type { Dep } from '../src/scanner.js';
import { mkdirSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const makeDep = (name: string, license: string, version = '1.0.0'): Dep => ({
  name,
  version,
  license,
  path: '/mock',
});

describe('evaluatePolicy', () => {
  it('marks dependency as allowed when license is in allow list', () => {
    const policy: Policy = { allow: ['MIT', 'Apache-2.0'], deny: [], failOnUnknown: false };
    const deps = [makeDep('express', 'MIT'), makeDep('lodash', 'Apache-2.0')];
    const results = evaluatePolicy(policy, deps);
    expect(results[0].verdict).toBe('allowed');
    expect(results[1].verdict).toBe('allowed');
  });

  it('marks dependency as denied when license is in deny list', () => {
    const policy: Policy = { allow: [], deny: ['AGPL-3.0', 'GPL-3.0'], failOnUnknown: false };
    const deps = [makeDep('viral-lib', 'AGPL-3.0'), makeDep('gpl-thing', 'GPL-3.0')];
    const results = evaluatePolicy(policy, deps);
    expect(results[0].verdict).toBe('denied');
    expect(results[1].verdict).toBe('denied');
  });

  it('marks UNKNOWN license as unknown when failOnUnknown is true', () => {
    const policy: Policy = { allow: [], deny: [], failOnUnknown: true };
    const deps = [makeDep('mystery', 'UNKNOWN')];
    const results = evaluatePolicy(policy, deps);
    expect(results[0].verdict).toBe('unknown');
  });

  it('marks all dependencies as allowed with empty policy (no allow, no deny, failOnUnknown=false)', () => {
    const policy: Policy = { allow: [], deny: [], failOnUnknown: false };
    const deps = [
      makeDep('a', 'MIT'),
      makeDep('b', 'GPL-3.0'),
      makeDep('c', 'UNKNOWN'),
      makeDep('d', 'WTFPL'),
    ];
    const results = evaluatePolicy(policy, deps);
    expect(results.every((r) => r.verdict === 'allowed')).toBe(true);
  });

  it('handles SPDX OR expression — allows if any part is in allow list', () => {
    const policy: Policy = { allow: ['MIT'], deny: [], failOnUnknown: false };
    const deps = [makeDep('dual-licensed', 'MIT OR Apache-2.0')];
    const results = evaluatePolicy(policy, deps);
    expect(results[0].verdict).toBe('allowed');
  });

  it('handles SPDX OR expression — denies if any part is in deny list', () => {
    const policy: Policy = { allow: [], deny: ['GPL-3.0'], failOnUnknown: false };
    const deps = [makeDep('mixed', 'MIT OR GPL-3.0')];
    const results = evaluatePolicy(policy, deps);
    expect(results[0].verdict).toBe('denied');
  });

  it('marks license as unknown when not found in allow list', () => {
    const policy: Policy = { allow: ['MIT', 'Apache-2.0'], deny: [], failOnUnknown: false };
    const deps = [makeDep('weird', 'WTFPL')];
    const results = evaluatePolicy(policy, deps);
    expect(results[0].verdict).toBe('unknown');
  });

  it('deny takes precedence over allow when license is in both lists', () => {
    const policy: Policy = { allow: ['MIT', 'AGPL-3.0'], deny: ['AGPL-3.0'], failOnUnknown: false };
    const deps = [makeDep('conflict', 'AGPL-3.0')];
    const results = evaluatePolicy(policy, deps);
    expect(results[0].verdict).toBe('denied');
  });

  it('matches license prefix — AGPL-3.0-only is denied by AGPL-3.0 rule', () => {
    const policy: Policy = { allow: [], deny: ['AGPL-3.0'], failOnUnknown: false };
    const deps = [makeDep('strict-agpl', 'AGPL-3.0-only')];
    const results = evaluatePolicy(policy, deps);
    expect(results[0].verdict).toBe('denied');
  });

  it('UNKNOWN license is allowed when failOnUnknown is false and no allow list', () => {
    const policy: Policy = { allow: [], deny: [], failOnUnknown: false };
    const deps = [makeDep('mystery', 'UNKNOWN')];
    const results = evaluatePolicy(policy, deps);
    expect(results[0].verdict).toBe('allowed');
  });

  it('returns correct result shape with name, version, license, and verdict', () => {
    const policy: Policy = { allow: ['MIT'], deny: [], failOnUnknown: false };
    const deps = [makeDep('express', 'MIT', '4.18.2')];
    const results = evaluatePolicy(policy, deps);
    expect(results[0]).toEqual({
      name: 'express',
      version: '4.18.2',
      license: 'MIT',
      verdict: 'allowed',
    });
  });

  it('handles SPDX OR expression with allow list — second part matches', () => {
    const policy: Policy = { allow: ['Apache-2.0'], deny: [], failOnUnknown: false };
    const deps = [makeDep('dual', 'MIT OR Apache-2.0')];
    const results = evaluatePolicy(policy, deps);
    expect(results[0].verdict).toBe('allowed');
  });
});

describe('loadPolicy', () => {
  const tmpDir = join(tmpdir(), 'licensewall-policy-test-' + Date.now());

  beforeAll(() => {
    mkdirSync(tmpDir, { recursive: true });
  });

  afterAll(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('loads policy from .licensewallrc.json file', () => {
    const filePath = join(tmpDir, '.licensewallrc.json');
    writeFileSync(
      filePath,
      JSON.stringify({
        allow: ['MIT', 'Apache-2.0'],
        deny: ['AGPL-3.0'],
        failOnUnknown: true,
      })
    );
    const policy = loadPolicy(filePath);
    expect(policy.allow).toEqual(['MIT', 'Apache-2.0']);
    expect(policy.deny).toEqual(['AGPL-3.0']);
    expect(policy.failOnUnknown).toBe(true);
  });

  it('returns default empty policy when file does not exist', () => {
    const policy = loadPolicy(join(tmpDir, 'nonexistent.json'));
    expect(policy.allow).toEqual([]);
    expect(policy.deny).toEqual([]);
    expect(policy.failOnUnknown).toBe(false);
  });
});
