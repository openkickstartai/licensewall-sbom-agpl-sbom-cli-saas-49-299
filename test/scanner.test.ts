import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
  checkPolicy,
  generateSBOM,
  scanNodeModules,
  scanDeep,
  detectLicenseFromFile,
  Dep,
  ScannedDep,
  Policy,
} from '../src/scanner.js';
import { mkdirSync, writeFileSync, rmSync } from 'fs';
import { join, resolve } from 'path';
import { tmpdir } from 'os';

const mockDeps: Dep[] = [
  { name: 'express', version: '4.18.2', license: 'MIT', path: '/x' },
  { name: 'react', version: '18.2.0', license: 'MIT', path: '/x' },
  { name: 'viral-lib', version: '1.0.0', license: 'AGPL-3.0-only', path: '/x' },
  { name: 'mystery', version: '0.1.0', license: 'UNKNOWN', path: '/x' },
];

describe('checkPolicy — deny list', () => {
  it('flags denied AGPL license', () => {
    const v = checkPolicy(mockDeps, { deny: ['AGPL-3.0'] });
    expect(v.some((x) => x.dep.name === 'viral-lib')).toBe(true);
    expect(v.some((x) => x.dep.name === 'express')).toBe(false);
  });

  it('always flags UNKNOWN licenses', () => {
    const v = checkPolicy(mockDeps, { deny: ['AGPL-3.0'] });
    expect(v.some((x) => x.dep.license === 'UNKNOWN')).toBe(true);
  });
});

describe('checkPolicy — allow list', () => {
  it('flags licenses not in allow list', () => {
    const v = checkPolicy(mockDeps, { allow: ['MIT', 'Apache-2.0'] });
    const violatedNames = v.map((x) => x.dep.name);
    expect(violatedNames).toContain('viral-lib');
    expect(violatedNames).toContain('mystery');
    expect(violatedNames).not.toContain('express');
  });

  it('passes when all licenses are allowed', () => {
    const clean: Dep[] = [
      { name: 'a', version: '1.0.0', license: 'MIT', path: '/x' },
      { name: 'b', version: '2.0.0', license: 'Apache-2.0', path: '/x' },
    ];
    const v = checkPolicy(clean, { allow: ['MIT', 'Apache-2.0'] });
    expect(v).toHaveLength(0);
  });

  it('returns no violations with empty policy on clean deps', () => {
    const clean: Dep[] = [
      { name: 'a', version: '1.0.0', license: 'MIT', path: '/x' },
    ];
    const v = checkPolicy(clean, {});
    expect(v).toHaveLength(0);
  });
});

describe('scanNodeModules', () => {
  const tmpDir = join(tmpdir(), 'lw-test-' + Date.now());

  beforeAll(() => {
    mkdirSync(join(tmpDir, 'node_modules', 'foo'), { recursive: true });
    writeFileSync(
      join(tmpDir, 'node_modules', 'foo', 'package.json'),
      JSON.stringify({ name: 'foo', version: '1.0.0', license: 'MIT' }),
    );
    mkdirSync(join(tmpDir, 'node_modules', '@bar', 'baz'), { recursive: true });
    writeFileSync(
      join(tmpDir, 'node_modules', '@bar', 'baz', 'package.json'),
      JSON.stringify({ name: '@bar/baz', version: '2.0.0', license: 'ISC' }),
    );
  });

  afterAll(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('discovers top-level deps', () => {
    const deps = scanNodeModules(tmpDir);
    expect(deps.length).toBe(2);
    expect(deps.some((d) => d.name === 'foo')).toBe(true);
    expect(deps.some((d) => d.name === '@bar/baz')).toBe(true);
  });

  it('returns empty for missing node_modules', () => {
    const deps = scanNodeModules('/nonexistent/path');
    expect(deps).toHaveLength(0);
  });
});

describe('generateSBOM', () => {
  it('generates valid CycloneDX structure', () => {
    const deps: Dep[] = [{ name: 'x', version: '1.0.0', license: 'MIT', path: '/x' }];
    const sbom = generateSBOM(deps) as any;
    expect(sbom.bomFormat).toBe('CycloneDX');
    expect(sbom.specVersion).toBe('1.5');
    expect(sbom.components).toHaveLength(1);
    expect(sbom.components[0].name).toBe('x');
    expect(sbom.components[0].purl).toBe('pkg:npm/x@1.0.0');
  });
});

// ─── New tests: scanDeep, detectLicenseFromFile, ScannedDep ──────────────────

const fixtureDir = resolve(__dirname, 'fixtures', 'fake-project');

describe('detectLicenseFromFile', () => {
  it('detects MIT license from LICENSE file', () => {
    const depPath = join(fixtureDir, 'node_modules', 'dep-b');
    const result = detectLicenseFromFile(depPath);
    expect(result).toBe('MIT');
  });

  it('returns null when no license file exists', () => {
    const depPath = join(fixtureDir, 'node_modules', 'dep-no-license');
    const result = detectLicenseFromFile(depPath);
    expect(result).toBeNull();
  });

  it('returns null for nonexistent directory', () => {
    const result = detectLicenseFromFile('/totally/fake/path');
    expect(result).toBeNull();
  });
});

describe('scanDeep', () => {
  let results: ScannedDep[];

  beforeAll(() => {
    results = scanDeep(fixtureDir);
  });

  it('discovers all direct dependencies at depth 0', () => {
    const directNames = results.filter((d) => d.depth === 0).map((d) => d.name);
    expect(directNames).toContain('dep-a');
    expect(directNames).toContain('dep-b');
    expect(directNames).toContain('dep-d');
    expect(directNames).toContain('@scope/scoped-pkg');
    expect(directNames).toContain('dep-no-license');
  });

  it('discovers transitive dependency dep-c', () => {
    const depC = results.find((d) => d.name === 'dep-c');
    expect(depC).toBeDefined();
    expect(depC!.version).toBe('2.0.0');
    expect(depC!.license).toBe('ISC');
  });

  it('deduplicates dep-c (appears under dep-a and dep-d)', () => {
    const depCs = results.filter((d) => d.name === 'dep-c');
    expect(depCs).toHaveLength(1);
  });

  it('sets correct depth for transitive deps', () => {
    const depC = results.find((d) => d.name === 'dep-c');
    expect(depC).toBeDefined();
    expect(depC!.depth).toBe(1);
  });

  it('populates dependedBy with all parent packages', () => {
    const depC = results.find((d) => d.name === 'dep-c');
    expect(depC).toBeDefined();
    expect(depC!.dependedBy).toContain('dep-a');
    expect(depC!.dependedBy).toContain('dep-d');
    expect(depC!.dependedBy).toHaveLength(2);
  });

  it('uses detectLicenseFromFile fallback for dep-b (no license in package.json)', () => {
    const depB = results.find((d) => d.name === 'dep-b');
    expect(depB).toBeDefined();
    expect(depB!.license).toBe('MIT');
  });

  it('marks dep-no-license as UNKNOWN when no license field and no LICENSE file', () => {
    const depNone = results.find((d) => d.name === 'dep-no-license');
    expect(depNone).toBeDefined();
    expect(depNone!.license).toBe('UNKNOWN');
  });

  it('handles scoped packages correctly', () => {
    const scoped = results.find((d) => d.name === '@scope/scoped-pkg');
    expect(scoped).toBeDefined();
    expect(scoped!.version).toBe('0.5.0');
    expect(scoped!.license).toBe('BSD-3-Clause');
    expect(scoped!.depth).toBe(0);
  });

  it('returns correct total count (6 unique deps)', () => {
    // dep-a, dep-b, dep-c (deduped), dep-d, @scope/scoped-pkg, dep-no-license
    expect(results).toHaveLength(6);
  });
});
