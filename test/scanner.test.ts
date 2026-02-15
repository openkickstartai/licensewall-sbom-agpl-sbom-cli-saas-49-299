import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { checkPolicy, generateSBOM, scanNodeModules, Dep, Policy } from '../src/scanner.js';
import { mkdirSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
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

  it('returns no violations with empty policy', () => {
    const clean: Dep[] = [
      { name: 'a', version: '1.0.0', license: 'MIT', path: '/x' },
    ];
    expect(checkPolicy(clean, {})).toHaveLength(0);
  });
});

describe('generateSBOM', () => {
  it('produces valid CycloneDX 1.5 SBOM', () => {
    const sbom = generateSBOM(mockDeps, 'my-app') as Record<string, any>;
    expect(sbom.bomFormat).toBe('CycloneDX');
    expect(sbom.specVersion).toBe('1.5');
    expect(sbom.components).toHaveLength(4);
    expect(sbom.components[0].purl).toBe('pkg:npm/express@4.18.2');
    expect(sbom.components[0].licenses[0].license.id).toBe('MIT');
    expect(sbom.metadata.component.name).toBe('my-app');
    expect(sbom.metadata.tools[0].name).toBe('licensewall');
  });
});

describe('scanNodeModules', () => {
  const tmp = join(tmpdir(), `licensewall-test-${Date.now()}`);

  beforeAll(() => {
    mkdirSync(join(tmp, 'node_modules', 'test-pkg'), { recursive: true });
    writeFileSync(
      join(tmp, 'node_modules', 'test-pkg', 'package.json'),
      JSON.stringify({ name: 'test-pkg', version: '3.2.1', license: 'BSD-3-Clause' })
    );
    mkdirSync(join(tmp, 'node_modules', '@acme', 'utils'), { recursive: true });
    writeFileSync(
      join(tmp, 'node_modules', '@acme', 'utils', 'package.json'),
      JSON.stringify({ name: '@acme/utils', version: '0.5.0', license: 'ISC' })
    );
    mkdirSync(join(tmp, 'node_modules', 'no-license-pkg'), { recursive: true });
    writeFileSync(
      join(tmp, 'node_modules', 'no-license-pkg', 'package.json'),
      JSON.stringify({ name: 'no-license-pkg', version: '1.0.0' })
    );
  });

  afterAll(() => rmSync(tmp, { recursive: true, force: true }));

  it('discovers regular and scoped packages', () => {
    const deps = scanNodeModules(tmp);
    expect(deps).toHaveLength(3);
    expect(deps.find((d) => d.name === 'test-pkg')?.license).toBe('BSD-3-Clause');
    expect(deps.find((d) => d.name === '@acme/utils')?.license).toBe('ISC');
    expect(deps.find((d) => d.name === 'no-license-pkg')?.license).toBe('UNKNOWN');
  });

  it('returns empty array when node_modules missing', () => {
    expect(scanNodeModules('/nonexistent/path')).toEqual([]);
  });
});
