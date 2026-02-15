import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { initConfig } from '../src/init.js';
import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('initConfig', () => {
  let testDir: string;

  beforeEach(() => {
    testDir = join(
      tmpdir(),
      `licensewall-init-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(testDir, { recursive: true, force: true });
  });

  it('creates permissive config with correct allow and deny lists', () => {
    initConfig('permissive', testDir);
    const configPath = join(testDir, '.licensewallrc.json');
    expect(existsSync(configPath)).toBe(true);
    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    expect(config.allow).toEqual(
      expect.arrayContaining([
        'MIT',
        'ISC',
        'BSD-2-Clause',
        'BSD-3-Clause',
        'Apache-2.0',
        'CC0-1.0',
        'Unlicense',
      ]),
    );
    expect(config.allow).toHaveLength(7);
    expect(config.deny).toEqual(
      expect.arrayContaining(['AGPL-3.0', 'GPL-2.0', 'GPL-3.0']),
    );
    expect(config.deny).toHaveLength(3);
  });

  it('creates moderate config with weak-copyleft licenses allowed', () => {
    initConfig('moderate', testDir);
    const configPath = join(testDir, '.licensewallrc.json');
    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    // Should include all permissive licenses plus LGPL/MPL
    expect(config.allow).toEqual(
      expect.arrayContaining([
        'MIT',
        'ISC',
        'BSD-2-Clause',
        'BSD-3-Clause',
        'Apache-2.0',
        'CC0-1.0',
        'Unlicense',
        'LGPL-2.1',
        'LGPL-3.0',
        'MPL-2.0',
      ]),
    );
    expect(config.allow).toHaveLength(10);
    expect(config.deny).toEqual(
      expect.arrayContaining(['AGPL-3.0', 'GPL-2.0', 'GPL-3.0']),
    );
  });

  it('creates strict config with minimal allowed licenses only', () => {
    initConfig('strict', testDir);
    const configPath = join(testDir, '.licensewallrc.json');
    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    expect(config.allow).toEqual(['MIT', 'ISC', 'BSD-2-Clause', 'Apache-2.0']);
    expect(config.deny).toEqual(
      expect.arrayContaining(['AGPL-3.0', 'GPL-2.0', 'GPL-3.0']),
    );
  });

  it('sets default tier to free with maxDependencies 100', () => {
    initConfig('permissive', testDir);
    const configPath = join(testDir, '.licensewallrc.json');
    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    expect(config.tier).toBe('free');
    expect(config.maxDependencies).toBe(100);
  });

  it('does not overwrite existing config without force flag', () => {
    const configPath = join(testDir, '.licensewallrc.json');
    const original = { allow: ['MIT'], existing: true };
    writeFileSync(configPath, JSON.stringify(original), 'utf-8');

    expect(() => initConfig('permissive', testDir)).toThrow(/already exists/);

    // Verify original file is untouched
    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    expect(config.existing).toBe(true);
    expect(config.allow).toEqual(['MIT']);
  });

  it('overwrites existing config when force flag is set', () => {
    const configPath = join(testDir, '.licensewallrc.json');
    writeFileSync(configPath, JSON.stringify({ existing: true }), 'utf-8');

    initConfig('permissive', testDir, { force: true });

    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    expect(config.existing).toBeUndefined();
    expect(config.allow).toContain('MIT');
    expect(config.tier).toBe('free');
  });

  it('does not set maxDependencies for pro tier', () => {
    initConfig('moderate', testDir, { tier: 'pro' });
    const configPath = join(testDir, '.licensewallrc.json');
    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    expect(config.tier).toBe('pro');
    expect(config.maxDependencies).toBeUndefined();
  });

  it('does not set maxDependencies for enterprise tier', () => {
    initConfig('strict', testDir, { tier: 'enterprise' });
    const configPath = join(testDir, '.licensewallrc.json');
    const config = JSON.parse(readFileSync(configPath, 'utf-8'));
    expect(config.tier).toBe('enterprise');
    expect(config.maxDependencies).toBeUndefined();
  });

  it('all template files produce valid JSON parseable as Policy', () => {
    const templates = ['permissive', 'moderate', 'strict'] as const;
    for (const tpl of templates) {
      const dir = join(
        testDir,
        `sub-${tpl}`,
      );
      mkdirSync(dir, { recursive: true });
      initConfig(tpl, dir);
      const configPath = join(dir, '.licensewallrc.json');
      const config = JSON.parse(readFileSync(configPath, 'utf-8'));
      // Must have allow array
      expect(Array.isArray(config.allow)).toBe(true);
      expect(config.allow.length).toBeGreaterThan(0);
      // Must have deny array
      expect(Array.isArray(config.deny)).toBe(true);
      expect(config.deny.length).toBeGreaterThan(0);
      // All entries must be strings
      for (const l of config.allow) {
        expect(typeof l).toBe('string');
      }
      for (const l of config.deny) {
        expect(typeof l).toBe('string');
      }
    }
  });
});
