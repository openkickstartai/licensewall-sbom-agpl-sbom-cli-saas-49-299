#!/usr/bin/env node
import { Command } from 'commander';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import { scanNodeModules, checkPolicy, generateSBOM, Policy } from './scanner.js';
import { formatTable, formatJSON } from './formatters.js';

function loadPolicy(policyPath: string | undefined, dir: string): Policy {
  const p = policyPath ? resolve(policyPath) : resolve(dir, '.licensewall.json');
  if (existsSync(p)) {
    return JSON.parse(readFileSync(p, 'utf-8'));
  }
  return { deny: ['AGPL-3.0', 'GPL-3.0', 'SSPL-1.0', 'EUPL'] };
}

export const cli = new Command()
  .name('licensewall')
  .description('🧱 Dependency license compliance gate & SBOM generator')
  .version('1.0.0')
  .option('-q, --quiet', 'Suppress non-essential output')
  .option('--no-color', 'Disable colored output');

cli
  .command('scan')
  .description('Scan dependencies and list their licenses')
  .option('-d, --dir <path>', 'Project directory', '.')
  .option('-f, --format <format>', 'Output format: table or json', 'table')
  .action((opts) => {
    const dir = resolve(opts.dir);
    const deps = scanNodeModules(dir);
    const globalOpts = cli.opts();

    if (!globalOpts.quiet) {
      console.log(`\n🔍 LicenseWall scanned ${deps.length} dependencies\n`);
    }

    if (opts.format === 'json') {
      console.log(formatJSON(deps));
    } else {
      console.log(formatTable(deps));
    }
  });

cli
  .command('check')
  .description('Check dependencies against license policy (exits 1 on violation)')
  .option('-d, --dir <path>', 'Project directory', '.')
  .option('-p, --policy <path>', 'Path to policy file')
  .action((opts) => {
    const dir = resolve(opts.dir);
    const deps = scanNodeModules(dir);
    const policy = loadPolicy(opts.policy, dir);
    const violations = checkPolicy(deps, policy);
    const globalOpts = cli.opts();

    if (!globalOpts.quiet) {
      console.log(`\n🔍 LicenseWall checked ${deps.length} dependencies\n`);
    }

    if (violations.length > 0) {
      console.log(`🚨 ${violations.length} policy violation(s):\n`);
      for (const v of violations) {
        console.log(`  ❌ ${v.dep.name}@${v.dep.version} — ${v.reason}`);
      }
      process.exit(1);
    } else {
      if (!globalOpts.quiet) {
        console.log('✅ All dependencies comply with policy.');
      }
      process.exit(0);
    }
  });

cli
  .command('sbom')
  .description('Generate CycloneDX SBOM file')
  .option('-d, --dir <path>', 'Project directory', '.')
  .option('-o, --output <path>', 'Output file path', 'sbom.cdx.json')
  .action((opts) => {
    const dir = resolve(opts.dir);
    const deps = scanNodeModules(dir);
    const globalOpts = cli.opts();

    let sbom: object;
    try {
      sbom = generateSBOM(deps);
    } catch {
      sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.4',
        version: 1,
        components: deps.map((d) => ({
          type: 'library',
          name: d.name,
          version: d.version,
          licenses: [{ license: { id: d.license } }],
        })),
      };
    }

    const outPath = resolve(opts.output);
    writeFileSync(outPath, JSON.stringify(sbom, null, 2));

    if (!globalOpts.quiet) {
      console.log(`📦 SBOM written to ${outPath} (${deps.length} components)`);
    }
  });

cli.parse(process.argv);
