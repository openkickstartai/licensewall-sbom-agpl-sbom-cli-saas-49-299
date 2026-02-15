#!/usr/bin/env node
import { Command } from 'commander';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import { scanNodeModules, checkPolicy, generateSBOM, Policy } from './scanner.js';

function loadPolicy(dir: string): Policy {
  const p = resolve(dir, '.licensewall.json');
  if (existsSync(p)) {
    return JSON.parse(readFileSync(p, 'utf-8'));
  }
  return { deny: ['AGPL-3.0', 'GPL-3.0', 'SSPL-1.0', 'EUPL'] };
}

const cli = new Command()
  .name('licensewall')
  .description('🧱 Dependency license compliance gate & SBOM generator')
  .version('1.0.0');

cli
  .command('scan')
  .description('Scan dependencies and enforce license policy')
  .option('-d, --dir <path>', 'Project directory', '.')
  .option('--json', 'Output as JSON')
  .option('--sarif', 'Output as SARIF (Pro feature)')
  .action((opts) => {
    if (opts.sarif) {
      console.log('⚡ SARIF output requires LicenseWall Pro ($49/mo)');
      console.log('   Upgrade → https://licensewall.dev/pricing');
      process.exit(0);
    }
    const dir = resolve(opts.dir);
    const deps = scanNodeModules(dir);
    const policy = loadPolicy(dir);
    const violations = checkPolicy(deps, policy);
    console.log(`\n🔍 LicenseWall scanned ${deps.length} dependencies\n`);
    if (opts.json) {
      const out = { total: deps.length, compliant: deps.length - violations.length, violations };
      console.log(JSON.stringify(out, null, 2));
    } else {
      for (const d of deps) {
        const bad = violations.some((v) => v.dep.name === d.name);
        console.log(`  ${bad ? '❌' : '✅'} ${d.name}@${d.version} — ${d.license}`);
      }
    }
    if (violations.length > 0) {
      console.log(`\n🚨 ${violations.length} policy violation(s):\n`);
      for (const v of violations) {
        console.log(`  ❌ ${v.dep.name}@${v.dep.version}: ${v.reason}`);
      }
      console.log('');
      process.exit(1);
    } else {
      console.log('\n✅ All dependencies comply with license policy!\n');
    }
  });

cli
  .command('sbom')
  .description('Generate CycloneDX 1.5 SBOM')
  .option('-d, --dir <path>', 'Project directory', '.')
  .option('-o, --output <file>', 'Output file path', 'sbom.cdx.json')
  .action((opts) => {
    const dir = resolve(opts.dir);
    const deps = scanNodeModules(dir);
    const sbom = generateSBOM(deps);
    const outPath = resolve(dir, opts.output);
    writeFileSync(outPath, JSON.stringify(sbom, null, 2));
    console.log(`\n📦 SBOM written to ${opts.output} (${deps.length} components)\n`);
  });

cli.parse();
