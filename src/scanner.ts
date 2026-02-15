import { readdirSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';

export interface Dep {
  name: string;
  version: string;
  license: string;
  path: string;
}

export interface Policy {
  allow?: string[];
  deny?: string[];
}

export interface Violation {
  dep: Dep;
  reason: string;
}

function normalizeLicense(raw: unknown): string {
  if (!raw) return 'UNKNOWN';
  if (typeof raw === 'string') return raw;
  if (typeof raw === 'object' && raw !== null && 'type' in raw) {
    return String((raw as Record<string, unknown>).type);
  }
  if (Array.isArray(raw)) {
    return raw.map((l) => (typeof l === 'object' && l?.type ? l.type : String(l))).join(' OR ');
  }
  return 'UNKNOWN';
}

function readPkg(pkgDir: string, name: string): Dep | null {
  const pkgPath = join(pkgDir, 'package.json');
  if (!existsSync(pkgPath)) return null;
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    return {
      name,
      version: pkg.version || '0.0.0',
      license: normalizeLicense(pkg.license || pkg.licenses),
      path: pkgDir,
    };
  } catch {
    return null;
  }
}

export function scanNodeModules(dir: string): Dep[] {
  const nmDir = join(dir, 'node_modules');
  if (!existsSync(nmDir)) return [];
  const deps: Dep[] = [];
  for (const entry of readdirSync(nmDir)) {
    if (entry.startsWith('.')) continue;
    if (entry.startsWith('@')) {
      const scopeDir = join(nmDir, entry);
      try {
        for (const sub of readdirSync(scopeDir)) {
          const dep = readPkg(join(scopeDir, sub), `${entry}/${sub}`);
          if (dep) deps.push(dep);
        }
      } catch { /* not a directory */ }
    } else {
      const dep = readPkg(join(nmDir, entry), entry);
      if (dep) deps.push(dep);
    }
  }
  return deps;
}

export function checkPolicy(deps: Dep[], policy: Policy): Violation[] {
  const violations: Violation[] = [];
  for (const dep of deps) {
    const lic = dep.license.toUpperCase();
    if (lic === 'UNKNOWN') {
      violations.push({ dep, reason: 'Unknown license — manual review required' });
      continue;
    }
    if (policy.deny?.some((d) => lic.includes(d.toUpperCase()))) {
      violations.push({ dep, reason: `License "${dep.license}" is denied by policy` });
    } else if (policy.allow?.length && !policy.allow.some((a) => lic.includes(a.toUpperCase()))) {
      violations.push({ dep, reason: `License "${dep.license}" not in allow list` });
    }
  }
  return violations;
}

export function generateSBOM(deps: Dep[], name = 'project'): object {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      component: { type: 'application', name },
      tools: [{ vendor: 'LicenseWall', name: 'licensewall', version: '1.0.0' }],
    },
    components: deps.map((d) => ({
      type: 'library',
      name: d.name,
      version: d.version,
      licenses: [{ license: { id: d.license } }],
      purl: `pkg:npm/${d.name}@${d.version}`,
    })),
  };
}

export { generateSBOM, writeSBOM } from './sbom.js';
export type { CycloneDXDocument, CycloneDXComponent, ScannedDep } from './sbom.js';
