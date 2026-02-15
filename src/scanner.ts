import { readdirSync, readFileSync, existsSync } from 'fs';
import { join } from 'path';

export interface Dep {
  name: string;
  version: string;
  license: string;
  path: string;
}

export interface ScannedDep extends Dep {
  depth: number;
  dependedBy: string[];
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

export function detectLicenseFromFile(depPath: string): string | null {
  const licenseFiles = [
    'LICENSE', 'LICENSE.md', 'LICENSE.txt',
    'LICENCE', 'LICENCE.md', 'LICENCE.txt',
    'COPYING', 'COPYING.md',
  ];

  for (const filename of licenseFiles) {
    const filePath = join(depPath, filename);
    if (!existsSync(filePath)) continue;
    try {
      const content = readFileSync(filePath, 'utf-8');
      const upper = content.toUpperCase();

      // Specific patterns first (order matters)
      if (upper.includes('APACHE') && (upper.includes('VERSION 2.0') || upper.includes('APACHE-2.0'))) return 'Apache-2.0';
      if (upper.includes('MIT LICENSE') || upper.includes('PERMISSION IS HEREBY GRANTED, FREE OF CHARGE')) return 'MIT';
      if (upper.includes('ISC LICENSE') || (upper.includes('ISC') && upper.includes('PERMISSION TO USE'))) return 'ISC';
      if (upper.includes('BSD 3-CLAUSE') || upper.includes('BSD-3-CLAUSE')) return 'BSD-3-Clause';
      if (upper.includes('BSD 2-CLAUSE') || upper.includes('BSD-2-CLAUSE')) return 'BSD-2-Clause';
      if (upper.includes('GNU AFFERO GENERAL PUBLIC LICENSE') && upper.includes('VERSION 3')) return 'AGPL-3.0';
      if (upper.includes('GNU GENERAL PUBLIC LICENSE') && upper.includes('VERSION 3')) return 'GPL-3.0';
      if (upper.includes('GNU GENERAL PUBLIC LICENSE') && upper.includes('VERSION 2')) return 'GPL-2.0';
      if (upper.includes('GNU LESSER GENERAL PUBLIC LICENSE')) return 'LGPL';
      if (upper.includes('MOZILLA PUBLIC LICENSE') && upper.includes('2.0')) return 'MPL-2.0';
      if (upper.includes('THE UNLICENSE') || (upper.includes('UNLICENSE') && upper.includes('PUBLIC DOMAIN'))) return 'Unlicense';

      // Broader fallback with word boundaries
      if (/\bMIT\b/.test(upper)) return 'MIT';
      if (/\bISC\b/.test(upper)) return 'ISC';
      if (/\bBSD\b/.test(upper)) return 'BSD';
      if (/\bGPL\b/.test(upper)) return 'GPL';
      if (/\bAPACHE\b/.test(upper)) return 'Apache-2.0';

      // Found a file but couldn't identify license
      return null;
    } catch {
      continue;
    }
  }
  return null;
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

export function scanDeep(rootDir: string): ScannedDep[] {
  const seen = new Map<string, ScannedDep>();

  function walkNodeModules(nmDir: string, depth: number, parent: string | null): void {
    if (!existsSync(nmDir)) return;
    let entries: string[];
    try {
      entries = readdirSync(nmDir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.startsWith('.')) continue;
      if (entry.startsWith('@')) {
        const scopeDir = join(nmDir, entry);
        try {
          for (const sub of readdirSync(scopeDir)) {
            processDep(join(scopeDir, sub), `${entry}/${sub}`, depth, parent);
          }
        } catch { /* not a directory */ }
      } else {
        processDep(join(nmDir, entry), entry, depth, parent);
      }
    }
  }

  function processDep(depDir: string, name: string, depth: number, parent: string | null): void {
    const pkgPath = join(depDir, 'package.json');
    if (!existsSync(pkgPath)) return;
    let pkg: Record<string, unknown>;
    try {
      pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    } catch {
      return;
    }
    const version = (pkg.version as string) || '0.0.0';
    let license = normalizeLicense(pkg.license || (pkg as any).licenses);

    // Fallback: detect license from file if package.json has no license field
    if (license === 'UNKNOWN') {
      const detected = detectLicenseFromFile(depDir);
      if (detected) license = detected;
    }

    const key = `${name}@${version}`;
    const existing = seen.get(key);
    if (existing) {
      // Deduplicate: merge dependedBy, keep smallest depth
      if (parent && !existing.dependedBy.includes(parent)) {
        existing.dependedBy.push(parent);
      }
      if (depth < existing.depth) {
        existing.depth = depth;
      }
    } else {
      const scanned: ScannedDep = {
        name,
        version,
        license,
        path: depDir,
        depth,
        dependedBy: parent ? [parent] : [],
      };
      seen.set(key, scanned);
    }

    // Recurse into nested node_modules
    walkNodeModules(join(depDir, 'node_modules'), depth + 1, name);
  }

  walkNodeModules(join(rootDir, 'node_modules'), 0, null);
  return Array.from(seen.values());
}

export function checkPolicy(deps: Dep[], policy: Policy): Violation[] {
  const violations: Violation[] = [];
  for (const dep of deps) {
    if (dep.license === 'UNKNOWN') {
      violations.push({ dep, reason: 'Unknown license — requires manual review' });
      continue;
    }
    if (policy.allow && policy.allow.length > 0) {
      if (!policy.allow.some((a) => dep.license.includes(a))) {
        violations.push({ dep, reason: `License "${dep.license}" not in allow list` });
      }
    } else if (policy.deny && policy.deny.length > 0) {
      if (policy.deny.some((d) => dep.license.includes(d))) {
        violations.push({ dep, reason: `License "${dep.license}" is denied by policy` });
      }
    }
  }
  return violations;
}

export function generateSBOM(deps: Dep[]): Record<string, unknown> {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
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
