import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import type { Dep } from './scanner.js';

export interface Policy {
  allow: string[];
  deny: string[];
  failOnUnknown: boolean;
}

export type Verdict = 'allowed' | 'denied' | 'unknown';

export interface PolicyResult {
  name: string;
  version: string;
  license: string;
  verdict: Verdict;
}

/**
 * Load policy from a JSON file (e.g. `.licensewallrc.json`).
 * Returns a default empty policy if the file does not exist.
 */
export function loadPolicy(filePath: string): Policy {
  const fullPath = resolve(filePath);
  if (!existsSync(fullPath)) {
    return { allow: [], deny: [], failOnUnknown: false };
  }
  const raw = JSON.parse(readFileSync(fullPath, 'utf-8'));
  return {
    allow: Array.isArray(raw.allow) ? raw.allow : [],
    deny: Array.isArray(raw.deny) ? raw.deny : [],
    failOnUnknown: raw.failOnUnknown === true,
  };
}

/**
 * Parse an SPDX license expression into individual license identifiers.
 * Splits on " OR " to handle dual-licensed packages.
 */
function parseSPDXParts(license: string): string[] {
  return license.split(/\s+OR\s+/).map((s) => s.trim()).filter(Boolean);
}

/**
 * Check if a license identifier matches a list entry.
 * Supports prefix matching so "AGPL-3.0-only" matches "AGPL-3.0".
 */
function matchesLicense(licensePart: string, listItem: string): boolean {
  const a = licensePart.toLowerCase();
  const b = listItem.toLowerCase();
  return a === b || a.startsWith(b + '-');
}

/**
 * Check if any SPDX part matches any entry in the given list.
 */
function matchesAnyInList(licenseParts: string[], list: string[]): boolean {
  return licenseParts.some((part) =>
    list.some((item) => matchesLicense(part, item))
  );
}

/**
 * Evaluate a policy against a list of scanned dependencies.
 * Returns a verdict for each dependency: allowed, denied, or unknown.
 *
 * Rules (in order of precedence):
 * 1. If any SPDX part matches the deny list → denied
 * 2. If allow list is non-empty and any SPDX part matches → allowed
 * 3. If allow list is non-empty and nothing matches → unknown
 * 4. If no allow list, failOnUnknown=true, and license is UNKNOWN → unknown
 * 5. Otherwise → allowed
 */
export function evaluatePolicy(policy: Policy, dependencies: Dep[]): PolicyResult[] {
  return dependencies.map((dep) => {
    const parts = parseSPDXParts(dep.license);
    let verdict: Verdict;

    // 1. Deny list takes highest precedence
    if (policy.deny.length > 0 && matchesAnyInList(parts, policy.deny)) {
      verdict = 'denied';
    }
    // 2-3. Allow list evaluation
    else if (policy.allow.length > 0) {
      if (matchesAnyInList(parts, policy.allow)) {
        verdict = 'allowed';
      } else {
        verdict = 'unknown';
      }
    }
    // 4. No allow list — check failOnUnknown for UNKNOWN licenses
    else if (policy.failOnUnknown && dep.license === 'UNKNOWN') {
      verdict = 'unknown';
    }
    // 5. Default: allowed
    else {
      verdict = 'allowed';
    }

    return {
      name: dep.name,
      version: dep.version,
      license: dep.license,
      verdict,
    };
  });
}
