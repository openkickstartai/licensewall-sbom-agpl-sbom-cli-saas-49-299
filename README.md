# 🧱 LicenseWall

**Dependency license compliance gate & SBOM generator.**

Stop AGPL/GPL copyleft licenses from silently entering your codebase. Auto-generate audit-grade SBOMs for SOC2, ISO 27001, EU CRA, and EO 14028 compliance.

## 🚀 Quick Start

```bash
# Install
npm install

# Scan current project for license violations
npx tsx src/index.ts scan

# Generate CycloneDX SBOM
npx tsx src/index.ts sbom -o sbom.cdx.json

# Scan with JSON output
npx tsx src/index.ts scan --json

# Scan a different project
npx tsx src/index.ts scan --dir /path/to/project
```

## ⚙️ Policy Configuration

Create `.licensewall.json` in your project root:

```json
{
  "allow": ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"],
  "deny": ["AGPL-3.0", "GPL-3.0", "SSPL-1.0", "EUPL"]
}
```

- **allow** — only these licenses pass (allowlist mode)
- **deny** — these licenses always fail (denylist mode)
- If no config exists, defaults to denying AGPL-3.0, GPL-3.0, SSPL-1.0, EUPL
- `UNKNOWN` licenses always trigger a violation for manual review

## 🔌 CI/CD Integration

```yaml
# GitHub Actions
- name: License Gate
  run: npx licensewall scan --dir .
```

The `scan` command exits with code 1 on policy violations, blocking your PR.

## 💰 Pricing

| Feature | Free | Pro $49/mo | Enterprise $299/mo |
|---|---|---|---|
| npm dependency scanning | ✅ | ✅ | ✅ |
| Allow/deny policy engine | ✅ | ✅ | ✅ |
| CycloneDX SBOM generation | ✅ | ✅ | ✅ |
| JSON output | ✅ | ✅ | ✅ |
| Python/Rust/Java/Go scanning | — | ✅ | ✅ |
| SARIF output for GitHub Security | — | ✅ | ✅ |
| PDF audit reports | — | ✅ | ✅ |
| PR comment bot | — | ✅ | ✅ |
| Slack/Teams notifications | — | — | ✅ |
| Approval workflow for exceptions | — | — | ✅ |
| Audit trail & history dashboard | — | — | ✅ |
| SSO / SAML | — | — | ✅ |
| Priority support + SLA | — | — | ✅ |

## 📊 Why Pay for LicenseWall?

**The cost of NOT knowing your licenses:**

- 🔥 One undiscovered AGPL dependency can force you to open-source your entire product
- 💸 License compliance audits during M&A or enterprise sales cost $10K-50K in legal fees
- ⏱️ Manual license review takes 2-4 hours per audit — LicenseWall does it in seconds
- 📋 SOC2/ISO 27001 auditors increasingly require SBOM documentation
- 🇪🇺 EU Cyber Resilience Act (2024) mandates SBOM for all software sold in the EU

**Pro pays for itself after one avoided compliance incident.**

Competitor pricing: FOSSA starts at $230/mo, Snyk at $98/user/mo. LicenseWall Pro at $49/mo is 4-5x cheaper.

## 🧪 Run Tests

```bash
npm test
```

## License

MIT
