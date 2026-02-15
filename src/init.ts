import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export type TemplateName = 'permissive' | 'moderate' | 'strict';
export type Tier = 'free' | 'pro' | 'enterprise';

export interface InitOptions {
  force?: boolean;
  tier?: Tier;
}

export interface InitConfig {
  allow?: string[];
  deny?: string[];
  tier: Tier;
  maxDependencies?: number;
}

const TIER_MAX_DEPS: Record<Tier, number | undefined> = {
  free: 100,
  pro: undefined,
  enterprise: undefined,
};

export function initConfig(
  template: TemplateName,
  targetDir: string,
  options: InitOptions = {},
): void {
  const { force = false, tier = 'free' } = options;
  const configPath = resolve(targetDir, '.licensewallrc.json');

  if (existsSync(configPath) && !force) {
    throw new Error(
      `Config file already exists at ${configPath}. Use --force to overwrite.`,
    );
  }

  const templatePath = join(__dirname, 'templates', `${template}.json`);
  if (!existsSync(templatePath)) {
    throw new Error(`Unknown template: ${template}`);
  }

  const templateContent = JSON.parse(readFileSync(templatePath, 'utf-8'));

  const config: InitConfig = {
    ...templateContent,
    tier,
  };

  const maxDeps = TIER_MAX_DEPS[tier];
  if (maxDeps !== undefined) {
    config.maxDependencies = maxDeps;
  }

  mkdirSync(targetDir, { recursive: true });
  writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', 'utf-8');
}
