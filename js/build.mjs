// Bundles the extension's detection engine for the agent's embedded QuickJS.
//
//   dist/detection.js    engine + guard-core token memory + polyfills  → riot-detect (include_str!)
//   dist/conformance.js  the extension's conformance runner + case files → riot-detect tests
//
// The engine is consumed from source. Point SONAR_PACKAGES_DIR at the `packages/` folder of a
// riot-browser-extension checkout that has the shared-packages split (feat/shared-sonar-packages).
import { build } from 'esbuild';
import { existsSync, readdirSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const packagesDir = resolve(
  process.env.SONAR_PACKAGES_DIR ?? join(homedir(), 'dev/riot/riot-browser-extension-pkgs/packages'),
);
const detectionDir = join(packagesDir, 'sonar-detection');
const guardCoreDir = join(packagesDir, 'sonar-guard-core');
const conformanceDir = join(detectionDir, 'conformance');

for (const dir of [detectionDir, guardCoreDir]) {
  if (!existsSync(join(dir, 'src/index.ts'))) {
    console.error(`missing ${dir}/src/index.ts; set SONAR_PACKAGES_DIR to a checkout's packages/ folder`);
    process.exit(1);
  }
}

// One instance of each package for every importer (guard-core imports the engine too): the
// detector registry and the conversation token memory are module state.
const sonarSources = {
  name: 'sonar-sources',
  setup(b) {
    const map = {
      '@tryriot/sonar-detection': join(detectionDir, 'src/index.ts'),
      '@tryriot/sonar-guard-core': join(guardCoreDir, 'src/index.ts'),
    };
    b.onResolve({ filter: /^@tryriot\/sonar-(detection|guard-core)$/ }, (args) => ({ path: map[args.path] }));
    b.onResolve({ filter: /^@sonar-conformance\// }, (args) => ({
      path: join(conformanceDir, args.path.slice('@sonar-conformance/'.length) + '.ts'),
    }));
    // Type-only package: nothing to bundle if an import survives type stripping.
    b.onResolve({ filter: /^@tryriot\/sonar-schema/ }, () => ({ path: 'sonar-schema', namespace: 'empty' }));
    b.onLoad({ filter: /.*/, namespace: 'empty' }, () => ({ contents: 'export {}', loader: 'js' }));
  },
};

const conformanceCases = {
  name: 'conformance-cases',
  setup(b) {
    b.onResolve({ filter: /^virtual:conformance-cases$/ }, () => ({ path: 'cases', namespace: 'virtual' }));
    b.onLoad({ filter: /.*/, namespace: 'virtual' }, () => {
      const casesDir = join(conformanceDir, 'cases');
      const files = readdirSync(casesDir)
        .sort()
        .flatMap((group) =>
          readdirSync(join(casesDir, group))
            .filter((f) => f.endsWith('.json'))
            .sort()
            .map((f) => [`cases/${group}/${f}`, JSON.parse(readFileSync(join(casesDir, group, f), 'utf8'))]),
        );
      return { contents: `export default ${JSON.stringify(files)};`, loader: 'js' };
    });
  },
};

const common = {
  bundle: true,
  format: 'iife',
  platform: 'neutral',
  target: 'es2022',
  mainFields: ['module', 'main'],
  conditions: ['riot-source'],
  legalComments: 'none',
  logLevel: 'warning',
  plugins: [sonarSources, conformanceCases],
};

// Rewrites only what changed: `riot-detect` embeds dist/detection.js (`include_str!`), and
// cargo rebuilds it, with the daemon's LTO, whenever the file's mtime moves.
const writeIfChanged = (file, contents) => {
  if (existsSync(file) && readFileSync(file).equals(Buffer.from(contents))) return;
  writeFileSync(file, contents);
};
const bundle = async (entry, out, options = {}) => {
  const result = await build({ ...common, ...options, entryPoints: [join(here, entry)], outfile: join(here, out), write: false });
  for (const file of result.outputFiles) writeIfChanged(file.path, file.contents);
};

mkdirSync(join(here, 'dist'), { recursive: true });
await bundle('src/host.ts', 'dist/detection.js', { minify: true });
await bundle('src/conformance.ts', 'dist/conformance.js');

// Where the fixtures live, for the Rust conformance test.
writeIfChanged(join(here, 'dist/conformance-dir.txt'), conformanceDir);
const size = (f) => (readFileSync(join(here, 'dist', f)).length / 1024).toFixed(0);
console.log(`dist/detection.js ${size('detection.js')} KiB, dist/conformance.js ${size('conformance.js')} KiB`);
