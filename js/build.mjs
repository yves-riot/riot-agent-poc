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

// Source patches for QuickJS, applied at bundle time. Each must match exactly once (the build
// fails otherwise, so an upstream change is noticed) and each is meant to be upstreamed: they are
// behaviour-preserving on V8 and only remove costs QuickJS does not optimise away.
const PATCHES = [
  {
    file: join(detectionDir, 'src/detectors/phone.ts'),
    find: 'CURRENCY_SUFFIX.test(text.slice(endsAt))',
    replace: 'CURRENCY_SUFFIX.test(text.slice(endsAt, endsAt + 64))',
    why:
      'V8 slices in O(1); QuickJS copies, so slicing the whole tail per phone match is O(n^2). ' +
      'The suffix regex is anchored and only reads whitespace + a currency token.',
  },
];

const sourcePatches = {
  name: 'source-patches',
  setup(b) {
    for (const patch of PATCHES) {
      b.onLoad({ filter: new RegExp(patch.file.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$') }, () => {
        const source = readFileSync(patch.file, 'utf8');
        const count = source.split(patch.find).length - 1;
        if (count !== 1) throw new Error(`patch for ${patch.file} matched ${count} times: ${patch.find}`);
        return { contents: source.replace(patch.find, patch.replace), loader: 'ts' };
      });
    }
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
  plugins: [sonarSources, sourcePatches, conformanceCases],
};

mkdirSync(join(here, 'dist'), { recursive: true });
await build({ ...common, entryPoints: [join(here, 'src/host.ts')], outfile: join(here, 'dist/detection.js'), minify: true });
await build({ ...common, entryPoints: [join(here, 'src/conformance.ts')], outfile: join(here, 'dist/conformance.js') });

// Where the fixtures live, for the Rust conformance test.
writeFileSync(join(here, 'dist/conformance-dir.txt'), conformanceDir);
const size = (f) => (readFileSync(join(here, 'dist', f)).length / 1024).toFixed(0);
console.log(`dist/detection.js ${size('detection.js')} KiB, dist/conformance.js ${size('conformance.js')} KiB`);
