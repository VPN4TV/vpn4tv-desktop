#!/bin/bash
# VPN4TV: run the converter unit tests without the full Electron toolchain.
#
# Only the Electron-free modules are compiled here (the service that creates
# profiles needs Electron and vite's __APP_VERSION__ define; pnpm typecheck
# covers those).
# The repo pins Node 26 + pnpm for the app build; the converter is plain
# TypeScript depending only on node: builtins, so it compiles and runs under any
# modern Node. TypeScript and @types/node are installed into a temp dir, so this
# touches neither the repo's node_modules nor anything global. From the repo root:
#
#   scripts/test-converter.sh
set -e
cd "$(dirname "$0")/.."

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

echo "==> checking for circular imports"
node scripts/check-cycles.mjs

echo "==> installing a throwaway TypeScript toolchain in $OUT"
npm install --silent --prefix "$OUT" typescript@5.7 @types/node@22 >/dev/null

cat > "$OUT/tsconfig.json" <<EOF
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "CommonJS",
    "moduleResolution": "Node",
    "strict": true,
    "skipLibCheck": true,
    "esModuleInterop": true,
    "types": ["node"],
    "typeRoots": ["$OUT/node_modules/@types"],
    "outDir": "$OUT/js"
  },
  "include": [
    "$PWD/src/main/vpn4tv/support.ts",
    "$PWD/src/main/vpn4tv/parser.ts",
    "$PWD/src/main/vpn4tv/generator.ts",
    "$PWD/src/main/vpn4tv/onboarding.ts",
    "$PWD/src/main/vpn4tv/dns.ts",
    "$PWD/src/main/vpn4tv/dns.test.ts",
    "$PWD/src/main/vpn4tv/converter.test.ts",
    "$PWD/src/main/vpn4tv/onboarding.test.ts",
    "$PWD/src/main/vpn4tv/integration.test.ts"
  ]
}
EOF

echo "==> typechecking + compiling"
"$OUT/node_modules/.bin/tsc" -p "$OUT/tsconfig.json"

echo "==> running tests"
cd "$OUT/js"
node --test
