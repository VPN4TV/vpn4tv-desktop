#!/bin/bash
# VPN4TV: run the converter unit tests without the full Electron toolchain.
#
# The repo pins Node 26 + pnpm for the app build; the converter is plain
# TypeScript with no dependencies beyond node: builtins, so it can be compiled
# and tested with any modern Node. Run from the repo root:
#
#   scripts/test-converter.sh
set -e
cd "$(dirname "$0")/.."

OUT=$(mktemp -d)
CONFIG="$OUT/tsconfig.json"
cat > "$CONFIG" <<EOF
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "CommonJS",
    "moduleResolution": "Node",
    "strict": true,
    "skipLibCheck": true,
    "esModuleInterop": true,
    "outDir": "$OUT/js"
  },
  "include": ["$PWD/src/shared/vpn4tv/**/*.ts"]
}
EOF

npx --yes -p typescript@5.7 tsc -p "$CONFIG"
cd "$OUT/js"
node --test
