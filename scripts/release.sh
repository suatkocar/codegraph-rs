#!/usr/bin/env bash
# Release script — bumps version everywhere, commits, tags, pushes, publishes npm.
#
# Usage:
#   ./scripts/release.sh 0.2.0
#   ./scripts/release.sh 0.2.0 --otp=123456

set -eo pipefail

VERSION="$1"
OTP_FLAG="$2"

if [ -z "$VERSION" ]; then
  echo "Usage: ./scripts/release.sh <version> [--otp=CODE]"
  echo "Example: ./scripts/release.sh 0.2.0 --otp=123456"
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

info()  { printf "\033[1;34m==>\033[0m %s\n" "$1"; }
ok()    { printf "\033[1;32m==>\033[0m %s\n" "$1"; }

# 1. Update versions
info "Bumping version to ${VERSION}..."
sed -i '' "s/^version = \".*\"/version = \"${VERSION}\"/" Cargo.toml
sed -i '' "s/\"version\": \".*\"/\"version\": \"${VERSION}\"/" npm/package.json

# 2. Rebuild to update Cargo.lock
info "Building..."
cargo build --release --no-default-features 2>&1 | tail -1

# 3. Commit + push
info "Committing and pushing..."
git add Cargo.toml Cargo.lock npm/package.json
git commit -m "v${VERSION}"
git push origin main

# 4. Tag + push tag (triggers GitHub Actions release build)
info "Tagging v${VERSION}..."
git tag "v${VERSION}"
git push origin "v${VERSION}"

# 5. Publish to npm
info "Publishing to npm..."
if [ -n "$OTP_FLAG" ]; then
  (cd npm && npm publish --access public "$OTP_FLAG")
else
  (cd npm && npm publish --access public)
fi

ok "Released v${VERSION} — GitHub + npm synced!"
echo ""
echo "  GitHub: https://github.com/suatkocar/codegraph/releases/tag/v${VERSION}"
echo "  npm:    https://www.npmjs.com/package/@suatkocar/codegraph"
echo ""
