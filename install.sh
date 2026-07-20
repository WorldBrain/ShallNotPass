#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
helper_name="supabase-ops-guard-helper"
requested_codesign_identity="${SOG_CODESIGN_IDENTITY:-Developer ID Application: WorldBrain UG (haftungsbeschränkt) (5YUPQC9D96)}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  printf '%s\n' "Supabase Ops Guard currently supports macOS only." >&2
  exit 1
fi

command -v swift >/dev/null || {
  printf '%s\n' "Swift is required. Install Xcode Command Line Tools first: xcode-select --install" >&2
  exit 1
}

swift build -c release --package-path "$root"

codesign_identity="$({
  security find-identity -v -p codesigning | awk -v requested="$requested_codesign_identity" \
    '$2 == requested || index($0, "\"" requested "\"") { print $2; exit }'
} || true)"

if [[ -z "$codesign_identity" ]]; then
  printf '%s\n' "Required code-signing identity is unavailable: ${requested_codesign_identity}" >&2
  printf '%s\n' "Set SOG_CODESIGN_IDENTITY to an available Developer ID identity." >&2
  exit 1
fi

codesign --force \
  --sign "$codesign_identity" \
  --identifier dev.supabase-ops-guard \
  "$root/.build/release/$helper_name"

codesign --verify --strict "$root/.build/release/$helper_name"

# The protected helper is outside the agent's repository workspace. `sudo` asks
# the human at the macOS terminal; no password is passed through this script.
sudo install -d -o root -g wheel -m 755 /usr/local/libexec/supabase-ops-guard
sudo install -o root -g wheel -m 755 \
  "$root/.build/release/$helper_name" \
  "/usr/local/libexec/supabase-ops-guard/$helper_name"
sudo install -o root -g wheel -m 755 \
  "$root/bin/supabase-ops-guard" \
  /usr/local/bin/supabase-ops-guard

printf '%s\n' "Installed Supabase Ops Guard. Run: supabase-ops-guard help"
