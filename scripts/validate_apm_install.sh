#!/usr/bin/env bash
# Validate CodeGuard APM skill-only package installs across harnesses.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGING="/tmp/codeguard-apm-validate-$$"
CONSUMER="${STAGING}/consumer"

cleanup() {
  rm -rf "${STAGING}"
}
trap cleanup EXIT

if ! command -v apm >/dev/null 2>&1; then
  echo "❌ APM CLI not found. Install it before running this script:"
  echo "   brew install microsoft/apm/apm"
  echo "   or: pip install apm-cli"
  exit 1
fi

echo "Staging package without .venv..."
mkdir -p "${STAGING}"
rsync -a \
  --exclude '.venv' \
  --exclude '.env' \
  --exclude '.env.*' \
  --exclude '.git' \
  --exclude 'dist' \
  --exclude 'test-output' \
  --exclude 'apm_modules' \
  "${ROOT}/" "${STAGING}/package/"

echo "Creating consumer project..."
mkdir -p "${STAGING}"
(
  cd "${STAGING}"
  apm init consumer -y --target cursor,copilot,claude,windsurf,codex
  python3 - <<'PY'
import yaml
from pathlib import Path

apm_path = Path("consumer/apm.yml")
data = yaml.safe_load(apm_path.read_text(encoding="utf-8"))
data["targets"] = ["cursor", "copilot", "claude", "windsurf", "codex"]
apm_path.write_text(
    yaml.safe_dump(data, sort_keys=False, allow_unicode=True),
    encoding="utf-8",
)
PY
)

echo "Installing CodeGuard from staged package..."
(
  cd "${CONSUMER}"
  apm install "${STAGING}/package" \
    --target cursor,copilot,claude,windsurf,codex
)

expect_count=23

check_count() {
  local label="$1"
  local pattern="$2"
  local actual
  actual="$(find "${CONSUMER}" -path "${pattern}" | wc -l | tr -d ' ')"
  if [[ "${actual}" -ne "${expect_count}" ]]; then
    echo "❌ ${label}: expected ${expect_count}, found ${actual}"
    exit 1
  fi
  echo "✅ ${label}: ${actual} files"
}

check_count "Skill rules" "*/.agents/skills/codeguard/rules/codeguard-*.md"

test -f "${CONSUMER}/.agents/skills/codeguard/SKILL.md" \
  || { echo "❌ CodeGuard SKILL.md missing"; exit 1; }
echo "✅ CodeGuard SKILL.md present"

echo "✅ APM skill install validation passed"
