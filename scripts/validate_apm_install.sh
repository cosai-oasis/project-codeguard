#!/usr/bin/env bash
# Validate CodeGuard APM package installs and deploys rules to multiple harnesses.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGING="/tmp/codeguard-apm-validate-$$"
CONSUMER="${STAGING}/consumer"

cleanup() {
  rm -rf "${STAGING}"
}
trap cleanup EXIT

if ! command -v apm >/dev/null 2>&1; then
  echo "Installing APM CLI..."
  curl -sSL https://aka.ms/apm-unix | sh
  export PATH="${HOME}/.local/bin:${PATH}"
fi

echo "Staging package without .venv..."
mkdir -p "${STAGING}"
rsync -a \
  --exclude '.venv' \
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

check_count "Cursor rules" "*/.cursor/rules/codeguard-*.mdc"
check_count "Copilot instructions" "*/.github/instructions/codeguard-*.instructions.md"
check_count "Claude rules" "*/.claude/rules/codeguard-*.md"
check_count "Windsurf rules" "*/.windsurf/rules/codeguard-*.md"
check_count "Skill rules" "*/.agents/skills/codeguard/rules/codeguard-*.md"

test -f "${CONSUMER}/.codex/agents/codeguard-reviewer.toml" \
  || { echo "❌ Codex reviewer agent missing"; exit 1; }
echo "✅ Codex reviewer agent present"

test -f "${CONSUMER}/.agents/skills/codeguard/SKILL.md" \
  || { echo "❌ CodeGuard SKILL.md missing"; exit 1; }
echo "✅ CodeGuard SKILL.md present"

echo "✅ APM install validation passed"
