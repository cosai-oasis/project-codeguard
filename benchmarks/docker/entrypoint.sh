#!/usr/bin/env bash
set -euo pipefail

# --- Environment variables (set by orchestrator) ---
# REPO_URL          - Git repository to clone
# REPO_REF          - Branch/tag to checkout
# RUN_MODE          - "with_skills" or "without_skills"
# AGENT_PROMPT      - The prompt to send to the opencode agent
# AGENT_MODEL       - Model identifier for opencode
# OPENAI_API_KEY    - API key (passed through from host)
# OPENAI_BASE_URL   - OpenRouter base URL

WORK_DIR="/workspace/repo"
DIFF_OUTPUT="/workspace/output/diff.patch"
LOG_OUTPUT="/workspace/output/agent.log"
USAGE_OUTPUT="/workspace/output/usage.json"

mkdir -p /workspace/output

# 1. Clone the target repository
echo "[entrypoint] Cloning ${REPO_URL} at ref ${REPO_REF}..."
git clone --depth 1 --branch "${REPO_REF}" "${REPO_URL}" "${WORK_DIR}" 2>&1

cd "${WORK_DIR}"

# 2. Conditionally install CodeGuard skills
if [ "${RUN_MODE}" = "with_skills" ]; then
    echo "[entrypoint] Installing CodeGuard skills..."
    mkdir -p .opencode/skills/software-security/rules
    cp /opt/codeguard-skills/software-security/SKILL.md \
       .opencode/skills/software-security/
    cp /opt/codeguard-skills/software-security/rules/*.md \
       .opencode/skills/software-security/rules/
    echo "[entrypoint] Skills installed: $(ls .opencode/skills/software-security/rules/ | wc -l) rules"
else
    echo "[entrypoint] Running WITHOUT CodeGuard skills (baseline)"
fi

# 3. Mark baseline so final diff captures only agent changes
git add -A
git \
    -c user.name="bench" \
    -c user.email="bench@local" \
    commit --allow-empty -m "pre-benchmark baseline" 2>/dev/null || true

# 4. Run the opencode agent
echo "[entrypoint] Running opencode agent with model ${AGENT_MODEL}..."
opencode \
    --model "${AGENT_MODEL}" \
    --non-interactive \
    --prompt "${AGENT_PROMPT}" \
    > "${LOG_OUTPUT}" 2>&1 || true

echo "[entrypoint] Agent exited with code $?"

# 5. Collect the diff
git add -A
git diff --cached --no-color > "${DIFF_OUTPUT}" 2>/dev/null || true

DIFF_LINES=$(wc -l < "${DIFF_OUTPUT}" 2>/dev/null || echo "0")
echo "[entrypoint] Diff collected: ${DIFF_LINES} lines"

# 6. Extract token usage from agent log (best-effort)
# Look for common patterns: "prompt_tokens", "completion_tokens", "total_tokens"
# OpenRouter / OpenAI-compatible agents typically log JSON usage blocks.
PROMPT_TOKENS=$(grep -oP '"prompt_tokens"\s*:\s*\K\d+' "${LOG_OUTPUT}" 2>/dev/null | awk '{s+=$1}END{print s+0}')
COMPLETION_TOKENS=$(grep -oP '"completion_tokens"\s*:\s*\K\d+' "${LOG_OUTPUT}" 2>/dev/null | awk '{s+=$1}END{print s+0}')
TOTAL_TOKENS=$((PROMPT_TOKENS + COMPLETION_TOKENS))

cat > "${USAGE_OUTPUT}" <<USAGE_EOF
{"prompt_tokens": ${PROMPT_TOKENS}, "completion_tokens": ${COMPLETION_TOKENS}, "total_tokens": ${TOTAL_TOKENS}}
USAGE_EOF

echo "[entrypoint] Agent tokens: prompt=${PROMPT_TOKENS} completion=${COMPLETION_TOKENS} total=${TOTAL_TOKENS}"
echo "[entrypoint] Done."
