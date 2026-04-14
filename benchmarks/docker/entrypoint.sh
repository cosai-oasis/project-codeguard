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
# BENCH_DEBUG       - "1" to enable debug output (optional)

WORK_DIR="/workspace/repo"
OUTPUT_DIR="/workspace/output"
DIFF_OUTPUT="${OUTPUT_DIR}/diff.patch"
LOG_OUTPUT="${OUTPUT_DIR}/agent.log"
USAGE_OUTPUT="${OUTPUT_DIR}/usage.json"
DEBUG_TRACE="${OUTPUT_DIR}/trace.json"

mkdir -p "${OUTPUT_DIR}"

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

# 3. Expose API key to opencode under the env var it expects
export OPENROUTER_API_KEY="${OPENAI_API_KEY}"

# 4. Mark baseline so final diff captures only agent changes
git add -A
git \
    -c user.name="bench" \
    -c user.email="bench@local" \
    commit --allow-empty -m "pre-benchmark baseline" 2>/dev/null || true

# 5. Run the opencode agent (JSON stream → stdout, stderr → separate file)
echo "[entrypoint] Running opencode agent with model ${AGENT_MODEL}..."
opencode run \
    -m "${AGENT_MODEL}" \
    --format json \
    --dangerously-skip-permissions \
    "${AGENT_PROMPT}" \
    > "${LOG_OUTPUT}" 2>"${OUTPUT_DIR}/agent.stderr" || true

echo "[entrypoint] Agent exited with code $?"

# 6. Collect the diff
git add -A
git diff --cached --no-color > "${DIFF_OUTPUT}" 2>/dev/null || true

DIFF_LINES=$(wc -l < "${DIFF_OUTPUT}" 2>/dev/null || echo "0")
echo "[entrypoint] Diff collected: ${DIFF_LINES} lines"

# 7. Build debug trace — full JSON events from opencode output
#    Each line in LOG_OUTPUT is a JSON event from --format json.
#    Wrap them into a JSON array for easy consumption.
echo "[" > "${DEBUG_TRACE}"
first=true
while IFS= read -r line; do
    # Only include lines that look like JSON objects
    if echo "${line}" | grep -q '^{'; then
        if [ "${first}" = true ]; then
            first=false
        else
            echo "," >> "${DEBUG_TRACE}"
        fi
        echo "${line}" >> "${DEBUG_TRACE}"
    fi
done < "${LOG_OUTPUT}"
echo "]" >> "${DEBUG_TRACE}"

TRACE_EVENTS=$(grep -c '^{' "${LOG_OUTPUT}" 2>/dev/null || echo "0")
echo "[entrypoint] Trace: ${TRACE_EVENTS} events saved"

# 8. Extract token usage from opencode JSON events
#    opencode step_finish events have: "tokens":{"total":N,"input":N,"output":N}
INPUT_TOKENS=$(grep -oP '"input"\s*:\s*\K\d+' "${LOG_OUTPUT}" 2>/dev/null \
    | awk '{s+=$1}END{print s+0}')
OUTPUT_TOKENS=$(grep -oP '"output"\s*:\s*\K\d+' "${LOG_OUTPUT}" 2>/dev/null \
    | awk '{s+=$1}END{print s+0}')
TOTAL_TOKENS=$((INPUT_TOKENS + OUTPUT_TOKENS))

cat > "${USAGE_OUTPUT}" <<USAGE_EOF
{"prompt_tokens": ${INPUT_TOKENS}, "completion_tokens": ${OUTPUT_TOKENS}, "total_tokens": ${TOTAL_TOKENS}}
USAGE_EOF

echo "[entrypoint] Agent tokens: input=${INPUT_TOKENS} output=${OUTPUT_TOKENS} total=${TOTAL_TOKENS}"

# 9. Debug: print summary if BENCH_DEBUG=1
if [ "${BENCH_DEBUG:-0}" = "1" ]; then
    echo ""
    echo "========== DEBUG: agent.stderr =========="
    cat "${OUTPUT_DIR}/agent.stderr" 2>/dev/null || true
    echo ""
    echo "========== DEBUG: trace events =========="
    head -50 "${LOG_OUTPUT}" 2>/dev/null || true
    echo ""
    echo "========== DEBUG: diff head =========="
    head -30 "${DIFF_OUTPUT}" 2>/dev/null || true
    echo ""
    echo "========== DEBUG: skills check =========="
    ls -la .opencode/skills/software-security/ 2>/dev/null || echo "No skills installed"
    ls .opencode/skills/software-security/rules/ 2>/dev/null || true
fi

echo "[entrypoint] Done."
