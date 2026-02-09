#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# CodeGraph Security Scan — GitHub Action entrypoint
#
# Indexes the target directory, starts the MCP HTTP server, runs security
# scans via MCP tool calls, formats results as markdown, and optionally
# posts a PR comment.
# ---------------------------------------------------------------------------
set -euo pipefail

DIRECTORY="${1:-.}"
SEVERITY="${2:-medium}"
COMMENT_ON_PR="${3:-true}"
MCP_PORT=19876
MCP_URL="http://127.0.0.1:${MCP_PORT}/mcp"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

severity_rank() {
  case "$1" in
    info)     echo 0 ;;
    low)      echo 1 ;;
    medium)   echo 2 ;;
    high)     echo 3 ;;
    critical) echo 4 ;;
    Info)     echo 0 ;;
    Low)      echo 1 ;;
    Medium)   echo 2 ;;
    High)     echo 3 ;;
    Critical) echo 4 ;;
    *)        echo 0 ;;
  esac
}

severity_emoji() {
  case "$1" in
    Critical) echo ":red_circle:" ;;
    High)     echo ":orange_circle:" ;;
    Medium)   echo ":yellow_circle:" ;;
    Low)      echo ":white_circle:" ;;
    Info)     echo ":blue_circle:" ;;
    *)        echo ":white_circle:" ;;
  esac
}

# Send a JSON-RPC request to the MCP server and return the result.
# Uses the MCP streamable HTTP protocol (POST with JSON-RPC body).
mcp_call() {
  local method="$1"
  local params="$2"
  local id="${3:-1}"

  local body
  body=$(jq -n \
    --arg method "$method" \
    --arg id "$id" \
    --argjson params "$params" \
    '{"jsonrpc":"2.0","id":($id|tonumber),"method":$method,"params":$params}')

  curl -s -X POST "$MCP_URL" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -d "$body"
}

# Wait for the MCP server to be ready (up to 30 seconds).
wait_for_server() {
  local attempts=0
  local max_attempts=60
  while [ $attempts -lt $max_attempts ]; do
    if curl -s -o /dev/null -w "%{http_code}" "$MCP_URL" 2>/dev/null | grep -qE "^[2-5][0-9][0-9]$"; then
      return 0
    fi
    sleep 0.5
    attempts=$((attempts + 1))
  done
  echo "::error::MCP server failed to start within 30 seconds"
  return 1
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

echo "::group::CodeGraph Security Scan"
echo "Directory: ${DIRECTORY}"
echo "Minimum severity: ${SEVERITY}"
echo "Comment on PR: ${COMMENT_ON_PR}"

# Resolve workspace directory
WORKSPACE="${GITHUB_WORKSPACE:-$(pwd)}"
if [[ "$DIRECTORY" = /* ]]; then
  SCAN_DIR="$DIRECTORY"
else
  SCAN_DIR="${WORKSPACE}/${DIRECTORY}"
fi
SCAN_DIR=$(cd "$SCAN_DIR" && pwd)

echo "Resolved scan directory: ${SCAN_DIR}"

# Step 1: Index the codebase
echo "::group::Indexing codebase"
cd "$SCAN_DIR"
codegraph index "$SCAN_DIR" 2>&1
echo "::endgroup::"

# Step 2: Start MCP HTTP server in the background
echo "::group::Starting MCP server"
codegraph serve --db "${SCAN_DIR}/.codegraph/codegraph.db" --http "127.0.0.1:${MCP_PORT}" &
MCP_PID=$!

# Ensure cleanup on exit
cleanup() {
  if kill -0 "$MCP_PID" 2>/dev/null; then
    kill "$MCP_PID" 2>/dev/null || true
    wait "$MCP_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

wait_for_server
echo "MCP server ready (PID: ${MCP_PID})"
echo "::endgroup::"

# Step 3: Initialize MCP session
echo "::group::Running security scans"
INIT_RESPONSE=$(mcp_call "initialize" '{
  "protocolVersion": "2025-03-26",
  "capabilities": {},
  "clientInfo": {"name": "codegraph-gh-action", "version": "1.0.0"}
}' 1)

SESSION_ID=$(echo "$INIT_RESPONSE" | jq -r '.result.sessionId // empty' 2>/dev/null || true)

# Step 4: Call codegraph_scan_security
SCAN_RESPONSE=$(mcp_call "tools/call" "{
  \"name\": \"codegraph_scan_security\",
  \"arguments\": {\"directory\": \"${SCAN_DIR}\"}
}" 2)

SCAN_RESULT=$(echo "$SCAN_RESPONSE" | jq -r '.result.content[0].text // empty' 2>/dev/null || true)

# Step 5: Call codegraph_check_owasp
OWASP_RESPONSE=$(mcp_call "tools/call" "{
  \"name\": \"codegraph_check_owasp\",
  \"arguments\": {\"directory\": \"${SCAN_DIR}\"}
}" 3)

OWASP_RESULT=$(echo "$OWASP_RESPONSE" | jq -r '.result.content[0].text // empty' 2>/dev/null || true)

# Step 6: Call codegraph_check_cwe
CWE_RESPONSE=$(mcp_call "tools/call" "{
  \"name\": \"codegraph_check_cwe\",
  \"arguments\": {\"directory\": \"${SCAN_DIR}\"}
}" 4)

CWE_RESULT=$(echo "$CWE_RESPONSE" | jq -r '.result.content[0].text // empty' 2>/dev/null || true)

echo "::endgroup::"

# Step 7: Parse results and apply severity filter
MIN_RANK=$(severity_rank "$SEVERITY")

# Extract findings from the general scan (primary source)
TOTAL_FINDINGS=$(echo "$SCAN_RESULT" | jq -r '.totalFindings // 0' 2>/dev/null || echo 0)
CRITICAL=$(echo "$SCAN_RESULT" | jq -r '.critical // 0' 2>/dev/null || echo 0)
HIGH=$(echo "$SCAN_RESULT" | jq -r '.high // 0' 2>/dev/null || echo 0)
MEDIUM=$(echo "$SCAN_RESULT" | jq -r '.medium // 0' 2>/dev/null || echo 0)
LOW=$(echo "$SCAN_RESULT" | jq -r '.low // 0' 2>/dev/null || echo 0)
FILES_SCANNED=$(echo "$SCAN_RESULT" | jq -r '.filesScanned // 0' 2>/dev/null || echo 0)
RULES_APPLIED=$(echo "$SCAN_RESULT" | jq -r '.rulesApplied // 0' 2>/dev/null || echo 0)

OWASP_TOTAL=$(echo "$OWASP_RESULT" | jq -r '.totalFindings // 0' 2>/dev/null || echo 0)
CWE_TOTAL=$(echo "$CWE_RESULT" | jq -r '.totalFindings // 0' 2>/dev/null || echo 0)

# ---------------------------------------------------------------------------
# Step 8: Build markdown report
# ---------------------------------------------------------------------------

REPORT=""
REPORT+="## :shield: CodeGraph Security Scan Results\n\n"

# Summary table
REPORT+="| Metric | Value |\n"
REPORT+="|--------|-------|\n"
REPORT+="| Files scanned | ${FILES_SCANNED} |\n"
REPORT+="| Rules applied | ${RULES_APPLIED} |\n"
REPORT+="| Total findings | ${TOTAL_FINDINGS} |\n"
REPORT+="| :red_circle: Critical | ${CRITICAL} |\n"
REPORT+="| :orange_circle: High | ${HIGH} |\n"
REPORT+="| :yellow_circle: Medium | ${MEDIUM} |\n"
REPORT+="| :white_circle: Low | ${LOW} |\n"
REPORT+="| OWASP Top 10 findings | ${OWASP_TOTAL} |\n"
REPORT+="| CWE Top 25 findings | ${CWE_TOTAL} |\n\n"

# Filtered findings table
if [ "$TOTAL_FINDINGS" -gt 0 ] 2>/dev/null; then
  FILTERED_FINDINGS=$(echo "$SCAN_RESULT" | jq -c --arg min "$MIN_RANK" '
    [.findings[]? | select(
      (if .severity == "Critical" then 4
       elif .severity == "High" then 3
       elif .severity == "Medium" then 2
       elif .severity == "Low" then 1
       else 0 end) >= ($min | tonumber)
    )]' 2>/dev/null || echo "[]")

  FILTERED_COUNT=$(echo "$FILTERED_FINDINGS" | jq 'length' 2>/dev/null || echo 0)

  if [ "$FILTERED_COUNT" -gt 0 ] 2>/dev/null; then
    REPORT+="### Findings (severity >= ${SEVERITY})\n\n"
    REPORT+="| Severity | File | Line | Rule | Message |\n"
    REPORT+="|----------|------|------|------|--------|\n"

    echo "$FILTERED_FINDINGS" | jq -c '.[]' 2>/dev/null | head -50 | while IFS= read -r finding; do
      sev=$(echo "$finding" | jq -r '.severity // "Unknown"')
      file=$(echo "$finding" | jq -r '.file // "?"')
      line=$(echo "$finding" | jq -r '.line // "?"')
      rule=$(echo "$finding" | jq -r '.ruleName // .ruleId // "?"')
      msg=$(echo "$finding" | jq -r '.message // "?"' | head -c 100)
      emoji=$(severity_emoji "$sev")

      # Make file path relative to workspace
      rel_file="${file#"${SCAN_DIR}/"}"

      echo "| ${emoji} ${sev} | \`${rel_file}\` | ${line} | ${rule} | ${msg} |"
    done > /tmp/findings_table.txt

    REPORT+=$(cat /tmp/findings_table.txt 2>/dev/null || true)
    REPORT+="\n\n"

    if [ "$FILTERED_COUNT" -gt 50 ]; then
      REPORT+="*... and $((FILTERED_COUNT - 50)) more findings (showing top 50)*\n\n"
    fi
  else
    REPORT+="### :white_check_mark: No findings at severity >= ${SEVERITY}\n\n"
  fi

  # Top issues
  TOP_ISSUES=$(echo "$SCAN_RESULT" | jq -c '.topIssues // []' 2>/dev/null || echo "[]")
  TOP_COUNT=$(echo "$TOP_ISSUES" | jq 'length' 2>/dev/null || echo 0)

  if [ "$TOP_COUNT" -gt 0 ] 2>/dev/null; then
    REPORT+="### Top Issues\n\n"
    echo "$TOP_ISSUES" | jq -c '.[]' 2>/dev/null | while IFS= read -r issue; do
      rule=$(echo "$issue" | jq -r '.rule // "?"')
      count=$(echo "$issue" | jq -r '.count // 0')
      echo "- **${rule}**: ${count} occurrences"
    done > /tmp/top_issues.txt
    REPORT+=$(cat /tmp/top_issues.txt 2>/dev/null || true)
    REPORT+="\n\n"
  fi
else
  REPORT+="### :white_check_mark: No security findings detected\n\n"
fi

REPORT+="---\n"
REPORT+="*Scanned by [CodeGraph](https://github.com/suatkocar/codegraph) v$(codegraph --version 2>/dev/null | head -1 || echo 'unknown')*\n"

# ---------------------------------------------------------------------------
# Step 9: Write to GitHub Step Summary
# ---------------------------------------------------------------------------

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  echo -e "$REPORT" >> "$GITHUB_STEP_SUMMARY"
  echo "Report written to GITHUB_STEP_SUMMARY"
fi

# ---------------------------------------------------------------------------
# Step 10: Post PR comment if requested
# ---------------------------------------------------------------------------

if [ "$COMMENT_ON_PR" = "true" ] && [ -n "${GITHUB_EVENT_NAME:-}" ]; then
  if [ "$GITHUB_EVENT_NAME" = "pull_request" ] || [ "$GITHUB_EVENT_NAME" = "pull_request_target" ]; then
    PR_NUMBER=$(jq -r '.pull_request.number // empty' "${GITHUB_EVENT_PATH:-/dev/null}" 2>/dev/null || true)
    if [ -n "$PR_NUMBER" ] && command -v gh >/dev/null 2>&1; then
      echo "Posting comment to PR #${PR_NUMBER}"
      echo -e "$REPORT" | gh pr comment "$PR_NUMBER" --body-file - 2>/dev/null || \
        echo "::warning::Failed to post PR comment (missing GITHUB_TOKEN permissions?)"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Step 11: Set outputs and exit code
# ---------------------------------------------------------------------------

# Set action outputs
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "total-findings=${TOTAL_FINDINGS}" >> "$GITHUB_OUTPUT"
  echo "critical=${CRITICAL}" >> "$GITHUB_OUTPUT"
  echo "high=${HIGH}" >> "$GITHUB_OUTPUT"
  echo "medium=${MEDIUM}" >> "$GITHUB_OUTPUT"
  echo "low=${LOW}" >> "$GITHUB_OUTPUT"
  echo "owasp-findings=${OWASP_TOTAL}" >> "$GITHUB_OUTPUT"
  echo "cwe-findings=${CWE_TOTAL}" >> "$GITHUB_OUTPUT"
fi

echo "::endgroup::"

# Print summary to console
echo ""
echo "=== Security Scan Summary ==="
echo "Files scanned:    ${FILES_SCANNED}"
echo "Total findings:   ${TOTAL_FINDINGS}"
echo "  Critical:       ${CRITICAL}"
echo "  High:           ${HIGH}"
echo "  Medium:         ${MEDIUM}"
echo "  Low:            ${LOW}"
echo "OWASP findings:   ${OWASP_TOTAL}"
echo "CWE findings:     ${CWE_TOTAL}"
echo ""

# Fail the action if critical or high findings exist
if [ "${CRITICAL:-0}" -gt 0 ]; then
  echo "::error::${CRITICAL} critical security finding(s) detected"
  exit 1
elif [ "${HIGH:-0}" -gt 0 ]; then
  echo "::warning::${HIGH} high severity security finding(s) detected"
fi

exit 0
