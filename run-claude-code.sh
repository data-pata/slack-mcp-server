#!/usr/bin/env bash
# Launches the audited slack-mcp-server binary for Claude Code (stdio).
# Tokens are pulled from 1Password at exec time so they never live in any
# Claude config file on disk. They do live in this process's environment
# (and the child's /proc/<pid>/environ) — visible to same-UID processes,
# but no broader.
#
# Prerequisites:
#   1. 1Password CLI signed in (`op signin` or biometric unlock).
#   2. 1Password Private vault item titled "slack-mcp" with fields "xoxc"
#      and "xoxd" containing the browser-session values.
#   3. Binary built with `GOFLAGS=-mod=readonly make build`. The wrapper
#      refuses to launch if the binary doesn't carry the audited commit
#      hash — bump EXPECTED_COMMIT below only after re-auditing.
#
# Default tool allowlist is read-only (mitigates audit finding F1 — the
# unguarded write tools are not registered). Passing --enabled-tools (or
# -e) overrides; the wrapper detects the flag and skips its default so
# behaviour is predictable.

set -euo pipefail

SLACK_MCP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SLACK_MCP_BIN="$SLACK_MCP_DIR/build/slack-mcp-server"
EXPECTED_COMMIT="b88c0de"   # see SECURITY-AUDIT-2026-05-25.md
READ_ONLY_TOOLS="conversations_history,conversations_replies,conversations_search_messages,conversations_unreads,channels_list,channels_me,users_search,usergroups_list,saved_list"

if [[ ! -x "$SLACK_MCP_BIN" ]]; then
  echo "slack-mcp-server binary missing at $SLACK_MCP_BIN" >&2
  echo "Run 'GOFLAGS=-mod=readonly make build' in $SLACK_MCP_DIR" >&2
  exit 1
fi

# Drift guard: the binary embeds the git commit hash via -X ldflags, so
# grep -aF on the file finds it. On mismatch, refuse to launch —
# re-audit before bumping EXPECTED_COMMIT.
if ! grep -qaF "$EXPECTED_COMMIT" "$SLACK_MCP_BIN"; then
  echo "Built binary does not carry audited commit ($EXPECTED_COMMIT)." >&2
  echo "Re-audit per SECURITY-AUDIT-2026-05-25.md before bumping EXPECTED_COMMIT in this script." >&2
  exit 1
fi

if ! command -v op >/dev/null 2>&1; then
  echo "1Password CLI ('op') not found on PATH" >&2
  exit 1
fi

SLACK_MCP_XOXC_TOKEN="$(op read 'op://Private/slack-mcp/xoxc')" \
  || { echo "Failed to read xoxc from 1Password (op://Private/slack-mcp/xoxc)" >&2; exit 1; }
SLACK_MCP_XOXD_TOKEN="$(op read 'op://Private/slack-mcp/xoxd')" \
  || { echo "Failed to read xoxd from 1Password (op://Private/slack-mcp/xoxd)" >&2; exit 1; }

if [[ -z "$SLACK_MCP_XOXC_TOKEN" || -z "$SLACK_MCP_XOXD_TOKEN" ]]; then
  echo "op returned an empty token — verify 'slack-mcp' in 1Password has both 'xoxc' and 'xoxd' fields populated" >&2
  exit 1
fi

export SLACK_MCP_XOXC_TOKEN SLACK_MCP_XOXD_TOKEN
export SLACK_MCP_LOG_LEVEL="${SLACK_MCP_LOG_LEVEL:-warn}"   # F4 — silence per-request param logging

# If the caller passed --enabled-tools / -e, don't double-up.
has_tools_override=false
for arg in "$@"; do
  case "$arg" in
    --enabled-tools|--enabled-tools=*|-e|-e=*) has_tools_override=true; break ;;
  esac
done

if "$has_tools_override"; then
  exec "$SLACK_MCP_BIN" --transport stdio "$@"
else
  exec "$SLACK_MCP_BIN" --transport stdio --enabled-tools "$READ_ONLY_TOOLS" "$@"
fi
