# Runbook — Slack MCP Server (this fork, for Claude Code)

How to build, run, and wire this fork into Claude Code on Patrik's workstation. See [`SECURITY-AUDIT-2026-05-25.md`](./SECURITY-AUDIT-2026-05-25.md) for the audit that informs the defaults below.

| Field | Value |
| --- | --- |
| Repo path | `/home/patrik/git/data-pata/slack-mcp-server` |
| Pinned audit commit | `b88c0de` |
| Transport | `stdio` only — see audit F2 |
| Default tool surface | read-only allowlist — see audit F1 |
| Token source | 1Password Private vault, item `slack-mcp`, fields `xoxc` and `xoxd` |
| Secret-store CLI | `op` (1Password) |

## Build

Requires Go 1.25.

```bash
cd /home/patrik/git/data-pata/slack-mcp-server
GOFLAGS=-mod=readonly make build
```

Produces `./build/slack-mcp-server` with the git commit hash linked in via `-ldflags`. The wrapper verifies that hash at every launch (`EXPECTED_COMMIT` constant) and refuses to start on mismatch — that's the forcing function to re-audit after every upstream pull.

`GOFLAGS=-mod=readonly` makes the build fail loud if `go.sum` would change. Without it, `make build` runs `go mod tidy` first and can silently shift transitive dependencies. Vendoring (`go mod vendor` once, then `-mod=vendor`) is a stronger guarantee if you want it; for now `readonly` is enough.

Re-run after any `git pull` from upstream. Cross-platform builds via `make build-all-platforms` if needed.

## Token setup (one-time)

Extract the browser-session credentials from a logged-in Slack web tab:

- **xoxc-…** — Chrome DevTools → Console → `JSON.parse(localStorage.localConfig_v2).teams[document.location.pathname.match(/^\/client\/([A-Z0-9]+)/)[1]].token`
- **xoxd-…** — Chrome DevTools → Application → Cookies → value of the `d` cookie

If the xoxc snippet returns `undefined`, the Slack web client's localStorage schema may have changed — check the upstream `docs/01-authentication-setup.md` for the current extraction recipe.

Store them in 1Password:

```bash
op item create --category=login --title=slack-mcp --vault=Private \
  xoxc="xoxc-…" xoxd="xoxd-…"
```

Or create through the 1Password UI and add custom fields `xoxc` and `xoxd`. The wrapper script reads them at `op://Private/slack-mcp/xoxc` and `op://Private/slack-mcp/xoxd`.

## Smoke test

```bash
SLACK_MCP_XOXC_TOKEN=demo SLACK_MCP_XOXD_TOKEN=demo \
  ./build/slack-mcp-server --transport stdio
```

`demo` tokens skip the Slack call; the server boots, logs "Slack MCP Server is fully ready" on stderr, and blocks waiting for JSON-RPC on stdin. Ctrl-C to exit. If this works, the binary itself is healthy.

For a real smoke test, run the wrapper directly:

```bash
./run-claude-code.sh
```

It should fetch tokens from 1Password (you may get a touch-ID / unlock prompt) and reach "ready" without `Error booting provider`. Same Ctrl-C to exit.

## Wire into Claude Code

Pick whichever Claude Code profile matches the Slack workspace you're targeting (e.g. `CLAUDE_CONFIG_DIR=~/.claude` for a work profile, `~/.claude-personal` for personal).

```bash
CLAUDE_CONFIG_DIR=~/.claude claude mcp add slack \
  -- /home/patrik/git/data-pata/slack-mcp-server/run-claude-code.sh
```

Stdio is `claude mcp add`'s default transport; no `--transport` flag needed. Don't pass `-e SLACK_MCP_XOX*` — the wrapper handles tokens via 1Password. Don't pass `--enabled-tools` here — the wrapper bakes the read-only allowlist in. Extra args go after the wrapper path: `claude mcp add slack -- /path/to/run-claude-code.sh --enabled-tools …`.

Verify Claude Code sees the server:

```bash
claude mcp list
```

## What ends up on disk

- **The built binary** at `./build/slack-mcp-server`. Embedded commit hash; the wrapper verifies it at launch.
- **The user/channel cache** at `~/.cache/slack-mcp-server/` (or `$XDG_CACHE_HOME/slack-mcp-server/`). Per-team JSON files (`<TEAMID>_users_cache.json`, etc.) at `0600` containing the full Slack workspace directory — names, emails, phones, titles, custom profile fields, and Slack Connect external users. Persists indefinitely; `cacheTTL` controls refresh only, not deletion. Pass `--no-cache` for ad-hoc runs where `@username` / `#channel` resolution isn't worth keeping the directory on disk, and include the cache path in any laptop-rotation procedure.
- **No tokens.** Tokens live only in the running process's environment (visible to same-UID processes via `/proc/<pid>/environ`), pulled fresh from 1Password each launch.

## Adjusting the tool surface

The wrapper defaults to read-only. To allow message-posting in a one-off Claude Code session:

```bash
./run-claude-code.sh --enabled-tools conversations_history,conversations_replies,conversations_add_message
# also set SLACK_MCP_ADD_MESSAGE_TOOL=true (or a comma-separated channel allowlist)
```

`conversations_add_message`, `reactions_add`, `reactions_remove`, `attachment_get_data`, and `conversations_mark` are properly gated by their own env vars and are safe to add to the allowlist. The audit-F1 tools (`usergroups_users_update`, `conversations_leave`, etc.) are not gated and should stay out of the allowlist unless deliberately enabled.

## Upgrade flow (when upstream releases something interesting)

```bash
cd /home/patrik/git/data-pata/slack-mcp-server
git fetch origin
git log --oneline HEAD..origin/master   # what's new
# Review diffs in security-relevant paths:
git diff HEAD..origin/master -- pkg/transport/ pkg/server/auth/ pkg/provider/edge/ go.mod
git merge origin/master                 # only after the review is clean
GOFLAGS=-mod=readonly make build
```

Re-verify line refs in F1–F4 (and the cleared items) still match the new source. Add a dated audit section to `SECURITY-AUDIT-2026-05-25.md` (or create a new dated file) describing what you re-checked. **Only then** update `EXPECTED_COMMIT` in `run-claude-code.sh` to the new short hash. The wrapper refuses to launch until you do — that's the forcing function.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `slack-mcp-server binary missing` | `make build` not run, or run on a different machine |
| `Built binary does not carry audited commit` | The source moved past `EXPECTED_COMMIT`; re-audit, then bump the constant in `run-claude-code.sh` |
| `op returned an empty token` | The `xoxc` or `xoxd` field in the 1Password `slack-mcp` item is missing / renamed |
| `Error booting provider` on startup | Token expired (logout, password change, admin revoke); re-extract from a fresh Slack web session |
| 1Password prompts on every invocation | `op` session expired; `op signin` or enable biometric unlock in the 1Password app |
| Claude Code says "MCP server crashed" | Run the wrapper manually first — stderr will carry the real error (`op read` failure, drift-check failure, missing 1Password item, etc.) |
