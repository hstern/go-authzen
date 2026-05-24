#!/bin/sh
# govulncheck → Forgejo issues, reconciled against MAIN. Source mode (this is a library
# module — there's no shipping binary to scan), so govulncheck walks the import graph from
# every package under ./... and reports the deps reachable from any of them.
#
# Makes the open `vulnerability` issues match the findings:
#   - opens one issue per affecting vuln not already tracked (deduped by OSV id), and
#   - auto-closes any open `vulnerability` issue whose OSV id is no longer detected (fixed).
#
# Issues track main's state, so the issue side runs only on an AUTHORITATIVE event — a push to
# main or the scheduled run. Anywhere else — a manual dispatch off a branch, or no token — it
# stays report-only. NON-BLOCKING: a finding never fails the job (the tracked issue is the
# signal); the job fails only if the scan itself errors.
#
# Env (the workflow passes these): FORGEJO_TOKEN (Actions token, needs issue:write),
# GITHUB_REPOSITORY (owner/repo), GITHUB_API_URL (instance API root), GITHUB_REF_NAME +
# GITHUB_EVENT_NAME (to decide authoritative).
set -u
API="${GITHUB_API_URL:-https://git.stern.ca/api/v1}"
REPO="${GITHUB_REPOSITORY:-}"

# 1) Scan. Exit 0 = clean, 3 = vulns found; anything else is a real error → fail the job.
json=$(govulncheck -json ./...)
rc=$?
if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
  echo "ERROR: govulncheck failed (exit $rc)" >&2
  printf '%s\n' "$json" | tail -20 >&2
  exit 1
fi

# 2) Distinct AFFECTING vulns: findings whose trace reaches a function (source mode's "your code
#    is affected by" set), joined to their summary. One row per vuln: ID|MODULE|FIXED|SUMMARY.
rows=$(printf '%s' "$json" | jq -rs '
  (map(select(.osv).osv) | map({key:.id, value:(.summary // "(no summary)")}) | from_entries) as $sum
  | map(select(.finding).finding)
  | map(select(any(.trace[]?; .function != null)))
  | unique_by(.osv)
  | .[]
  | "\(.osv)|\(.trace[0].module // "?")|\(.fixed_version // "unspecified")|\($sum[.osv] // "(no summary)")"
')
ids=$(printf '%s\n' "$rows" | sed '/^$/d' | cut -d'|' -f1 | sort -u)

if [ -n "$rows" ]; then
  echo "govulncheck — affecting vulnerabilities:"
  printf '%s\n' "$rows" | sed 's/^/  /'
else
  echo "govulncheck found no affecting vulnerabilities."
fi

# 3) Reconcile issues only on an authoritative run (issues mirror main). Else report-only.
authoritative=0
[ "${GITHUB_REF_NAME:-}" = "main" ] && authoritative=1
[ "${GITHUB_EVENT_NAME:-}" = "schedule" ] && authoritative=1
if [ -z "${FORGEJO_TOKEN:-}" ] || [ -z "$REPO" ] || [ "$authoritative" -ne 1 ]; then
  echo "(report-only — not reconciling issues)"
  exit 0
fi

auth="Authorization: token $FORGEJO_TOKEN"
ctype="Content-Type: application/json"

# 4) Ensure a "vulnerability" label exists; resolve its id (best-effort — issues create without).
label_id=$(curl -fsS -H "$auth" "$API/repos/$REPO/labels" \
  | jq -r '.[] | select(.name=="vulnerability") | .id' 2>/dev/null | head -1)
if [ -z "$label_id" ]; then
  label_id=$(curl -fsS -X POST -H "$auth" -H "$ctype" \
    -d '{"name":"vulnerability","color":"#d73a4a","description":"govulncheck finding"}' \
    "$API/repos/$REPO/labels" 2>/dev/null | jq -r '.id // empty')
fi

# 5) Open one issue per affecting vuln, deduped against OPEN issues (search by OSV id in title).
printf '%s\n' "$rows" | while IFS='|' read -r id module fixed summary; do
  [ -n "$id" ] || continue
  hit=$(curl -fsS -H "$auth" "$API/repos/$REPO/issues?state=open&type=issues&q=$id" 2>/dev/null \
    | jq -r --arg id "$id" '.[]? | select(.title | contains($id)) | .number' 2>/dev/null | head -1)
  if [ -n "$hit" ]; then
    echo "  skip $id — already tracked in #$hit"
    continue
  fi
  title="[vuln] $id: $module"
  body=$(printf '`govulncheck` found a vulnerability reachable from the source tree on `main`.\n\n- **ID:** [%s](https://pkg.go.dev/vuln/%s)\n- **Module:** `%s`\n- **Fixed in:** `%s`\n- **Summary:** %s\n\n**Fix:** bump `%s` to the fixed version. The `vuln` workflow auto-closes this issue once the fix lands on `main`.\n\n_Opened automatically by the `vuln` workflow; deduped against open issues._' \
    "$id" "$id" "$module" "$fixed" "$summary" "$module")
  payload=$(jq -n --arg t "$title" --arg b "$body" --arg l "${label_id:-}" \
    '{title:$t, body:$b} + (if $l=="" then {} else {labels:[($l|tonumber)]} end)')
  num=$(curl -fsS -X POST -H "$auth" -H "$ctype" -d "$payload" "$API/repos/$REPO/issues" 2>/dev/null | jq -r '.number // "?"')
  echo "  opened $id — issue #$num"
done

# 6) Auto-close: any OPEN `vulnerability` issue whose OSV id is no longer detected has been
#    fixed on main. Close it with a note. (Only `vulnerability`-labelled issues; title format
#    `[vuln] <id>: ...` yields the id — anything else is left alone.)
curl -fsS -H "$auth" "$API/repos/$REPO/issues?state=open&type=issues&labels=vulnerability" 2>/dev/null \
  | jq -r '.[]? | "\(.number)|\(.title)"' \
  | while IFS='|' read -r num title; do
      id=$(printf '%s' "$title" | sed -n 's/^\[vuln\] \([^:]*\):.*/\1/p')
      [ -n "$id" ] || continue
      if printf '%s\n' "$ids" | grep -qx "$id"; then
        continue   # still affecting — leave open
      fi
      curl -fsS -X POST -H "$auth" -H "$ctype" \
        -d '{"body":"Resolved — `govulncheck` no longer detects this on `main`. Auto-closed by the `vuln` workflow."}' \
        "$API/repos/$REPO/issues/$num/comments" >/dev/null 2>&1
      curl -fsS -X PATCH -H "$auth" -H "$ctype" -d '{"state":"closed"}' \
        "$API/repos/$REPO/issues/$num" >/dev/null 2>&1
      echo "  closed #$num — $id no longer detected"
    done

echo "vuln reconcile complete."
