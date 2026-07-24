#!/usr/bin/env bash
# gh-handle-spam <issue-or-pr-number>
# Requires: gh CLI + a PAT with user:write scope if blocking users

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: gh-handle-spam <issue-or-pr-number>"
  exit 1
fi

NUM="$1"
REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
ORG="$(echo "$REPO" | cut -d/ -f1)"

# Get type (issue or PR) and author
DATA="$(gh api /repos/$REPO/issues/$NUM)"
AUTHOR="$(echo "$DATA" | jq -r .user.login)"
IS_PR="$(echo "$DATA" | jq -r '.pull_request // empty')"

if [ -n "$IS_PR" ]; then
  TYPE="pr"
else
  TYPE="issue"
fi

echo "Cleaning spam $TYPE #$NUM from @$AUTHOR in $REPO..."

# 1. Close
gh "$TYPE" close "$NUM" --repo "$REPO" -c "Closing as spam."

# 2. Lock
gh "$TYPE" lock "$NUM" --repo "$REPO" --reason spam || true

# 3. Label (create 'spam' label if missing)
if ! gh label list --repo "$REPO" | grep -q '^spam'; then
  gh label create spam --repo "$REPO" --color FF0000 --description "SPAM"
fi
gh "$TYPE" edit "$NUM" --repo "$REPO" --add-label spam

# 4. Block user (personal account only, requires token with user:write)
echo "Blocking @$AUTHOR from personal account..."
gh api --method PUT "/user/blocks/$AUTHOR" >/dev/null || {
  echo "Failed to block @$AUTHOR in personal account (check token scope)."
}

CURRENT_USER="$(gh api /user --jq .login)"
if [ "$ORG" != "$CURRENT_USER" ]; then
  echo "Blocking @$AUTHOR from org $ORG..."
  gh api --method PUT "/orgs/$ORG/blocks/$AUTHOR" >/dev/null || {
    echo "Failed to block @$AUTHOR in org $ORG (need admin:org scope)."
  }
fi

echo "Done: $TYPE #$NUM closed, locked, labeled spam, and @$AUTHOR blocked."
