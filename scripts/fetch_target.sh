#!/usr/bin/env bash
# Fetch the evaluation target (Langflow) at a PINNED ref into targets/.
# The target is never vendored into this repo (see .gitignore) so we don't
# redistribute someone else's code; anyone re-running gets the identical revision.
#
# Usage: bash scripts/fetch_target.sh
set -euo pipefail

REPO_URL="https://github.com/langflow-ai/langflow.git"
PINNED_REF="1.7.3"          # keep in sync with config.yaml target.pinned_ref
DEST="targets/langflow"

cd "$(dirname "$0")/.."

if [ -d "$DEST/.git" ]; then
  echo "[fetch_target] $DEST already present; verifying ref..."
else
  echo "[fetch_target] cloning $REPO_URL @ $PINNED_REF (shallow) ..."
  mkdir -p targets
  git clone --depth 1 --branch "$PINNED_REF" "$REPO_URL" "$DEST"
fi

cd "$DEST"
HEAD_SHA="$(git rev-parse HEAD)"
echo "[fetch_target] HEAD = $HEAD_SHA (tag $PINNED_REF)"

# Sanity check: confirm the real compile/exec sink is present at this revision.
SINK_FILE="src/backend/base/langflow/helpers/flow.py"
if grep -qE "compile\(.*\"exec\"\)" "$SINK_FILE" && grep -qE "^\s*exec\(" "$SINK_FILE"; then
  echo "[fetch_target] OK: verified compile()/exec() sink present in $SINK_FILE"
else
  echo "[fetch_target] WARNING: expected compile/exec sink not found in $SINK_FILE at $PINNED_REF" >&2
  echo "[fetch_target] The pinned ref may have changed; review scope before running." >&2
fi

echo "[fetch_target] done."
