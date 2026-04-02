#!/usr/bin/env bash
# DepVet Docker runner — security-hardened execution
#
# Usage:
#   ./docker-run.sh scan requests 2.31.0 2.32.0
#   ./docker-run.sh monitor --top 100 --once
#   ./docker-run.sh watchlist list

set -euo pipefail

IMAGE="${DEPVET_IMAGE:-depvet:latest}"

exec docker run \
  --rm \
  --read-only \
  --tmpfs /tmp:size=512m,noexec,nosuid \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --network host \
  -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY:-}" \
  -e OPENAI_API_KEY="${OPENAI_API_KEY:-}" \
  -e DEPVET_LOG_LEVEL="${DEPVET_LOG_LEVEL:-WARNING}" \
  "$IMAGE" \
  "$@"
