#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
	echo "Usage: npm run demo:stdio -- <path-to-video.mp4> [case-id]" >&2
	exit 2
fi

MCP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sh "$MCP_DIR/scripts/setup.sh"
exec node "$MCP_DIR/src/client.mjs" "$@"
