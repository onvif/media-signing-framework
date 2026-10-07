#!/bin/sh
set -eu

MCP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sh "$MCP_DIR/scripts/setup.sh"
exec node "$MCP_DIR/src/server.mjs"
