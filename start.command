#!/bin/bash
# Double-click launcher for macOS.
cd "$(dirname "$0")" || exit 1
if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is not installed. Get it from https://nodejs.org (version 18 or newer)."
  read -r -p "Press Enter to close."
  exit 1
fi
node server.js
read -r -p "Dabba stopped. Press Enter to close."
