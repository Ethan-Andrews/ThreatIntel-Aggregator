#!/bin/bash
set -e

echo "[1/5] Installing sandbox dependencies..."
sudo apt-get update -qq && sudo apt-get install -y bubblewrap socat

echo "[2/5] Installing Claude Code CLI..."
npm install -g @anthropic-ai/claude-code

echo "[3/5] Fixing bind-mount ownership..."
sudo chown -R vscode:vscode /home/vscode/.claude

echo "[4/5] Hardening .claude directory permissions..."
chmod 700 /home/vscode/.claude
find /home/vscode/.claude -type f -exec chmod 600 {} \;

echo "[5/5] Checking .env..."
if [ -f /workspaces/TI_RSS_Feed/backend/.env ]; then
    echo "[info] .env exists. Chmod skipped — 9p WSL2 mount, permissions NTFS-controlled."
    echo "[info] Protection: Claude Code sandbox deny rule active. Set NTFS ACLs on Windows host."
else
    echo "[info] .env not found — skipping."
fi

echo "[done] Post-create complete. Run 'claude login' to authenticate."