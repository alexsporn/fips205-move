#!/usr/bin/env bash
set -euo pipefail

# === Configuration ===
FUNDING_ADDRESS="0x4993f3eee84c4fc748b54c217de9ac0b28d65e7802c2f4b2bcc33570fbf798ba"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# === Switch to funding address ===
echo "Switching to funding address..."
iota client switch --address "$FUNDING_ADDRESS"
iota client faucet
sleep 1

# === Build ===
echo ""
echo "Building Move package..."
iota move build

# === Publish ===
echo ""
echo "Publishing package..."
PUBLISH_OUTPUT=$(iota client publish --json --gas-budget 5000000000)

# === Extract IDs from publish output ===
PACKAGE_ID=$(echo "$PUBLISH_OUTPUT" | jq -r '.objectChanges[] | select(.type == "published") | .packageId')

if [ -z "$PACKAGE_ID" ] || [ "$PACKAGE_ID" = "null" ]; then
    echo "ERROR: Failed to extract package ID from publish output"
    echo "$PUBLISH_OUTPUT" | jq .
    exit 1
fi


echo ""
echo "Deployed successfully!"
echo "  Package ID:  $PACKAGE_ID"
