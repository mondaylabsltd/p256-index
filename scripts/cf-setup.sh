#!/bin/bash
# CF Worker setup: creates D1 database (idempotent) and generates wrangler.json
set -e

DB_NAME="webauthnp256-queue"
CONFIG_FILE="wrangler.jsonc"

echo "Checking for existing D1 database '$DB_NAME'..."
DB_ID=$(npx wrangler d1 list 2>/dev/null | grep -E "(^|[[:space:]|])$DB_NAME([[:space:]|]|$)" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1 || true)

if [ -z "$DB_ID" ]; then
  echo "Creating D1 database '$DB_NAME'..."
  CREATE_OUTPUT=$(npx wrangler d1 create "$DB_NAME" 2>&1)
  DB_ID=$(echo "$CREATE_OUTPUT" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)
  if [ -z "$DB_ID" ]; then
    echo "Failed to extract database_id. Output:"
    echo "$CREATE_OUTPUT"
    exit 1
  fi
  echo "Created D1 database: $DB_ID"
else
  echo "Found existing D1 database: $DB_ID"
fi

# Patch the COMMITTED wrangler.jsonc in place (idempotent). The config is now
# version-controlled — production CF deployment is reproducible from the repo
# (previously the deployed wrangler.json was generated and gitignored while the
# committed wrangler.jsonc was dead, so prod config drifted invisibly).
if grep -q "\"database_id\": \"$DB_ID\"" "$CONFIG_FILE"; then
  echo "$CONFIG_FILE already references database_id: $DB_ID"
else
  sed -i.bak -E "s/\"database_id\": \"[^\"]*\"/\"database_id\": \"$DB_ID\"/" "$CONFIG_FILE" && rm -f "$CONFIG_FILE.bak"
  echo "Updated $CONFIG_FILE with database_id: $DB_ID (commit this change)"
fi

echo ""
echo "Next steps:"
echo "  npx wrangler secret put PRIVATE_KEY"
echo "  npx wrangler secret put TELEGRAM_BOT_TOKEN"
echo "  npx wrangler secret put TELEGRAM_CHAT_ID"
echo "  npx wrangler secret put ALCHEMY_API_KEY   # optional: priority write RPC"
echo "  npm run deploy"
