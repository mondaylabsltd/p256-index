#!/bin/bash
# CF Worker setup: creates D1 database (idempotent) and generates wrangler.json
set -e

DB_NAME="webauthnp256-queue"
CONFIG_OUTPUT="wrangler.json"

echo "Checking for existing D1 database '$DB_NAME'..."
DB_ID=$(npx wrangler d1 list 2>/dev/null | grep "$DB_NAME" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1 || true)

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

# Generate wrangler.json (pure JSON, no comments)
cat > "$CONFIG_OUTPUT" <<TMPL
{
  "name": "webauthnp256-publickey-index",
  "main": "worker/index.ts",
  "compatibility_date": "2024-09-23",
  "compatibility_flags": ["nodejs_compat"],
  "d1_databases": [
    {
      "binding": "DB",
      "database_name": "$DB_NAME",
      "database_id": "$DB_ID"
    }
  ],
  "durable_objects": {
    "bindings": [
      {
        "name": "QUEUE_PROCESSOR",
        "class_name": "QueueProcessor"
      }
    ]
  },
  "migrations": [
    {
      "tag": "v1",
      "new_classes": ["QueueProcessor"]
    }
  ],
  "triggers": {
    "crons": ["* * * * *"]
  },
  "observability": {
    "enabled": false,
    "logs": {
      "enabled": true,
      "invocation_logs": true
    }
  }
}
TMPL

echo "Generated $CONFIG_OUTPUT with database_id: $DB_ID"
echo ""
echo "Next steps:"
echo "  npx wrangler secret put PRIVATE_KEY"
echo "  npx wrangler secret put TELEGRAM_BOT_TOKEN"
echo "  npx wrangler secret put TELEGRAM_CHAT_ID"
echo "  npx wrangler secret put ALCHEMY_API_KEY   # optional: priority write RPC"
echo "  npm run deploy"
