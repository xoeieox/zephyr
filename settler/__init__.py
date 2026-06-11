"""Settler - Open Payments settlement from Zephyr intent queue.

The settler is a separate process that:
1. Drains pending intents from the Zephyr intent queue (atomic claim)
2. Resolves wallet hints from WalletMap
3. Executes Open Payments flow via Rafiki GNAP (testnet)
4. Records settlements in a ledger
5. Marks intents as settled/no-route/failed

Run with: python -m settler.run
Environment variables:
  ZEPHYR_INTENT_QUEUE_DB          -- intent queue SQLite path
  ZEPHYR_SETTLEMENT_LEDGER_DB     -- settlement ledger SQLite path
  ZEPHYR_SETTLER_WALLET_MAP       -- JSON file: {pubkey_id → wallet address}
  ZEPHYR_SETTLER_SOURCE_WALLET    -- funded settlement-pool source account URL
  ZEPHYR_SETTLER_GNAP_ENDPOINT    -- Rafiki GNAP endpoint (default: interledger-test.dev)
"""
