# apex-ses-unsubscribe

RFC 8058 one-click unsubscribe endpoint for the Apex SES platform
(~/workspace/ses-platform-2026-10-20 on the ops VM). Deployed from this
staging snapshot of the platform's unsubscribe.py + suppression.py
(stdlib-only Python; the platform originals are the source of truth —
re-copy before redeploying after any platform edit).

- Serves POST/GET /u/{token} (HMAC-signed opt-out tokens minted by the
  platform's sender.py) and records opt-outs into its LOCAL SQLite
  registry (staging only — Render's disk is ephemeral).
- The secret arrives as env SES_UNSUB_SECRET (same hex string as the
  platform's data/unsub_secret.key) so sender-minted tokens verify here.
- Durability: the VM's unsub_sync.py pulls GET /optouts (HMAC-keyed) into
  the platform suppression registry on the poller cadence; the sender
  consults only that registry.
- Free plan spins down when idle; the first hit wakes it (~30-60s).
  Before sustained live volume, move to a paid instance (ops decision).
