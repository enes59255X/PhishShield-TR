# PhishShield TR V2.0 Stable Backup

**Created:** 2026-09-03
**Version:** 2.0-stable

## Contents

- `phishshield_v2.db` - SQLite database with all analysis history and threat intelligence

## Restore Instructions

If you need to restore this backup:

1. Stop the running backend server
2. Copy `phishshield_v2.db` to `backend/phishshield.db`
3. Restart the server

## What's Included

- Site analyses history
- Official domains database
- Phishing domains database
- USOM feed cache
- User feedback

## V2 -> V3 Migration Notes

This backup was taken before the V3 migration which includes:
- Canonical Result structure (detection/result.py)
- Trust Classification (site_type field)
- Cache V2 with versioning
- Signal Engine V2
