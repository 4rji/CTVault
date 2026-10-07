# Test fixtures (immutable)

Real Certificate Transparency data captured on 2026-10-04. Tests use these
files instead of the live log, so results never depend on the network or on
the log's current state.

| File | Source | Content |
|---|---|---|
| `log_list_google.json` | `https://www.gstatic.com/ct/log_list/v3/log_list.json` v93.3 (2026-10-03T13:35:24Z) | Google operator only, trimmed to the 2026h2/2027h1 RFC 6962 logs and 2027h1 tiled logs |
| `log_list_v93.3_full.json` | same URL and version, untrimmed | every operator, RFC 6962 and tiled log (used to prove log names are unique) |
| `argon2027h1_sth1.json` | `https://ct.googleapis.com/logs/us1/argon2027h1/ct/v1/get-sth` | signed tree head, tree size 384,065,451 (06:25:33Z) |
| `argon2027h1_sth2.json` | same endpoint, a few minutes later | signed tree head, tree size 384,071,894 |
| `argon2027h1_consistency.json` | `get-sth-consistency?first=384065451&second=384071894` | 23-node consistency proof between the two heads |
| `argon2027h1_entries_380000000.json` | `get-entries?start=380000000&end=380000031` (05:38Z), saved exactly as served | 32 real entries: 11 x509, 21 precert |
| `log_list_v93.6_full.json` | the log list URL above, v93.6 (2026-10-06T13:36:54Z), captured 2026-10-07 04:22Z, untrimmed | every operator; 43 tiled logs with their keys and URLs (amendment A6) |
| `parcelyard2026h2_checkpoint` | `https://storage.googleapis.com/parcelyard2026h2.prod.certificate.transparency.goog/checkpoint` (2026-10-07 04:22Z) | static-ct-api checkpoint, tree size 1,587,930,800, four signature lines (amendment A6) |
| `parcelyard2026h2_tile_0_x006_x202_854` | same prefix, `tile/0/x006/x202/854` (its partial `.p/176` answered 404) | full level-0 hash tile |
| `parcelyard2026h2_tile_1_x024_229.p_230`, `…_tile_2_094.p_165`, `…_tile_3_000.p_94` | same prefix, `tile/1/x024/229.p/230`, `tile/2/094.p/165`, `tile/3/000.p/94` | the right edge of the checkpoint's tree |
| `parcelyard2026h2_data_x006_x202_854` | same prefix, `tile/data/x006/x202/854`, served as identity | 256 live entries: 158 x509, 98 precert, 52 distinct issuers |
| `parcelyard2026h2_issuer_adb4a7e9…9925` | same prefix, `issuer/adb4a7e9…9925` | an issuer certificate as served (Merge Delay Intermediate 1) |

Rules:

- Never edit or refresh these files. `TestFixturesAreUnchanged` in
  `internal/merkle` checks the SHA-256 of each one.
- A new capture goes in a new file with a new name, and its hash is added to
  that test in the same commit.
- `.gitattributes` marks this directory `-text`, so line-ending conversion can
  never alter the bytes.
