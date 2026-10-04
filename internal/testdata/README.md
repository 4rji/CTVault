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

Rules:

- Never edit or refresh these files. `TestFixturesAreUnchanged` in
  `internal/merkle` checks the SHA-256 of each one.
- A new capture goes in a new file with a new name, and its hash is added to
  that test in the same commit.
- `.gitattributes` marks this directory `-text`, so line-ending conversion can
  never alter the bytes.
