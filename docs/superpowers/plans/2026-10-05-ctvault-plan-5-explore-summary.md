# CTVault Plan 5 (`explore`, the TUI): Summary

Built directly in the tree, as Plan 4 was: tests first, the usual gate, real data, and this summary instead of a plan document.

**Spec:** amendment A4 (`docs/superpowers/specs/2026-10-05-ctvault-plan5-amendment.md`), approved section by section on 2026-10-05.

## What It Adds

| Piece | Where | What it does |
|---|---|---|
| The query bar | `internal/query/bar.go` | `ParseBar` turns the bar into the same `Query` that `search`'s flags build. `Query.Bar` renders a query back. `IsBarKey` lists the terms. |
| Keyset pages | `internal/query/search.go` | `SearchPage` continues after the last row's sort key and unique tie-breaker, with NULLs last. Each `Page` returns its normalized query. |
| The `/` filter | `internal/query/search.go` | `Query.Filter` is a case-insensitive match over the displayed columns. It is part of the query, so it covers every page. |
| The precert↔final link | `internal/query/fetch.go` | `Fetcher.Linked` uses `delta_base_cert_id` first, then the `issuance_key` within 7 days, in both directions. |
| Exports of marked rows | `internal/query/export.go` | `ExportOptions.Selection` exports only the marked rows. `Meta.selection` records the key column and the sorted values. |
| The TUI | `internal/tui` | One root Bubble Tea v2 model: the bar, the results table, a detail pane, the certificate view (detail, text dump, PEM), help and a status line. Queries are asynchronous and cancellable, and pages are prefetched. |
| `ctvault explore` | `internal/cli/explore.go` | `explore [query] [--as-of N]`. It opens the snapshot and session as `search` does. Without a terminal it exits 2 and points to `search`. |
| Test vaults | `internal/querytest` | The writer-built test vault, shared by the `query` and `tui` tests, and a vault built from a captured sample (real data). |

**Dependencies:**
- Pinned: `charm.land/bubbletea/v2` v2.0.10, `charm.land/bubbles/v2` v2.2.1, `charm.land/lipgloss/v2` v2.0.6 and `github.com/charmbracelet/x/ansi` v0.11.8.
- Tests only: teatest v2 at `v2.0.0-20261004011457-ad85c59fdf4e`.
- Side effect: `go-runewidth` moved from v0.0.16 to v0.0.27 (indirect).

## Decisions to Review

A4's ten decisions are as approved. The implementation added these:

| # | Decision | Why |
|---|---|---|
| 1 | **`Esc` on the results, with nothing running and nothing to close, puts the cursor back in the bar.** `Esc` in the bar returns to the results. | A4's key table has no key for editing the query. |
| 2 | **`s` cycles from the group's default sort through each column, descending then ascending, and back to the default.** | "Cycle through the group's columns, then the direction" (A4 §3). The first `s` always gives the first column. |
| 3 | **`Space` marks a row and moves down one.** Marks belong to a list: they survive pages, sorting, the filter and `R`. `Tab` and a new query clear them. | Each group's rows have different keys. Marked rows that a filter hides are still recorded in the selection but not exported. |
| 4 | **`Enter` on a name lists its certificates under the same filters** (issuer, kind, dates and so on). `Enter` on an issuance shows a notice. | A4 defines `Enter` only for names and certificates. |
| 5 | **The detail pane shows the selected row's own columns in full, with no lookup.** The key, chain and precert↔final link are in `Enter`'s detail. | The spec's mockup showed the link and key in the pane. That would cost a fetch on every cursor move: about 0.3 s each at full scale. |
| 6 | **`f` cycles detail → text dump → PEM.** On a certs row it opens the text dump. `w` writes the text dump in the text view and the PEM otherwise, as `<first 16 hex of the SHA-256>.pem` or `.txt` by default. It refuses an existing file. | A4 §3. Files are created with `O_EXCL`, so nothing is ever replaced. |
| 7 | **Exports pick md, json or csv by extension** (default `ctvault-<group>-commit<N>.json`). `explore` never replaces a file. | `search` replaces files only with `--force`, and the TUI has no `--force`. |
| 8 | **`explore` needs a terminal on both stdin and stdout.** A single argument is the whole bar. A `key:value` argument with spaces, which the shell unquoted, is quoted again. So `explore example.com "issuer:Let's Encrypt"` works. | Shells strip quotes. |
| 9 | **Help is one list of keys**, not Bubbles' `help` columns. | The column layout cut two of the three key groups at 100 columns. |
| 10 | **Narrow terminals drop columns by priority.** At 80 columns, certs shows the SHA-256 prefix, `cert_id`, kind, issuer and the dates. The table shows dates as `YYYY-MM-DD` and booleans as yes or no; the pane shows full values. | A4 sets a minimum of 80×24. |

## Evidence (2026-10-05)

1. **TUI tests** (`internal/tui`, teatest v2 driving a real Bubble Tea program):
   - **How they run:** a hook records the model's screen after every update, so tests wait on the model, not on the renderer's output.
   - **Golden screens:** at 100×30 for names, marked names, certs, issuances, help and the start screen; at 80×24 for certs; the notice at 79×24. SHA-256s are masked: the test CA's keys are random.
   - **Same rows as `search`:** names, certs and issuances, a sort and the `/` filter, with 7-row pages.
   - **Navigation:** `Enter` and `Esc` from a name to its certificates, to a certificate's detail (names, entry, chain, linked precert), then the text dump and the PEM.
   - **Marks and exports:** three marks across two pages are exported with `selection`; the same path again is refused; with no marks every row is exported, without `selection`.
   - **`w`:** it never overwrites, and it writes the PEM and the text dump.
   - **Cancelling:** `Esc` cancels a slow query through its context. A replaced query's late answer, with rows, is dropped.
   - **`--as-of` and `R`:** commit 1 shows 20 names; after `R`, commit 3 shows 60.
   - **Bar errors:** each shows `search`'s message and runs nothing.
   - **Read-only:** a whole session (queries, detail, `w`, export, `R`) changes no file in the vault.
   - The suite passes under `-race`, 4 runs in a row.
2. **Real data** (`TestExploreOnRealData`, the canonical sample of 100,000 entries in 10 batches):

   | Session | Rows | First page | Every page |
   |---|---|---|---|
   | `on.aws` names (the most common domain) | 26,272 (132 pages) | 92 ms | 12.0 s |
   | `0025.ru` names | 5 | 28 ms | 51 ms |
   | `0025.ru` certs | 1 | 22 ms | 45 ms |
   | `0025.ru` issuances | 1 | 16 ms | 40 ms |

   - Every session's rows equal `search`.
   - A certificate's detail opens.
   - The filter plus a sort equals `search`.
3. **A real terminal:** the dev binary in a pseudo-terminal (110×30) on the 1,000,000-entry smoke vault from Plan 4.
   - It ran `amazonaws.com`, then `Tab`, `Enter` (detail with entries and the link), `f` (the text dump), `?` and `q`.
   - It exited 0, and its `tmp/duckdb-<pid>` folder was removed.
4. **Gate:** gofmt clean; `go vet` clean with 4 tag sets; race tests pass in production and dev builds (29 packages).

## Known Gaps

- **Each page re-runs the whole query** with the keyset predicate. For `on.aws` on the sample that is about 91 ms a page. At full scale, A3's worst case (a domain in every batch, about 60 s) would cost about 60 s *per page*. A rare domain (about 1 s) is fine.
  - **The fix, to decide:** materialize a query's result once, in a DuckDB temp table that can spill to `tmp/duckdb-<pid>/`, and page from it. Pages stay keyset pages, but only the first one pays.
  - This changes A4 §2.2's execution, not its behaviour.
- **`Ctrl-V` paste in the bar** uses Bubbles' clipboard support, which runs `xclip`, `xsel` or `wl-paste` when one is installed. A terminal's own paste (bracketed paste) needs nothing.
- **The detail pane** does not show the key algorithm or the linked certificate, as the spec's mockup did (decision 5).
