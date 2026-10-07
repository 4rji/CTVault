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

## Follow-up (2026-10-06): Held Results

As built above, each page re-ran the whole query with the keyset predicate. On the sample that was about 91 ms a page. At full scale, A3's worst case (a domain in every batch, about 60 s) would have cost about 60 s *per page*. The user approved the fix ("sigue"): compute each result once and page from it.

**What changed:**

| Piece | Where | What it does |
|---|---|---|
| `query.Hold` and `Results` | `internal/query/results.go` | `Hold` runs a query once into a table in the reader session's in-memory DuckDB. `Page(from, n)` reads a range of it. `Reorder(sort, filter)` gives the same rows in another order or under the `/` filter, from the held rows. `Export` writes them. `Len` is the total. `Close` drops them. |
| Shared SQL | `internal/query/search.go` | `compile` builds a search's SQL once, for `run` (search, keyset pages, exports) and `Hold`. The SQL itself is unchanged. |
| The TUI | `internal/tui` | Each list holds its rows. Pages, `s` and `/` read the held rows; `Tab`, a new query, `Enter` on a name and `R` run the query. A page appends its rows to the table instead of rebuilding every loaded row. |

**Decisions to review:**

| # | Decision | Why |
|---|---|---|
| 11 | **Held rows are an ordinary table in the session's in-memory database**, named `__ctv_held_<n>`, not a `TEMP` table. They spill to `tmp/duckdb-<pid>/` under the session's spill limit. Closing a list, or the session's end, drops them. | DuckDB's temp tables belong to one connection, and `database/sql` pools connections. A spike checked the spill: 5 million rows at a 100 MB memory limit put 934 MiB in the temp folder, with 37 MB in memory; `DROP` freed it. |
| 12 | **A held page is a range of row numbers**, assigned in the result's order. The table is written in that order, so a range reads only the row groups that hold it: a page near the end costs the same as the first. | The held rows never change, so positions are stable: pages never repeat or skip a row, as A4 §2.2 requires. `SearchPage` (keyset) stays in `query`. |
| 13 | **`s` and `/` reorder the held rows** and never read the vault. A new order or a filter is a second table; the default order shares the first. `Tab` runs the query again, since another group has other rows. | A sort or a filter of the worst-case domain would otherwise cost the whole query again. |
| 14 | **The status line shows the result's total from the first page** ("443748 names"), not "200+" until the last page. | **This changes A4's decision 3**, which you approved. The total costs nothing once the rows are held. One line in `counts()` restores "200+". |
| 15 | **Exports from `explore` write the held rows.** They are the rows on screen, and the bytes equal `search`'s export of the same query (tested). After a cancelled sort or filter, the shown query is not the held one, so `explore` runs the query as before. | No second run of a slow query. |
| 16 | **`Close` never waits.** A read that is running keeps the rows until it ends, and then drops them. | `explore` closes rows on its UI goroutine. An export that holds a read for its whole run would otherwise freeze the screen on `Tab`. |

**Evidence (2026-10-06):**

1. **`query` tests** (`results_test.go`, `results_internal_test.go`):
   - Held pages equal `Search` for the 8 paged queries: every group, both directions, NULLs and the filter. Each query's other sorts and filters, reordered from its held rows, equal `Search` with that sort and filter.
   - With the vault's Parquet files deleted after `Hold`, pages, `Reorder` and `Export` still work, and the export's bytes equal `Export`'s from before the deletion. A search then fails, which shows the files were needed.
   - Exports of a selection equal `Export`'s, CSV and side metadata included.
   - Sharing: the last `Close` drops the rows; a closed result refuses pages.
   - Edges: no matching row, a bad sort (`ErrUsage`), and a cancelled `Hold`, which leaves no table.
   - `Close` returns at once while a read runs; the table goes when the read ends.
   - Mutation checks: a reversed sort, a dropped filter and a wrong next-page rule each fail the tests.
2. **TUI tests:**
   - Paging three groups runs the query 3 times. `Tab` back runs it once more. Two sorts and a filter run it 0 times.
   - Held tables follow the lists: 1 for a query, 2 with a sort, 3 with a name's certificates pushed, 2 after `Esc`, 1 after `Tab`, a new query or `R`, and 0 after `explore` closes.
   - A cancelled query's rows, and those of a completed answer that arrives stale, are dropped. Mutation-checked.
   - The golden screens are unchanged. The suite passes under `-race`, 4 runs in a row.
3. **Real data** (the canonical sample of 100,000 entries):

   | Session | Before | Held |
   |---|---|---|
   | `on.aws` names, 26,272 rows: first page | 92 ms | 101 ms |
   | `on.aws` names: every page (132), through the UI | 12.0 s | 2.5 s |
   | a sort / the filter | a full query each | 53 ms / 28 ms |
   | the `query` package alone: one page | 61 ms (keyset) | 1.3 ms |

   The remaining UI time per page is mostly the test harness's polling and screen capture.
4. **The 1,000,000-entry smoke vault** (`amazonaws.com`):

   | Group | Rows | Hold (once) | A page | A page near the end | Sort | Filter | A keyset page |
   |---|---|---|---|---|---|---|---|
   | names | 443,748 | 599 ms | 1.7 ms | 1.3 ms | 176 ms | 86 ms | 471 ms |
   | certs | 168,566 | 301 ms | 2.0 ms | 2.0 ms | 111 ms | 120 ms | 230 ms |
   | issuances | 168,560 | 383 ms | 1.7 ms | 1.7 ms | 121 ms | 78 ms | 291 ms |

   - The dev binary in a pseudo-terminal: the first page in 0.7 s (443,748 names), six `End` pages, `s`, then `Tab`, `Enter`, `f`, `?` and `q`.
   - It exited 0, and its spill folder was removed.
5. **Gate:** green (29 packages).

**At full scale:** A3's worst-case domain still pays its query once (about 60 s), then pages cost milliseconds. A sort or a filter rewrites the held rows: linear in their number (176 ms for 443,748 rows). Its full-scale cost is not measured.

## Known Gaps

- **`Ctrl-V` paste in the bar** uses Bubbles' clipboard support, which runs `xclip`, `xsel` or `wl-paste` when one is installed. A terminal's own paste (bracketed paste) needs nothing.
- **The detail pane** does not show the key algorithm or the linked certificate, as the spec's mockup did (decision 5).
