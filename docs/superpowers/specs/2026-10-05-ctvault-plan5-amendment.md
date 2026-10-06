# CTVault Spec Amendment A4: `explore` (the TUI)

- **Date:** 2026-10-05
- **Status:** Approved 2026-10-05, section by section in the design discussion. It is built directly in the tree, like Plan 4.
- **Amends:** `docs/superpowers/specs/2026-10-04-ctvault-design.md` §11.4 ("the spec"), and amendments A1–A3.
- **Origin:** Plan 5 design discussion.
  - The whole TUI of spec §11.4 is in scope (choice A).
  - It is a thin TUI over the `query` package (approach 1).
- **Scope:** Plan 5, `explore` (phase 5 of spec §16).

Everything not changed here stays as in the spec and A1–A3. **Production safety requirements are unchanged.**

---

## 1. Architecture

- **The package:** `internal/tui`, with one root Bubble Tea model and Bubbles components:
  - the query bar (`textinput`);
  - results (`table`);
  - detail (`viewport`);
  - help (`help`).
- **Data:** every row comes from the `query` package: paged search, `fetch`, names, chains, entries. The TUI has no SQL of its own, so `search` and `explore` give the same results.
- **Libraries:** Bubble Tea v2 (`charm.land/bubbletea/v2` v2.0.10), Bubbles v2 (`charm.land/bubbles/v2` v2.2.1) and Lip Gloss v2 (`charm.land/lipgloss/v2` v2.0.6), pinned as spec §15 V3 asks. In v2 the root model's `View` returns a `tea.View`.

## 2. The query bar and execution

### 2.1 Syntax

The spec's example: `example.com issuer:"Let's Encrypt" since:2026-10 kind:final`.

- **Terms:** separated by spaces; a value with spaces goes in double quotes.
- **The mode:** a bare term is the domain (the default mode). The other modes are `suffix:`, `exact:`, `ip:`, `contains:` and `regex:`. A query has exactly one mode.
- **The filters** mirror `search`'s flags:

  | Short | Long | `search` flag |
  |---|---|---|
  | `issuer:` | `issuer:` | `--issuer` |
  | `org:` | `issuer-org:` | `--issuer-org` |
  | `issued-by:` | `issued-by:` | `--issued-by` |
  | `key:` | `key-alg:` | `--key-alg` |
  | `kind:` (comma list) | `kind:` | `--kind` |
  | `status:` | `parse-status:` | `--parse-status` |
  | `valid-at:` | `valid-at:` | `--valid-at` |
  | `wildcard` | `wildcard` | `--wildcard` |
  | `log:` | `log:` | `--log` |
  | `since:` / `until:` | `since:` / `until:` | `--since` / `--until` |
  | `by:not-before` | `by:not-before` | `--by not-before` |

- **One representation:** `query.ParseBar(text) (Query, error)` produces the same `query.Query` that `search` builds from its flags; a test checks both paths agree. `Query.Bar()` renders a query back, for display and exports.
- **Errors:** an unknown or malformed term is shown in the bar with the message `search` would give, and nothing runs.

### 2.2 Execution

- **Keyset pagination** (new in `query`): each page continues after the last row's sort key and its unique tie-breaker, with NULLs last. There is no `OFFSET`, so pages never repeat or skip rows.
- **Pages:** 200 rows. The next page is requested when the cursor nears the end. The row count shows as "200+" until the last page.
- **Asynchronous:** each query runs in a `tea.Cmd` with its own `context`.
  - `Esc` cancels it, and a new query cancels the previous one.
  - Results carry their query's number, so a late answer to an old query is dropped.
- **The snapshot is pinned per session** (spec §11.4). The status bar shows "as-of commit N".
  - `explore --as-of N` starts at an earlier commit.
  - `R` re-pins the latest commit. Without `R`, the session never changes by itself.

## 3. Screens and keys

**The main screen** follows the spec's mockup:
- the query bar at the top;
- the active group's results;
- a detail pane for the selected row;
- a status bar: rows, milliseconds, derived-table state, as-of commit, `[?]help`.

| Key | Action |
|---|---|
| `Tab` | switch between names, certs and issuances (re-runs the query) |
| `Enter` | open detail: on a name, the name's certificates; on a certificate, its detail. `Esc` goes back. |
| `f` | show the selected certificate as PEM or as `fetch`'s text dump |
| `w` | write the shown certificate to a file; never overwrites |
| `Space` | mark a row; marks persist across pages |
| `e` | export the marked rows, or all rows |
| `/` | filter the whole result |
| `s` | sort: cycle through the group's columns, then the direction |
| `Esc` | cancel the running query, or close the current view |
| `R` | re-pin the snapshot to the latest commit |
| `?` | help |
| `q`, `Ctrl-C` | quit |

**Certificate detail:**
- all its names;
- every log entry that references it;
- the chain;
- the **precert↔final link**:
  1. through `delta_base_cert_id` first;
  2. otherwise, through the `issuance_key` in `entries`: from a final to its precert within the 7 days before it, and from a precert to its final within the 7 days after it.

  The `entries` reads are pruned by Parquet min/max statistics on `ct_ts`. The spec described only the final-to-precert direction.

**The `/` filter** is a case-insensitive text match over the displayed columns. It is added to the same query, so it covers every page, not only the rows already loaded. Exports record it as `filter`.

**Exports** carry A3 §5's metadata: the exact query (filters, `/` filter, sort, group) and the as-of commit. An export of marked rows also records `selection` with the rows' keys.

**Strictly read-only:** no writer lock and no ingestion. Nothing is written outside `tmp/duckdb-<pid>/` and the export paths the user chooses.

## 4. The command and tests

- **The command:** `ctvault explore [query] [--as-of N]`.
  - It opens the snapshot and reader session as `search` does.
  - It needs a terminal: when stdout is not a TTY it exits 2 and suggests `search`.
  - The minimum terminal size is 80×24. A smaller terminal shows a notice instead of the table.
  - It is keyboard only in v1.
- **Tests:**
  - **`query`:**
    - the bar and `search`'s flags give the same `Query`;
    - concatenated pages equal the full result, for every group and sort, NULLs included;
    - the `/` filter covers every page;
    - the precert↔final link, by delta and by `issuance_key`, both ways.
  - **TUI** (teatest v2, pseudo-version `v2.0.0-20261004011457-ad85c59fdf4e`; tests only):
    - golden screens at a fixed size;
    - typing a query, `Tab`, `Enter`/`Esc`;
    - marking and exporting, with `selection`;
    - `w` never overwriting;
    - `Esc` cancelling a slow query (a test hook);
    - no file written or changed outside `tmp/duckdb-<pid>/` and the requested export.
  - **Real data:** a scripted session on the canonical sample gives the same rows as `search`.

## 5. Decisions this amendment adds

| # | Decision |
|---|---|
| 1 | The bar's short names (`org:`, `key:`, `status:`), with the long names also accepted. (§2.1) |
| 2 | `R` re-pins the snapshot; a session never changes by itself. (§2.2) |
| 3 | Pages of 200 rows with prefetch; "200+" until the last page. (§2.2) |
| 4 | `/` filters the whole result through the query. (§3) |
| 5 | `Enter` on a name lists its certificates; on a certificate, its detail. (§3) |
| 6 | The precert↔final link both ways, within 7 days. (§3) |
| 7 | Marks persist across pages; marked exports record `selection`. (§3) |
| 8 | `w` never overwrites. (§3) |
| 9 | `explore` needs a TTY and at least 80×24, keyboard only. (§4) |
| 10 | teatest pinned at a pseudo-version, tests only. (§4) |
