# CT Log Local Search Platform

## Overview

The idea is to build a small local Certificate Transparency search platform that:

1. Downloads Certificate Transparency log entries in manageable chunks.
2. Parses certificates and extracts searchable metadata.
3. Stores metadata in a local SQLite database.
4. Compresses the raw CT chunks with `zstd`.
5. Lets you search domains quickly without scanning terabytes of raw JSON.
6. Retrieves the original raw CT data only when needed.
7. Remembers the last processed CT log offset so future updates only download new entries.

The result is essentially a small local `crt.sh`-style search engine backed by your own CT archive.

---

# Why This Makes Sense

CT logs are public, append-only logs containing certificates and precertificates submitted by Certificate Authorities.

They can reveal:

- domains
- subdomains
- wildcard certificates
- old infrastructure names
- staging/dev systems
- API endpoints
- VPN hostnames
- historical certificates
- certificate issuance changes over time

The problem is volume.

A CT log can contain billions of entries. Saving everything as uncompressed JSON can require several terabytes.

Instead of repeatedly searching huge files, the application builds an index while downloading them.

Think of it like a book:

- compressed CT chunks = pages
- SQLite = index at the back of the book
- search query = look something up in the index
- raw chunk = open only the page containing the interesting entry

---

# High-Level Architecture

```text
                ┌──────────────────────┐
                │ Public CT Log        │
                └──────────┬───────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │ scrape-ct-log binary │
                └──────────┬───────────┘
                           │
                           │ raw chunk
                           ▼
                ┌──────────────────────┐
                │ Parser / Indexer     │
                │                      │
                │ - hostnames          │
                │ - fingerprints       │
                │ - timestamps         │
                │ - CT offsets         │
                └──────┬─────────┬─────┘
                       │         │
              metadata │         │ raw chunk
                       ▼         ▼
              ┌────────────┐   ┌───────────────┐
              │ SQLite DB  │   │ zstd archive  │
              └─────┬──────┘   └──────┬────────┘
                    │                 │
                    └───────┬─────────┘
                            ▼
                    ┌───────────────┐
                    │ Search CLI/TUI│
                    └───────────────┘
```

---

# Main Components

## 1. CT Collector

Initially use:

```text
mpalmer/scrape-ct-log
```

Repository:

```text
https://github.com/mpalmer/scrape-ct-log
```

Its job is simply to download entries from a CT log.

Example:

```bash
scrape-ct-log   -s 100000000   -n 500000   -o chunk.json   https://ct.googleapis.com/logs/us1/argon2026h1/
```

Meaning:

```text
-s = starting CT entry
-n = number of entries
-o = output file
```

The application does not need to keep the repository permanently.

Compile once:

```bash
cargo build --release
```

Then keep only:

```text
scrape-ct-log
```

Later the application could implement the CT protocol directly and remove this dependency.

---

# 2. Chunked Ingestion

Do NOT download an entire CT log at once.

Use chunks such as:

```text
500,000 entries
```

Example ranges:

```text
0 - 499999
500000 - 999999
1000000 - 1499999
...
```

Each chunk follows this flow:

```text
Download
   ↓
Parse
   ↓
Extract metadata
   ↓
Insert into SQLite
   ↓
Compress raw chunk
   ↓
Save checkpoint
   ↓
Continue
```

Benefits:

- low temporary disk usage
- easy restart
- manageable failures
- easy progress tracking
- individual chunks can be deleted or archived
- no need for one gigantic multi-terabyte file

---

# 3. Querying CT Log Size

Each CT log exposes its current tree size.

Example:

```bash
curl -s https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1/get-sth
```

Important field:

```json
{
  "tree_size": 2807501296
}
```

That means the log currently has:

```text
2,807,501,296 entries
```

The application should compare:

```text
current tree_size
vs
last processed offset
```

Example:

```text
Last processed:
2,807,500,000

Current tree size:
2,810,900,000
```

Only download:

```text
2,807,500,000 → 2,810,899,999
```

This makes future updates much cheaper after the initial historical ingestion.

---

# 4. SQLite Index

SQLite acts as the searchable catalog.

Instead of searching compressed files every time, queries hit SQLite first.

Possible schema:

```sql
CREATE TABLE certificates (
    id INTEGER PRIMARY KEY,

    hostname TEXT NOT NULL,
    fingerprint TEXT,
    cert_timestamp INTEGER,

    ct_log TEXT NOT NULL,
    entry_index INTEGER NOT NULL,

    chunk_start INTEGER,
    chunk_end INTEGER,
    chunk_file TEXT,

    issuer TEXT,
    subject TEXT,
    not_before INTEGER,
    not_after INTEGER
);
```

Useful indexes:

```sql
CREATE INDEX idx_hostname
ON certificates(hostname);

CREATE INDEX idx_fingerprint
ON certificates(fingerprint);

CREATE INDEX idx_log_entry
ON certificates(ct_log, entry_index);
```

---

# 5. What Should Be Indexed

At minimum:

```text
hostname
certificate fingerprint
certificate timestamp
CT log name
CT entry index
chunk start
chunk end
compressed chunk filename
```

Potential additional fields:

```text
issuer
subject
serial number
notBefore
notAfter
SAN values
certificate type
precertificate/certificate
public key algorithm
signature algorithm
key size
```

Example indexed record:

```text
hostname:
api.example.com

fingerprint:
A1:B2:C3:D4:...

timestamp:
2026-09-14T15:22:00Z

ct_log:
argon2026h1

entry_index:
1843920012

chunk_start:
1843500000

chunk_end:
1844000000

chunk_file:
argon2026h1_1843500000_1844000000.json.zst
```

---

# 6. Raw Chunk Storage

Suggested structure:

```text
storage/
├── chunks/
│   ├── argon2026h1_0000000000_0000500000.json.zst
│   ├── argon2026h1_0000500000_0001000000.json.zst
│   ├── argon2026h1_0001000000_0001500000.json.zst
│   └── ...
│
├── index/
│   └── ct-index.db
│
├── state/
│   └── argon2026h1.json
│
└── logs/
    └── ingest.log
```

Chunks should have predictable names.

Example:

```text
argon2026h1_1500000000_1500500000.json.zst
```

From the filename alone you know:

```text
CT log: argon2026h1
start: 1,500,000,000
end:   1,500,500,000
```

---

# 7. Compression

After indexing a raw chunk:

```bash
zstd -T0 chunk.json
```

Or stronger compression:

```bash
zstd -T0 -19 chunk.json
```

The original JSON can then be deleted after successful compression.

The application should verify the compressed archive exists before deleting the original.

Possible workflow:

```text
chunk.json
   ↓
parse/index
   ↓
chunk.json.zst
   ↓
verify
   ↓
delete chunk.json
```

---

# 8. Searching

A normal domain search should hit SQLite only.

Example:

```text
ctsearch search opengear.com
```

Conceptually:

```sql
SELECT *
FROM certificates
WHERE hostname = 'opengear.com'
   OR hostname LIKE '%.opengear.com';
```

Example output:

```text
opengear.com
www.opengear.com
api.opengear.com
support.opengear.com
vpn.opengear.com
*.cloud.opengear.com
```

The results can also display:

```text
Certificate fingerprint
Issuer
First seen
Expiration
CT log
Entry index
Raw archive location
```

---

# 9. Raw Entry Retrieval

Normally there is no reason to decompress anything during a search.

SQLite tells the application which archive contains the entry.

Example:

```text
Entry:
1843920012

Archive:
argon2026h1_1843500000_1844000000.json.zst
```

The application can stream-decompress it:

```bash
zstdcat argon2026h1_1843500000_1844000000.json.zst
```

Then extract the relevant entry.

Better:

```text
SQLite query
   ↓
Find chunk
   ↓
zstd stream
   ↓
extract requested CT entry
   ↓
display certificate
```

This avoids permanently decompressing large files.

---

# 10. Application Modes

A clean CLI could look like this.

## Initial ingestion

```bash
ctsearch ingest
```

Possible options:

```bash
ctsearch ingest   --log argon2026h1   --chunk-size 500000
```

---

## Incremental update

```bash
ctsearch update
```

Process:

```text
Read saved offset
↓
Fetch current tree_size
↓
Calculate unprocessed range
↓
Download new chunks
↓
Index
↓
Compress
↓
Update checkpoint
```

---

## Search

```bash
ctsearch search opengear.com
```

Possible variants:

```bash
ctsearch search --exact vpn.opengear.com
```

```bash
ctsearch search --suffix opengear.com
```

```bash
ctsearch search --wildcard "*.opengear.com"
```

---

## Certificate lookup

```bash
ctsearch cert <fingerprint>
```

---

## CT entry lookup

```bash
ctsearch entry <entry-index>
```

---

## Statistics

```bash
ctsearch stats
```

Example output:

```text
CT logs configured:      1
Entries processed:       2,807,500,000
Unique hostnames:        325,400,123
Certificates indexed:    1,945,220,887
Compressed storage:      1.3 TB
Last update:              2026-10-03
```

---

## List CT logs

```bash
ctsearch logs
```

Example:

```text
NAME          TREE SIZE       PROCESSED        STATUS
argon2026h1   2,807,501,296   2,807,500,000    current
```

---

# 11. Checkpoint / Resume

The application must be restartable.

Example state file:

```json
{
  "log": "argon2026h1",
  "url": "https://ct.googleapis.com/logs/us1/argon2026h1/",
  "chunk_size": 500000,
  "last_completed_offset": 1844000000,
  "last_tree_size": 2807501296
}
```

If ingestion crashes:

```text
last completed offset = 1,844,000,000
```

Restart from there rather than starting over.

Only advance the checkpoint after:

```text
download successful
AND
index successful
AND
compression successful
```

---

# 12. Failure Handling

The ingestion pipeline should handle:

```text
HTTP failures
429 rate limits
5xx responses
partial downloads
invalid JSON
scraper crashes
disk-full conditions
SQLite failures
compression failures
Ctrl+C
```

Do not mark a chunk completed until the entire pipeline succeeds.

Recommended sequence:

```text
download
↓
validate
↓
parse
↓
SQLite transaction
↓
compress
↓
verify archive
↓
save checkpoint
↓
remove temporary raw file
```

---

# 13. Rate Limiting

CT logs are designed to be publicly queried, but large ingestion generates substantial traffic.

The collector should support:

```text
retry
backoff
delay between chunks
```

Example:

```text
chunk completed
↓
sleep 2 seconds
↓
next chunk
```

For errors:

```text
1 second
2 seconds
4 seconds
8 seconds
...
```

---

# 14. Storage Strategy

There are several possible approaches.

## Option A — Index everything, keep everything

```text
SQLite metadata
+
all compressed chunks
```

Pros:

```text
complete historical archive
raw data always available
independent of external CT services
```

Cons:

```text
large storage requirement
```

---

## Option B — Index everything, delete raw chunks

```text
SQLite only
```

Pros:

```text
much smaller
fast search
```

Cons:

```text
cannot inspect original raw entry locally later
```

---

## Option C — Index everything, selectively keep chunks

Best compromise.

Example:

```text
Index every certificate
Keep compressed raw chunks for interesting periods/logs
Delete unnecessary archives
```

SQLite can remain your permanent searchable database.

---

# 15. SSD Storage

A cheap dedicated SSD is reasonable for this project.

However, raw JSON is inefficient.

Better:

```text
SSD
├── compressed CT chunks
└── SQLite database
```

Instead of:

```text
SSD
└── multi-terabyte raw JSON files
```

Potential storage progression:

```text
raw JSON
   ↓
SQLite metadata
+
zstd compressed chunks
```

---

# 16. MVP

Do not start by trying to build a complete `crt.sh`.

First version:

```text
1. Configure one CT log
2. Query tree_size
3. Download 500k chunk
4. Parse certificates
5. Extract SAN hostnames
6. Store in SQLite
7. Compress chunk
8. Save checkpoint
9. Search domains
10. Retrieve source chunk
```

Example CLI:

```text
ctsearch ingest
ctsearch update
ctsearch search example.com
ctsearch stats
```

That alone is already useful.

---

# 17. Phase 2

After MVP works:

```text
multiple CT logs
parallel parsing
better progress display
certificate fingerprint lookup
issuer search
date filtering
deduplication
wildcard handling
TUI
export JSON/CSV
```

Example:

```bash
ctsearch search opengear.com --since 2025-01-01
```

---

# 18. Phase 3

Possible advanced features:

```text
HTTP API
web frontend
distributed ingestion
Bloom filters
FTS indexes
domain suffix tables
certificate diffing
historical timelines
DNS resolution
live asset validation
ASN/IP enrichment
WHOIS/RDAP enrichment
notifications for new certificates
```

Example monitoring feature:

```text
Watch:
*.example.com

New CT certificate detected:
internal-api.example.com

Issuer:
Let's Encrypt

Seen:
2 minutes ago
```

At this point it becomes useful for:

```text
attack-surface monitoring
asset discovery
certificate monitoring
security research
PKI analysis
```

---

# 19. Language Choice

Good choices:

```text
Go
Rust
```

## Go

Advantages:

```text
simple concurrency
easy CLI development
easy SQLite integration
single static-ish binary
good TLS/X.509 library
```

## Rust

Advantages:

```text
performance
memory safety
good parsing ecosystem
scrape-ct-log is already Rust
```

For a first version, Go would likely make development faster.

For deeper integration with `scrape-ct-log`, Rust may be attractive.

---

# 20. Eventually Remove scrape-ct-log

Initially:

```text
your app
   ↓
scrape-ct-log
   ↓
CT API
```

Later:

```text
your app
   ↓
CT API directly
```

The CT endpoints are public and documented.

The application could implement:

```text
get-sth
get-entries
```

itself.

At that point the project becomes entirely standalone.

---

# 21. Possible Project Names

Ideas:

```text
ctseek
ctvault
ctindex
ctarchive
ctscope
ctfinder
ctscan
ctatlas
ctcache
```

Good candidates:

```text
CTSeek
CTVault
CTAtlas
```

`CTVault` fits particularly well if the project keeps compressed historical data.

`CTSeek` fits better if search is the main focus.

---

# 22. Core Concept

The entire project can be summarized as:

```text
Public CT Logs
      ↓
Chunked Downloader
      ↓
Certificate Parser
      ↓
SQLite Search Index
      ↓
zstd Historical Archive
      ↓
Fast Local Search
```

The important idea is:

> Never search terabytes of raw CT data when you can build the search index once during ingestion.

After the initial historical import, maintaining the database becomes much cheaper because CT logs are append-only.

You only process new entries.

That turns a huge public dataset into a practical local security research database.
