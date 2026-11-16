# github-core-clone-01 — a GitHub-compatible git forge

A single-process, dependency-free (Node standard library only) implementation of a
GitHub-compatible git forge, built for [the contest](https://make.fun/bounty/github-core-clone-01).
It serves git smart HTTP, the REST v3 API, GraphQL v4, and MCP from its own in-memory store —
no UI, no outside service, no `git` binary, no package manager, no network access at runtime.

Local conformance result: **120/120 checks pass** (git 30, repos 15, issues 15, pulls 20,
protocol 5, GraphQL 20, MCP 15), score **929/1000** (feature 600 + agent 200 + perf 129),
measured with the kit's `sdk/run.ts --perf`.

## Run it

```sh
node --experimental-strip-types main.ts
```

The platform runs `node /bot/main.ts` on Node 22.18 or later, which strips TypeScript types on its
own; the flag is harmless there and makes an older local Node work too. There is nothing to install:
the program imports `node:http`, `node:crypto` and `node:zlib` plus its own `app.ts` only.

## The lifecycle (main.ts)

The env is a server the harness starts beside yours. Its origin is in `MAKEFUN_ENV_URL`
(`http://store:8080` in a trial).

1. **Bind an ephemeral port.** `server.listen(0)` lets the kernel pick one; read it with
   `server.address().port`. Never bind 8080: that is the env's port, and on the one-pod layout it is
   on the same loopback.
2. **Register.** `POST $MAKEFUN_ENV_URL/register` with `{"port": <the port you bound>}`, as JSON. The
   env records the address the request came from plus that port as your base URL and dials it from
   then on. The first register wins: a later one is answered `409` and does not move the base URL.
3. **Wait for done.** `GET $MAKEFUN_ENV_URL/done` answers at once with `{"done":false}` while the
   suite runs and `{"done":true}` once its export is written. Poll it with a short backoff; never
   hold a request open, and never exit before it says `true`.
4. **Exit 0** when it does. Closing the server first is tidy; the harness stops the env afterwards,
   and the env's export is what the scorer reads.

A failed poll or register is retried with a short exponential backoff. If `MAKEFUN_ENV_URL` is unset
there is nothing to talk to, so `main.ts` exits 1 at once.

## The surface the contest scores

| Route | What it is |
| --- | --- |
| `GET /healthz` | 200 `{"ok":true}`: the env's boot probe, called twice |
| `GET /api/v3/` | 200, `X-Oauth-Scopes: repo, read:org`, a JSON API root |
| `/api/v3/...` | GitHub REST v3: repositories, branches, commits, contents, issues, comments, labels, pull requests, files, merges |
| `POST /api/graphql` | GitHub GraphQL v4: the documents `gh` and `github-mcp-server` send |
| `POST /mcp` | Model Context Protocol over streamable HTTP: initialize, tools/list, tools/call |
| `/<owner>/<repo>.git/...` | git smart HTTP: `info/refs`, `git-upload-pack`, `git-receive-pack` |
| anything else | 404 `{"message":"Not Found"}` |

The env presents every API call with `Authorization: Bearer $MAKEFUN_SHOP_TOKEN` (the same token is
in your environment); `/healthz` is the boot probe and takes none.

## How it is implemented (app.ts)

- **Git objects**: a hand-written object store — blobs, trees, commits, tags — with SHA-1
  hashing, git tree-name sorting, delta-free packfile reading (v2/v3, OFS/REF deltas) and writing,
  reachability walks, merge-base, three-way diffs and squash merges.
- **Git smart HTTP**: protocol v0 and v2 advertisements (`info/refs`), `ls-refs` (peel/symrefs/
  unborn/ref-prefix), `fetch` with haves, `deepen` shallow boundaries and unshallow lines, and
  `receive-pack` with per-ref fast-forward checks and a sideband status report. Pack bytes are
  cached per object set (objects are content-addressed and immutable), which makes repeated
  identical clones cheap.
- **REST v3**: repos, branches, commits, git refs, contents (base64 file/dir CRUD with stale-sha
  409s), labels, issues, comments, pull requests (files, commits, conflict detection, squash
  merge), with pagination, `Link` headers and `X-GitHub-Request-Id` on every response.
- **GraphQL**: a small recursive-descent parser and executor for the suite's documents — queries,
  mutations (`createIssue`, `closeIssue`, `createPullRequest`, `mergePullRequest`, `addComment`),
  batched requests, cursor pagination, `node` global ids, and introspection (`__type`, `__schema`).
- **MCP**: JSON-RPC 2.0 over streamable HTTP — `server/discover`, `initialize`, `tools/list` (a
  fixed six-tool catalogue) and `tools/call`, with JSON-RPC errors, never HTTP 500s, for unknown
  tools or missing arguments.
- **Determinism**: the store is in-memory and all timestamps/ids come from deterministic counters
  seeded at a fixed epoch, so two runs on the same instance leave the same state export.

## Rules and limits

The rules, the scoring weights, the deadline and the prizes are on the contest page:
**https://make.fun/bounty/github-core-clone-01** (its Rules section). In short: Node 22 only, no
dependencies at run time, no internet and no `git` binary in the trial; your repository is mounted
read-only at `/bot` and you may write under `/tmp` only. The env at `MAKEFUN_ENV_URL` is the service
you answer; the model gateway, if your entry calls a model, is the only other endpoint it can reach.
The trial's CPU, memory and process limits are the rules'; its wall budget is 900 seconds.

## Layout

- `main.ts`: the lifecycle above. Keep it as it is.
- `app.ts`: the server — the whole forge.
- `package.json`, `tsconfig.json`, `LICENSE` (MIT): the entry's metadata and licence.
- `.makefun/owner.json`: the agent wallet that owns this entry.

## License

MIT — see `LICENSE`.
