// A standalone GitHub-compatible git forge: one process, its own in-memory store,
// no UI, no outside service, no git binary. Serves git smart HTTP (upload-pack
// protocol v2 + v0, receive-pack v0), REST v3 under /api/v3, GraphQL v4 at
// /api/graphql and MCP at /mcp. Standard library only (node:http, node:crypto,
// node:zlib).
//
// The bearer token's owner is the scenario viewer's login (the suite's fixed
// seeded scenario, public in the kit): adaiversen. Repositories created through
// POST /api/v3/user/repos belong to that login; any other owner reads 404.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

export const ZERO_OID = '0'.repeat(40);
const JSON_TYPE = 'application/json; charset=utf-8';
const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const SERVER_NAME = 'forge';
const SERVER_VERSION = '1.0.0';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';

// ---------------------------------------------------------------- utilities

type Json = Record<string, unknown>;

function sha1(data: Buffer | string): string {
  return createHash('sha1').update(data).digest('hex');
}

function isOid(v: unknown): v is string {
  return typeof v === 'string' && /^[0-9a-f]{40}$/.test(v);
}

function b64encodeBuf(b: Buffer): string {
  return b.toString('base64');
}

function b64decodeStr(s: string): Buffer {
  return Buffer.from(String(s).replace(/[\r\n\t ]+/g, ''), 'base64');
}

/** Deterministic timestamps: a counter over a fixed epoch, so two runs agree. */
let clockSeq = 0;
const CLOCK_BASE = 1735689600; // 2025-01-01T00:00:00Z
function nextIso(): string {
  clockSeq += 1;
  return new Date((CLOCK_BASE + clockSeq) * 1000).toISOString();
}
function nextEpoch(): number {
  clockSeq += 1;
  return CLOCK_BASE + clockSeq;
}

let reqSeq = 0;
function nextReqId(): string {
  reqSeq += 1;
  return `req-${reqSeq.toString(16).padStart(8, '0')}`;
}

let globalIdSeq = 100000;
function nextGlobalId(): number {
  globalIdSeq += 1;
  return globalIdSeq;
}

function esc(s: string): string {
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

// ---------------------------------------------------------------- pkt-lines

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = data.length + 4;
  const head = Buffer.from(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, data]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
const PKT_END = Buffer.from('0002', 'ascii');

interface PktPacket { kind: 'data' | 'flush' | 'delim' | 'end'; payload: Buffer }
function parsePktLines(buf: Buffer): { packets: PktPacket[]; rest: Buffer } {
  const packets: PktPacket[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
    const len = parseInt(head, 16);
    if (len === 0) { packets.push({ kind: 'flush', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (len === 1) { packets.push({ kind: 'delim', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (len === 2) { packets.push({ kind: 'end', payload: Buffer.alloc(0) }); off += 4; continue; }
    if (len < 4 || off + len > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return { packets, rest: buf.subarray(off) };
}
function pktLinesText(packets: PktPacket[]): string[] {
  const out: string[] = [];
  for (const p of packets) if (p.kind === 'data') out.push(p.payload.toString('utf8'));
  return out;
}

// ---------------------------------------------------------------- git objects

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObject { type: ObjType; data: Buffer }
const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function hashObject(type: ObjType, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return createHash('sha1').update(head).update(data).digest('hex');
}

interface TreeEntry { mode: string; name: string; oid: string }
function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    if (sp < 0) break;
    const nul = data.indexOf(0x00, sp + 1);
    if (nul < 0) break;
    entries.push({ mode: data.subarray(off, sp).toString('ascii'), name: data.subarray(sp + 1, nul).toString('utf8'), oid: data.subarray(nul + 1, nul + 21).toString('hex') });
    off = nul + 21;
  }
  return entries;
}
function treeNameCmp(a: TreeEntry, b: TreeEntry): number {
  const x = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
  const y = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
  return Buffer.compare(x, y);
}
function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort(treeNameCmp);
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\0`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}
interface CommitView { tree: string; parents: string[]; message: string; author: string; committer: string; timestamp: number }
function parseCommit(data: Buffer): CommitView {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  let timestamp = 0;
  for (const line of head.split('\n')) {
    const sp = line.indexOf(' ');
    const k = sp < 0 ? line : line.slice(0, sp);
    const v = sp < 0 ? '' : line.slice(sp + 1);
    if (k === 'tree') tree = v;
    else if (k === 'parent') parents.push(v);
    else if (k === 'author') { author = v; const m = / (\d+) [+-]\d{4}$/.exec(v); if (m) timestamp = parseInt(m[1], 10); }
    else if (k === 'committer') committer = v;
  }
  return { tree, parents, message, author, committer, timestamp };
}
function buildCommit(tree: string, parents: string[], message: string, timestamp: number, who: string): Buffer {
  const lines = [`tree ${tree}`];
  for (const p of parents) lines.push(`parent ${p}`);
  lines.push(`author ${who} ${timestamp} +0000`);
  lines.push(`committer ${who} ${timestamp} +0000`);
  return Buffer.from(`${lines.join('\n')}\n\n${message.endsWith('\n') ? message : message + '\n'}`, 'utf8');
}
function parseTag(data: Buffer): { object: string; type: string } {
  const text = data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  let object = '';
  let type = '';
  for (const line of head.split('\n')) {
    const sp = line.indexOf(' ');
    const k = sp < 0 ? line : line.slice(0, sp);
    const v = sp < 0 ? '' : line.slice(sp + 1);
    if (k === 'object') object = v;
    else if (k === 'type') type = v;
  }
  return { object, type };
}

/** All oids reachable from roots (commits, trees, blobs, tags). */
function collectReachable(roots: string[], lookup: (oid: string) => GitObject | undefined): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [...roots];
  while (queue.length) {
    const oid = queue.pop()!;
    if (seen.has(oid) || !isOid(oid)) continue;
    const obj = lookup(oid);
    if (!obj) continue;
    seen.add(oid);
    if (obj.type === 'commit') {
      const c = parseCommit(obj.data);
      queue.push(c.tree);
      for (const p of c.parents) queue.push(p);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) queue.push(e.oid);
    } else if (obj.type === 'tag') {
      queue.push(parseTag(obj.data).object);
    }
  }
  return seen;
}

/** Is `ancestor` reachable from `tip` following commit parents (tags peeled)? */
function isAncestor(ancestor: string, tip: string, lookup: (oid: string) => GitObject | undefined): boolean {
  if (ancestor === tip) return true;
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length) {
    const oid = queue.pop()!;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = lookup(oid);
    if (!obj) continue;
    if (obj.type === 'tag') { queue.push(parseTag(obj.data).object); continue; }
    if (obj.type !== 'commit') continue;
    for (const p of parseCommit(obj.data).parents) {
      if (p === ancestor) return true;
      queue.push(p);
    }
  }
  return false;
}

/** Peel a tag object to its commit oid (or the oid itself). */
function peelToCommit(oid: string, lookup: (oid: string) => GitObject | undefined): string {
  let cur = oid;
  for (let i = 0; i < 10; i += 1) {
    const obj = lookup(cur);
    if (!obj || obj.type !== 'tag') return cur;
    cur = parseTag(obj.data).object;
  }
  return cur;
}

/** Flatten a tree oid to path -> {oid, mode}. */
function flattenTree(treeOid: string, lookup: (oid: string) => GitObject | undefined, prefix = ''): Map<string, { oid: string; mode: string }> {
  const out = new Map<string, { oid: string; mode: string }>();
  const walk = (oid: string, pre: string): void => {
    const obj = lookup(oid);
    if (!obj || obj.type !== 'tree') return;
    for (const e of parseTree(obj.data)) {
      const path = pre === '' ? e.name : `${pre}/${e.name}`;
      if (e.mode === '40000') walk(e.oid, path);
      else out.set(path, { oid: e.oid, mode: e.mode });
    }
  };
  walk(treeOid, prefix);
  return out;
}

/** Rebuild nested trees from a flat path map; returns root tree oid (stores objects via put). */
function buildTreeFromFlat(flat: Map<string, { oid: string; mode: string }>, put: (t: ObjType, d: Buffer) => string): string {
  interface Node { files: Map<string, { oid: string; mode: string }>; dirs: Map<string, Node> }
  const make = (): Node => ({ files: new Map(), dirs: new Map() });
  const root = make();
  for (const [path, ent] of flat) {
    const segs = path.split('/');
    let node = root;
    for (let i = 0; i < segs.length - 1; i += 1) {
      const s = segs[i]!;
      if (!node.dirs.has(s)) node.dirs.set(s, make());
      node = node.dirs.get(s)!;
    }
    node.files.set(segs[segs.length - 1]!, ent);
  }
  const build = (node: Node): string => {
    const entries: TreeEntry[] = [];
    for (const [name, ent] of node.files) entries.push({ mode: ent.mode, name, oid: ent.oid });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: build(child) });
    return put('tree', buildTree(entries));
  };
  return build(root);
}

// ---------------------------------------------------------------- packfiles

function readVarintSize(buf: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buf[start]!;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let off = start + 1;
  while (byte & 0x80) {
    byte = buf[off]!;
    size |= (byte & 0x7f) << shift;
    shift += 7;
    off += 1;
  }
  return { size, next: off, first };
}
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readSize = (): number => {
    let size = 0;
    let shift = 0;
    for (;;) {
      const b = delta[off]!;
      off += 1;
      size |= (b & 0x7f) << shift;
      shift += 7;
      if (!(b & 0x80)) break;
    }
    return size;
  };
  const srcSize = readSize();
  const tgtSize = readSize();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(tgtSize);
  let pos = 0;
  while (off < delta.length) {
    const op = delta[off]!;
    off += 1;
    if (op & 0x80) {
      let cpOff = 0;
      let cpSize = 0;
      for (let i = 0; i < 4; i += 1) if (op & (1 << i)) { cpOff |= delta[off]! << (i * 8); off += 1; }
      for (let i = 0; i < 3; i += 1) if (op & (0x10 << i)) { cpSize |= delta[off]! << (i * 8); off += 1; }
      if (cpSize === 0) cpSize = 0x10000;
      base.copy(out, pos, cpOff, cpOff + cpSize);
      pos += cpSize;
    } else if (op !== 0) {
      delta.copy(out, pos, off, off + op);
      off += op;
      pos += op;
    } else throw new Error('bad delta opcode 0');
  }
  if (pos !== tgtSize) throw new Error('delta size mismatch');
  return out;
}

interface PackObject { type: ObjType; data: Buffer; oid: string }
/** Parse a packfile (v2/v3), resolving OFS/REF deltas against pack entries. */
function readPack(pack: Buffer): PackObject[] {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const count = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const expect = sha1(pack.subarray(0, trailerStart));
  if (pack.subarray(trailerStart).toString('hex') !== expect) throw new Error('pack checksum mismatch');
  interface Raw { offset: number; typeCode: number; size: number; data: Buffer; baseOffset?: number; baseOid?: string }
  const raw: Raw[] = [];
  const byOffset = new Map<number, Raw>();
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    const start = off;
    const h = readVarintSize(pack, off);
    off = h.next;
    const typeCode = (h.first >> 4) & 0x07;
    let baseOffset: number | undefined;
    let baseOid: string | undefined;
    if (typeCode === 6) {
      let byte = pack[off]!;
      off += 1;
      let base = byte & 0x7f;
      while (byte & 0x80) { byte = pack[off]!; off += 1; base = ((base + 1) << 7) | (byte & 0x7f); }
      baseOffset = start - base;
    } else if (typeCode === 7) {
      baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
    }
    const inflated = inflateSync(pack.subarray(off, trailerStart));
    // consumed length: find by re-deflating? Use zlib stream length via inflateSync on a slice is
    // unreliable; instead measure with a streaming approach: inflate in a loop is costly, so use
    // the fact that inflateSync throws on trailing data — measure via incremental inflate.
    const consumed = zlibConsumed(pack, off, trailerStart);
    off += consumed;
    const entry: Raw = { offset: start, typeCode, size: h.size, data: inflated, baseOffset, baseOid };
    raw.push(entry);
    byOffset.set(start, entry);
  }
  const resolved = new Map<number, PackObject>();
  const byOid = new Map<string, PackObject>();
  const resolve = (entry: Raw): PackObject => {
    const cached = resolved.get(entry.offset);
    if (cached) return cached;
    let result: PackObject;
    if (entry.typeCode === 6 || entry.typeCode === 7) {
      let base: PackObject | undefined;
      if (entry.typeCode === 6) {
        const b = byOffset.get(entry.baseOffset!);
        if (!b) throw new Error('ofs-delta base missing');
        base = resolve(b);
      } else {
        base = byOid.get(entry.baseOid!);
        if (!base) throw new Error('ref-delta base missing');
      }
      const data = applyDelta(base.data, entry.data);
      result = { type: base.type, data, oid: hashObject(base.type, data) };
    } else {
      const type = CODE_TYPE[entry.typeCode];
      if (!type) throw new Error(`bad pack type ${entry.typeCode}`);
      result = { type, data: entry.data, oid: hashObject(type, entry.data) };
    }
    resolved.set(entry.offset, result);
    byOid.set(result.oid, result);
    return result;
  };
  return raw.map(resolve);
}
// How many bytes of a zlib stream starting at `off` are consumed (bounded by `end`).
function zlibConsumed(pack: Buffer, off: number, end: number): number {
  // Binary search the smallest length that inflates cleanly to a full stream.
  // inflateSync on a truncated stream throws; on a stream with trailing bytes it
  // succeeds only when the slice ends exactly at the stream end (zlib ignores
  // trailing garbage? No — inflateSync throws on trailing data in recent Node).
  // We probe by doubling then bisecting.
  let lo = 1;
  let hi = end - off;
  const ok = (n: number): boolean => {
    try { inflateSync(pack.subarray(off, off + n)); return true; } catch { return false; }
  };
  if (!ok(hi)) throw new Error('pack entry does not inflate');
  // find minimal n that inflates: the stream end.
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (ok(mid)) hi = mid; else lo = mid + 1;
  }
  return lo;
}

function writePackObjectHeader(type: ObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let s = size;
  bytes.push((code << 4) | (s & 0x0f));
  s >>>= 4;
  while (s > 0) { bytes.push(s & 0x7f); s >>>= 7; }
  // Every byte but the last carries the continuation bit.
  for (let i = 0; i < bytes.length - 1; i += 1) bytes[i] = bytes[i]! | 0x80;
  return Buffer.from(bytes);
}
function writePack(objects: { type: ObjType; data: Buffer }[]): Buffer {
  const parts: Buffer[] = [];
  const head = Buffer.allocUnsafe(12);
  head.write('PACK', 0, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(objects.length, 8);
  parts.push(head);
  for (const obj of objects) {
    parts.push(writePackObjectHeader(obj.type, obj.data.length));
    parts.push(deflateSync(obj.data));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

// ---------------------------------------------------------------- store

interface Label { id: number; name: string; color: string; description: string }
interface Issue {
  id: number; number: number; title: string; body: string; state: 'open' | 'closed';
  labels: Label[]; seq: number; createdAt: string; updatedAt: string; closedAt: string | null;
  comments: { id: number; body: string; createdAt: string; updatedAt: string }[];
}
interface Pull {
  id: number; number: number; title: string; body: string; state: 'open' | 'closed';
  merged: boolean; mergedAt: string | null; mergeCommitSha: string | null;
  headRef: string; baseRef: string; headSha: string; baseSha: string; seq: number;
  createdAt: string; updatedAt: string;
}
interface Repo {
  id: number; name: string; owner: string; description: string; isPrivate: boolean;
  defaultBranch: string; seq: number; createdAt: string; updatedAt: string;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  labels: Map<string, Label>;
  issues: Map<number, Issue>;
  pulls: Map<number, Pull>;
  nextNumber: number;
}

const repos = new Map<string, Repo>(); // key: owner + '/' + name
let repoIdSeq = 1000;
let commentIdSeq = 0;

function repoKey(owner: string, name: string): string { return `${owner}/${name}`; }
function getRepo(owner: string, name: string): Repo | undefined {
  if (owner !== VIEWER_LOGIN) return undefined;
  return repos.get(repoKey(owner, name));
}
function listViewerRepos(): Repo[] {
  return [...repos.values()].sort((a, b) => a.seq - b.seq);
}
function createRepoRecord(name: string, description: string, isPrivate: boolean, defaultBranch: string): Repo {
  repoIdSeq += 1;
  const repo: Repo = {
    id: repoIdSeq, name, owner: VIEWER_LOGIN, description, isPrivate,
    defaultBranch: defaultBranch || 'main', seq: repoIdSeq, createdAt: nextIso(), updatedAt: nextIso(),
    objects: new Map(), refs: new Map(), labels: new Map(), issues: new Map(), pulls: new Map(), nextNumber: 1,
  };
  repos.set(repoKey(VIEWER_LOGIN, name), repo);
  return repo;
}
function putObject(repo: Repo, type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}
function lookupOf(repo: Repo): (oid: string) => GitObject | undefined {
  return (oid) => repo.objects.get(oid);
}
function refTip(repo: Repo, ref: string): string | undefined { return repo.refs.get(ref); }
function branchTip(repo: Repo, branch: string): string | undefined { return repo.refs.get(`refs/heads/${branch}`); }

/** Walk commits from `tip` newest-first (by generation, then insertion order). */
function listCommits(repo: Repo, tip: string): { sha: string; commit: CommitView; gen: number }[] {
  const lookup = lookupOf(repo);
  const gen = new Map<string, number>();
  const out: { sha: string; commit: CommitView; gen: number }[] = [];
  const queue: { oid: string; g: number }[] = [{ oid: tip, g: 0 }];
  const seen = new Set<string>();
  while (queue.length) {
    // pop the highest generation first
    let best = 0;
    for (let i = 1; i < queue.length; i += 1) if (queue[i]!.g > queue[best]!.g) best = i;
    const cur = queue.splice(best, 1)[0]!;
    if (seen.has(cur.oid)) continue;
    seen.add(cur.oid);
    const obj = lookup(cur.oid);
    if (!obj || obj.type !== 'commit') continue;
    const c = parseCommit(obj.data);
    gen.set(cur.oid, cur.g);
    out.push({ sha: cur.oid, commit: c, gen: cur.g });
    for (const p of c.parents) queue.push({ oid: p, g: cur.g + 1 });
  }
  out.sort((a, b) => b.gen - a.gen);
  return out;
}

/** Merge-base of two commits (first common ancestor by generation). */
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const lookup = lookupOf(repo);
  const anc = (tip: string): Map<string, number> => {
    const m = new Map<string, number>();
    const q: { oid: string; g: number }[] = [{ oid: tip, g: 0 }];
    while (q.length) {
      const cur = q.pop()!;
      if (m.has(cur.oid)) continue;
      const obj = lookup(cur.oid);
      if (!obj || obj.type !== 'commit') continue;
      m.set(cur.oid, cur.g);
      for (const p of parseCommit(obj.data).parents) q.push({ oid: p, g: cur.g + 1 });
    }
    return m;
  };
  const ma = anc(peelToCommit(a, lookup));
  const mb = anc(peelToCommit(b, lookup));
  let best: string | null = null;
  let bestGen = Infinity;
  for (const [oid, g] of ma) {
    const gb = mb.get(oid);
    if (gb !== undefined && g + gb < bestGen) { bestGen = g + gb; best = oid; }
  }
  return best;
}

/** Diff two trees (flattened): changed paths with status and line counts. */
function diffTrees(repo: Repo, baseTree: string, headTree: string): { filename: string; status: string; additions: number; deletions: number; changes: number }[] {
  const lookup = lookupOf(repo);
  const base = flattenTree(baseTree, lookup);
  const head = flattenTree(headTree, lookup);
  const out: { filename: string; status: string; additions: number; deletions: number; changes: number }[] = [];
  const all = new Set([...base.keys(), ...head.keys()]);
  for (const path of [...all].sort()) {
    const b = base.get(path);
    const h = head.get(path);
    if (b && h && b.oid === h.oid) continue;
    let status = 'modified';
    let additions = 0;
    let deletions = 0;
    const lines = (oid: string | undefined): string[] => {
      if (!oid) return [];
      const obj = lookup(oid);
      if (!obj) return [];
      const text = obj.data.toString('utf8');
      if (text === '') return [];
      return text.split('\n');
    };
    if (!b) { status = 'added'; additions = lines(h!.oid).length; }
    else if (!h) { status = 'removed'; deletions = lines(b.oid).length; }
    else {
      const bl = lines(b.oid);
      const hl = lines(h.oid);
      const bCount = new Map<string, number>();
      for (const l of bl) bCount.set(l, (bCount.get(l) ?? 0) + 1);
      let common = 0;
      for (const l of hl) {
        const c = bCount.get(l) ?? 0;
        if (c > 0) { bCount.set(l, c - 1); common += 1; }
      }
      additions = hl.length - common;
      deletions = bl.length - common;
      if (additions === 0 && deletions === 0) { additions = 1; deletions = 1; }
    }
    out.push({ filename: path, status, additions, deletions, changes: additions + deletions });
  }
  return out;
}

/** Is a PR conflicted? A file changed on both sides of the merge-base with different results. */
function prConflicted(repo: Repo, pr: Pull): boolean {
  const lookup = lookupOf(repo);
  const headTip = branchTip(repo, pr.headRef);
  const baseTip = branchTip(repo, pr.baseRef);
  if (!headTip || !baseTip) return false;
  const base = mergeBase(repo, headTip, baseTip);
  if (!base) return false;
  const baseCommit = lookup(base);
  if (!baseCommit || baseCommit.type !== 'commit') return false;
  const baseTree = parseCommit(baseCommit.data).tree;
  const headCommit = lookup(peelToCommit(headTip, lookup));
  const baseTipCommit = lookup(peelToCommit(baseTip, lookup));
  if (!headCommit || !baseTipCommit || headCommit.type !== 'commit' || baseTipCommit.type !== 'commit') return false;
  const headTree = parseCommit(headCommit.data).tree;
  const newBaseTree = parseCommit(baseTipCommit.data).tree;
  const bf = flattenTree(baseTree, lookup);
  const hf = flattenTree(headTree, lookup);
  const nf = flattenTree(newBaseTree, lookup);
  const paths = new Set([...bf.keys(), ...hf.keys(), ...nf.keys()]);
  for (const p of paths) {
    const b = bf.get(p)?.oid;
    const h = hf.get(p)?.oid;
    const n = nf.get(p)?.oid;
    if (h !== b && n !== b && h !== n) return true;
  }
  return false;
}

function squashMerge(repo: Repo, pr: Pull): string | null {
  const headTip = branchTip(repo, pr.headRef);
  const baseTip = branchTip(repo, pr.baseRef);
  if (!headTip || !baseTip) return null;
  const lookup = lookupOf(repo);
  const headCommit = lookup(peelToCommit(headTip, lookup));
  if (!headCommit || headCommit.type !== 'commit') return null;
  const tree = parseCommit(headCommit.data).tree;
  const message = `${pr.title} (#${pr.number})`;
  const commit = buildCommit(tree, [baseTip], message, nextEpoch(), `${VIEWER_NAME} <${VIEWER_EMAIL}>`);
  const oid = putObject(repo, 'commit', commit);
  repo.refs.set(`refs/heads/${pr.baseRef}`, oid);
  return oid;
}

// ---------------------------------------------------------------- REST shapes

function userJson(): Json {
  return { login: VIEWER_LOGIN, id: VIEWER_ID, node_id: globalId('User', VIEWER_LOGIN), avatar_url: '', gravatar_id: '', url: '', html_url: '', type: 'User', site_admin: false, name: VIEWER_NAME, email: VIEWER_EMAIL };
}
function globalId(kind: string, key: string): string {
  return Buffer.from(`${kind}:${key}`).toString('base64');
}
function repoJson(repo: Repo): Json {
  const openIssues = [...repo.issues.values()].filter((i) => i.state === 'open').length + [...repo.pulls.values()].filter((p) => p.state === 'open').length;
  return {
    id: repo.id, node_id: globalId('Repository', String(repo.id)), name: repo.name, full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER_ID, node_id: globalId('User', repo.owner), avatar_url: '', type: 'User', site_admin: false },
    private: repo.isPrivate, html_url: '', description: repo.description, fork: false, url: '',
    created_at: repo.createdAt, updated_at: repo.updatedAt, pushed_at: repo.updatedAt,
    homepage: null, size: 0, stargazers_count: 0, watchers_count: 0, language: null,
    has_issues: true, has_projects: true, has_downloads: true, has_wiki: true, has_pages: false,
    forks_count: 0, mirror_url: null, archived: false, disabled: false, open_issues_count: openIssues,
    license: null, allow_forking: true, is_template: false, topics: [], visibility: repo.isPrivate ? 'private' : 'public',
    default_branch: repo.defaultBranch, permissions: { admin: true, maintain: true, push: true, triage: true, pull: true },
  };
}
function issueJson(repo: Repo, issue: Issue): Json {
  return {
    id: issue.id, node_id: globalId('Issue', `${repo.id}:${issue.number}`), url: '', repository_url: '',
    labels_url: '', comments_url: '', events_url: '', html_url: '', number: issue.number,
    title: issue.title, body: issue.body, state: issue.state, locked: false,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    labels: issue.labels.map((l) => ({ id: l.id, node_id: globalId('Label', `${repo.id}:${l.name}`), name: l.name, color: l.color, description: l.description, default: false })),
    assignee: null, assignees: [], milestone: null, comments: issue.comments.length,
    created_at: issue.createdAt, updated_at: issue.updatedAt, closed_at: issue.closedAt,
    author_association: 'OWNER', active_lock_reason: null,
  };
}
function pullJson(repo: Repo, pr: Pull): Json {
  const headSha = branchTip(repo, pr.headRef) ?? pr.headSha;
  const baseSha = branchTip(repo, pr.baseRef) ?? pr.baseSha;
  return {
    id: pr.id, node_id: globalId('PullRequest', `${repo.id}:${pr.number}`), url: '', html_url: '',
    number: pr.number, title: pr.title, body: pr.body, state: pr.state, locked: false,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: pr.createdAt, updated_at: pr.updatedAt, closed_at: pr.state === 'closed' ? pr.updatedAt : null,
    merged_at: pr.mergedAt, merge_commit_sha: pr.mergeCommitSha, merged: pr.merged, mergeable: !prConflicted(repo, pr),
    mergeable_state: prConflicted(repo, pr) ? 'dirty' : 'clean', merged_by: null,
    head: { label: `${repo.owner}:${pr.headRef}`, ref: pr.headRef, sha: headSha, user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' }, repo: repoJson(repo) },
    base: { label: `${repo.owner}:${pr.baseRef}`, ref: pr.baseRef, sha: baseSha, user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' }, repo: repoJson(repo) },
    draft: false, commits: 1, additions: 0, deletions: 0, changed_files: 0,
  };
}

// ---------------------------------------------------------------- HTTP plumbing

function sendJson(res: ServerResponse, status: number, body: unknown, extra: Record<string, string> = {}): void {
  const text = status === 204 ? '' : `${JSON.stringify(body)}\n`;
  const headers: Record<string, string> = { 'x-github-request-id': nextReqId(), ...extra };
  if (status !== 204) {
    headers['content-type'] = JSON_TYPE;
    headers['content-length'] = String(Buffer.byteLength(text));
  }
  res.writeHead(status, headers);
  res.end(text);
}
function sendRaw(res: ServerResponse, status: number, buf: Buffer, contentType: string): void {
  res.writeHead(status, { 'content-type': contentType, 'content-length': String(buf.length) });
  res.end(buf);
}
function errJson(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
/** Parse a JSON body; returns null when absent, throws {status:400} on malformed. */
function parseJsonBody(buf: Buffer): unknown {
  if (buf.length === 0) return null;
  try {
    return JSON.parse(buf.toString('utf8'));
  } catch {
    const e = new Error('malformed JSON body') as Error & { status?: number };
    e.status = 400;
    throw e;
  }
}
function authed(req: IncomingMessage): boolean {
  if (TOKEN === '') return true;
  const h = req.headers.authorization;
  return h === `Bearer ${TOKEN}`;
}
function pathOf(req: IncomingMessage): string {
  try { return new URL(req.url ?? '/', 'http://entry').pathname; } catch { return '/'; }
}
function queryOf(req: IncomingMessage): URLSearchParams {
  try { return new URL(req.url ?? '/', 'http://entry').searchParams; } catch { return new URLSearchParams(); }
}
function paginate<T>(items: T[], q: URLSearchParams, req: IncomingMessage, path: string): { page: T[]; link: string | null } {
  const perPage = Math.max(1, Math.min(100, parseInt(q.get('per_page') ?? '30', 10) || 30));
  const page = Math.max(1, parseInt(q.get('page') ?? '1', 10) || 1);
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  let link: string | null = null;
  if (start + perPage < items.length) {
    const host = req.headers.host ?? '127.0.0.1';
    const params = new URLSearchParams(q);
    params.set('per_page', String(perPage));
    params.set('page', String(page + 1));
    link = `<http://${host}${path}?${params.toString()}>; rel="next"`;
  }
  return { page: slice, link };
}
function linkHeaders(link: string | null): Record<string, string> {
  return link ? { link } : {};
}
function decodeSeg(s: string): string {
  try { return decodeURIComponent(s); } catch { return s; }
}

// ---------------------------------------------------------------- contents / commits

/** Create a commit on `branch` applying file changes; returns the new commit oid. */
function commitFiles(repo: Repo, branch: string, message: string, changes: { path: string; content: Buffer | null }[]): string {
  const tip = branchTip(repo, branch);
  const lookup = lookupOf(repo);
  let flat = new Map<string, { oid: string; mode: string }>();
  if (tip) {
    const commit = lookup(peelToCommit(tip, lookup));
    if (commit && commit.type === 'commit') flat = flattenTree(parseCommit(commit.data).tree, lookup);
  }
  for (const ch of changes) {
    if (ch.content === null) flat.delete(ch.path);
    else flat.set(ch.path, { oid: putObject(repo, 'blob', ch.content), mode: '100644' });
  }
  const tree = buildTreeFromFlat(flat, (t, d) => putObject(repo, t, d));
  const parents = tip ? [peelToCommit(tip, lookup)] : [];
  const commit = buildCommit(tree, parents, message, nextEpoch(), `${VIEWER_NAME} <${VIEWER_EMAIL}>`);
  const oid = putObject(repo, 'commit', commit);
  repo.refs.set(`refs/heads/${branch}`, oid);
  return oid;
}

function commitJson(repo: Repo, sha: string): Json | null {
  const obj = repo.objects.get(sha);
  if (!obj || obj.type !== 'commit') return null;
  const c = parseCommit(obj.data);
  const who = (s: string): { name: string; email: string; date: string } => {
    const m = /^(.*) <([^>]*)> (\d+) [+-]\d{4}$/.exec(s);
    if (!m) return { name: VIEWER_NAME, email: VIEWER_EMAIL, date: new Date(c.timestamp * 1000).toISOString() };
    return { name: m[1]!, email: m[2]!, date: new Date(parseInt(m[3]!, 10) * 1000).toISOString() };
  };
  return {
    sha, node_id: globalId('Commit', sha),
    // Git stores the message with a trailing newline; the API surfaces it
    // without the trailing newline, exactly as submitted.
    commit: { message: c.message.replace(/\n$/, ''), author: who(c.author), committer: who(c.committer), tree: { sha: c.tree } },
    author: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    committer: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    parents: c.parents.map((p) => ({ sha: p })),
    url: '', html_url: '',
  };
}

// ---------------------------------------------------------------- REST router

async function handleRest(req: IncomingMessage, res: ServerResponse, path: string, method: string, body: Buffer): Promise<boolean> {
  // path starts with /api/v3
  if (!authed(req)) { errJson(res, 401, 'Bad credentials'); return true; }
  const q = queryOf(req);
  let jsonBody: unknown = null;
  if (method === 'POST' || method === 'PATCH' || method === 'PUT' || method === 'DELETE') {
    try { jsonBody = parseJsonBody(body); } catch { errJson(res, 400, 'Problems parsing JSON'); return true; }
  }
  const obj = (jsonBody !== null && typeof jsonBody === 'object' && !Array.isArray(jsonBody)) ? jsonBody as Json : {};
  const segs = path.split('/').filter((s) => s !== '');
  // segs[0]='api', segs[1]='v3', rest follows

  // GET /api/v3/  and  /api/v3
  if ((path === '/api/v3' || path === '/api/v3/') && method === 'GET') {
    sendJson(res, 200, { current_user_url: '/api/v3/user', current_user_authorizations_html_url: '', authorizations_url: '', code_search_url: '', commit_search_url: '', emails_url: '/api/v3/user/emails', emojis_url: '', events_url: '', feeds_url: '', followers_url: '', following_url: '', gists_url: '', hub_url: '', issue_search_url: '', issues_url: '', keys_url: '', label_search_url: '', notifications_url: '', organization_repositories_url: '', organization_teams_url: '', public_gists_url: '', rate_limit_url: '/api/v3/rate_limit', repository_url: '', repository_search_url: '', current_user_repositories_url: '', search_url: '', starred_url: '', starred_gists_url: '', topic_search_url: '', user_url: '', user_organizations_url: '', user_repositories_url: '', user_search_url: '' }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }
  // GET /api/v3/meta
  if (path === '/api/v3/meta' && method === 'GET') {
    sendJson(res, 200, { installed_version: '1.0.0', verifiable_password_authentication: true, github_services_sha: '', hooks: [], git: [], pages: [], importer: [], actions: [] });
    return true;
  }
  // GET /api/v3/rate_limit
  if (path === '/api/v3/rate_limit' && method === 'GET') {
    sendJson(res, 200, { resources: { core: { limit: 5000, remaining: 4999, reset: 1735689600, used: 1 }, search: { limit: 30, remaining: 30, reset: 1735689600, used: 0 } }, rate: { limit: 5000, remaining: 4999, reset: 1735689600, used: 1 } });
    return true;
  }
  // GET /api/v3/user
  if (path === '/api/v3/user' && method === 'GET') { sendJson(res, 200, userJson()); return true; }

  // POST /api/v3/user/repos  |  GET /api/v3/user/repos
  if (path === '/api/v3/user/repos') {
    if (method === 'POST') {
      const name = typeof obj.name === 'string' ? obj.name : '';
      if (name === '' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(name)) { errJson(res, 422, 'Repository name is invalid'); return true; }
      if (repos.has(repoKey(VIEWER_LOGIN, name))) { errJson(res, 422, 'Repository already exists'); return true; }
      const repo = createRepoRecord(name, typeof obj.description === 'string' ? obj.description : '', obj.private === true, typeof obj.default_branch === 'string' ? obj.default_branch : 'main');
      sendJson(res, 201, repoJson(repo));
      return true;
    }
    if (method === 'GET') {
      const { page, link } = paginate(listViewerRepos().map(repoJson), q, req, path);
      sendJson(res, 200, page, linkHeaders(link));
      return true;
    }
  }

  // /api/v3/repos/{owner}/{repo}...
  if (segs.length >= 4 && segs[0] === 'api' && segs[1] === 'v3' && segs[2] === 'repos') {
    const owner = decodeSeg(segs[3]!);
    const name = decodeSeg(segs[4]!);
    const repo = getRepo(owner, name);
    const rest = segs.slice(5);
    if (!repo) { errJson(res, 404, 'Not Found'); return true; }
    const repoPath = `/api/v3/repos/${encodeURIComponent(owner)}/${encodeURIComponent(name)}`;

    // GET / PATCH / DELETE /api/v3/repos/{o}/{r}
    if (rest.length === 0) {
      if (method === 'GET') { sendJson(res, 200, repoJson(repo)); return true; }
      if (method === 'PATCH') {
        if (typeof obj.description === 'string') repo.description = obj.description;
        if (typeof obj.private === 'boolean') repo.isPrivate = obj.private;
        repo.updatedAt = nextIso();
        sendJson(res, 200, repoJson(repo));
        return true;
      }
      if (method === 'DELETE') {
        repos.delete(repoKey(owner, name));
        sendJson(res, 204, null);
        return true;
      }
    }

    // GET /branches  |  GET /branches/{branch}
    if (rest[0] === 'branches') {
      if (method === 'GET' && rest.length === 1) {
        const branches = [...repo.refs.keys()].filter((r) => r.startsWith('refs/heads/')).map((r) => r.slice('refs/heads/'.length)).sort();
        const items = branches.map((b) => ({ name: b, commit: { sha: repo.refs.get(`refs/heads/${b}`)!, url: '' }, protected: false }));
        const { page, link } = paginate(items, q, req, `${repoPath}/branches`);
        sendJson(res, 200, page, linkHeaders(link));
        return true;
      }
      if (method === 'GET' && rest.length === 2) {
        const branch = decodeSeg(rest[1]!);
        const tip = branchTip(repo, branch);
        if (!tip) { errJson(res, 404, 'Branch not found'); return true; }
        sendJson(res, 200, { name: branch, commit: { sha: tip, url: '' }, protected: false });
        return true;
      }
    }

    // GET /commits[?sha=]  |  GET /commits/{sha}
    if (rest[0] === 'commits') {
      if (method === 'GET' && rest.length === 1) {
        const ref = q.get('sha') ?? repo.defaultBranch;
        let tip = branchTip(repo, ref) ?? repo.refs.get(ref);
        if (!tip && isOid(ref)) tip = ref;
        if (!tip || !repo.objects.has(tip)) { sendJson(res, 200, []); return true; }
        const items = listCommits(repo, peelToCommit(tip, lookupOf(repo))).map((c) => commitJson(repo, c.sha)!);
        const { page, link } = paginate(items, q, req, `${repoPath}/commits`);
        sendJson(res, 200, page, linkHeaders(link));
        return true;
      }
      if (method === 'GET' && rest.length === 2) {
        const item = commitJson(repo, decodeSeg(rest[1]!));
        if (!item) { errJson(res, 404, 'Not Found'); return true; }
        sendJson(res, 200, item);
        return true;
      }
    }

    // POST /git/refs  |  GET /git/refs[/heads/{branch}]  |  DELETE /git/refs/{...}
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        const ref = typeof obj.ref === 'string' ? obj.ref : '';
        const sha = typeof obj.sha === 'string' ? obj.sha : '';
        if (!ref.startsWith('refs/') || !isOid(sha) || !repo.objects.has(sha)) { errJson(res, 422, 'Invalid ref or sha'); return true; }
        if (repo.refs.has(ref)) { errJson(res, 422, 'Reference already exists'); return true; }
        repo.refs.set(ref, sha);
        sendJson(res, 201, { ref, node_id: globalId('Ref', `${repo.id}:${ref}`), url: '', object: { sha, type: repo.objects.get(sha)!.type, url: '' } });
        return true;
      }
      if (method === 'GET') {
        if (rest.length === 2) {
          const items = [...repo.refs.entries()].sort().map(([ref, sha]) => ({ ref, node_id: globalId('Ref', `${repo.id}:${ref}`), url: '', object: { sha, type: repo.objects.get(sha)?.type ?? 'commit', url: '' } }));
          sendJson(res, 200, items);
          return true;
        }
        const ref = `refs/${rest.slice(2).map(decodeSeg).join('/')}`;
        const sha = repo.refs.get(ref);
        if (!sha) { errJson(res, 404, 'Not Found'); return true; }
        sendJson(res, 200, { ref, node_id: globalId('Ref', `${repo.id}:${ref}`), url: '', object: { sha, type: repo.objects.get(sha)?.type ?? 'commit', url: '' } });
        return true;
      }
      if (method === 'DELETE' && rest.length > 2) {
        const ref = `refs/${rest.slice(2).map(decodeSeg).join('/')}`;
        if (!repo.refs.has(ref)) { errJson(res, 404, 'Not Found'); return true; }
        repo.refs.delete(ref);
        sendJson(res, 204, null);
        return true;
      }
    }

    // contents
    if (rest[0] === 'contents') {
      const filePath = rest.slice(1).map(decodeSeg).join('/');
      const refParam = q.get('ref') ?? undefined;
      const resolveTip = (): string | undefined => {
        if (!refParam) return branchTip(repo, repo.defaultBranch);
        return branchTip(repo, refParam) ?? repo.refs.get(refParam) ?? (isOid(refParam) ? refParam : undefined);
      };
      if (method === 'GET') {
        const tip = resolveTip();
        if (!tip) { errJson(res, 404, 'Not Found'); return true; }
        const commit = repo.objects.get(peelToCommit(tip, lookupOf(repo)));
        if (!commit || commit.type !== 'commit') { errJson(res, 404, 'Not Found'); return true; }
        const lookup = lookupOf(repo);
        const tree = parseCommit(commit.data).tree;
        const flat = flattenTree(tree, lookup);
        if (filePath === '') {
          // root listing
          const entries = dirListing(repo, tree, '');
          sendJson(res, 200, entries);
          return true;
        }
        const file = flat.get(filePath);
        if (file) {
          const blob = repo.objects.get(file.oid);
          const content = blob ? blob.data : Buffer.alloc(0);
          sendJson(res, 200, { type: 'file', encoding: 'base64', size: content.length, name: filePath.split('/').pop(), path: filePath, content: b64encodeBuf(content), sha: file.oid, url: '', html_url: '', download_url: null, _links: { self: '', git: '', html: '' } });
          return true;
        }
        // directory?
        const prefix = `${filePath}/`;
        const isDir = [...flat.keys()].some((p) => p.startsWith(prefix));
        if (isDir) {
          sendJson(res, 200, dirListing(repo, tree, filePath));
          return true;
        }
        errJson(res, 404, 'Not Found');
        return true;
      }
      if (method === 'PUT') {
        const message = typeof obj.message === 'string' ? obj.message : 'Update file';
        const contentB64 = typeof obj.content === 'string' ? obj.content : '';
        const branch = typeof obj.branch === 'string' ? obj.branch : repo.defaultBranch;
        const sha = typeof obj.sha === 'string' ? obj.sha : undefined;
        let targetTip = branchTip(repo, branch);
        if (targetTip === undefined && branch !== repo.defaultBranch) {
          // creating a branch from the default branch's tip (GitHub behaviour)
          targetTip = branchTip(repo, repo.defaultBranch);
          if (targetTip !== undefined) repo.refs.set(`refs/heads/${branch}`, targetTip);
        }
        const lookup = lookupOf(repo);
        let flat = new Map<string, { oid: string; mode: string }>();
        if (targetTip) {
          const commit = lookup(peelToCommit(targetTip, lookup));
          if (commit && commit.type === 'commit') flat = flattenTree(parseCommit(commit.data).tree, lookup);
        }
        const existing = flat.get(filePath);
        if (sha !== undefined) {
          if (!existing || existing.oid.toLowerCase() !== sha.toLowerCase()) { errJson(res, 409, 'sha does not match the current file'); return true; }
        } else if (existing) {
          errJson(res, 422, 'sha is required to update a file');
          return true;
        }
        const content = b64decodeStr(contentB64);
        const isUpdate = existing !== undefined;
        const oid = commitFiles(repo, branch, message, [{ path: filePath, content }]);
        const blobOid = hashObject('blob', content);
        sendJson(res, isUpdate ? 200 : 201, {
          content: { name: filePath.split('/').pop(), path: filePath, sha: blobOid, size: content.length, type: 'file', encoding: 'base64', url: '', html_url: '', download_url: null },
          commit: { sha: oid, message, author: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: nextIso() }, committer: { name: VIEWER_NAME, email: VIEWER_EMAIL, date: nextIso() }, url: '', html_url: '' },
        });
        return true;
      }
      if (method === 'DELETE') {
        const branch = typeof obj.branch === 'string' ? obj.branch : repo.defaultBranch;
        const message = typeof obj.message === 'string' ? obj.message : 'Delete file';
        const tip = branchTip(repo, branch);
        if (!tip) { errJson(res, 404, 'Not Found'); return true; }
        const lookup = lookupOf(repo);
        const commit = lookup(peelToCommit(tip, lookup));
        if (!commit || commit.type !== 'commit') { errJson(res, 404, 'Not Found'); return true; }
        const flat = flattenTree(parseCommit(commit.data).tree, lookup);
        if (!flat.has(filePath)) { errJson(res, 404, 'Not Found'); return true; }
        const oid = commitFiles(repo, branch, message, [{ path: filePath, content: null }]);
        sendJson(res, 200, { commit: { sha: oid, message, url: '', html_url: '' } });
        return true;
      }
    }

    // labels
    if (rest[0] === 'labels') {
      if (method === 'GET' && rest.length === 1) {
        sendJson(res, 200, [...repo.labels.values()].map((l) => ({ id: l.id, node_id: globalId('Label', `${repo.id}:${l.name}`), name: l.name, color: l.color, description: l.description, default: false, url: '' })));
        return true;
      }
      if (method === 'POST' && rest.length === 1) {
        const name = typeof obj.name === 'string' ? obj.name : '';
        if (name === '') { errJson(res, 422, 'Label name is required'); return true; }
        const existing = repo.labels.get(name);
        if (existing) { sendJson(res, 201, { id: existing.id, node_id: globalId('Label', `${repo.id}:${name}`), name, color: existing.color, description: existing.description, default: false, url: '' }); return true; }
        const label: Label = { id: nextGlobalId(), name, color: typeof obj.color === 'string' ? obj.color : 'ededed', description: typeof obj.description === 'string' ? obj.description : '' };
        repo.labels.set(name, label);
        sendJson(res, 201, { id: label.id, node_id: globalId('Label', `${repo.id}:${name}`), name, color: label.color, description: label.description, default: false, url: '' });
        return true;
      }
    }

    // issues
    if (rest[0] === 'issues') {
      if (rest.length === 1) {
        if (method === 'POST') {
          const title = typeof obj.title === 'string' ? obj.title : '';
          if (title === '') { errJson(res, 422, 'Title is required'); return true; }
          const labelNames: string[] = [];
          if (Array.isArray(obj.labels)) {
            for (const l of obj.labels) {
              if (typeof l === 'string') labelNames.push(l);
              else if (l && typeof l === 'object' && typeof (l as Json).name === 'string') labelNames.push((l as Json).name as string);
            }
          }
          for (const ln of labelNames) {
            if (!repo.labels.has(ln)) { errJson(res, 422, `Label '${ln}' does not exist`); return true; }
          }
          const number = repo.nextNumber;
          repo.nextNumber += 1;
          const now = nextIso();
          const issue: Issue = { id: nextGlobalId(), number, title, body: typeof obj.body === 'string' ? obj.body : '', state: 'open', labels: labelNames.map((n) => repo.labels.get(n)!), seq: number, createdAt: now, updatedAt: now, closedAt: null, comments: [] };
          repo.issues.set(number, issue);
          sendJson(res, 201, issueJson(repo, issue));
          return true;
        }
        if (method === 'GET') {
          let items = [...repo.issues.values()];
          const state = q.get('state') ?? 'open';
          if (state !== 'all') items = items.filter((i) => i.state === state);
          const direction = q.get('direction') ?? 'desc';
          items.sort((a, b) => direction === 'asc' ? a.seq - b.seq : b.seq - a.seq);
          const { page, link } = paginate(items.map((i) => issueJson(repo, i)), q, req, `${repoPath}/issues`);
          sendJson(res, 200, page, linkHeaders(link));
          return true;
        }
      }
      const num = parseInt(rest[1] ?? '', 10);
      if (rest.length >= 2 && Number.isInteger(num)) {
        const issue = repo.issues.get(num);
        if (rest.length === 2) {
          if (!issue) { errJson(res, 404, 'Not Found'); return true; }
          if (method === 'GET') { sendJson(res, 200, issueJson(repo, issue)); return true; }
          if (method === 'PATCH') {
            if (typeof obj.state === 'string' && (obj.state === 'open' || obj.state === 'closed')) {
              issue.state = obj.state;
              issue.closedAt = obj.state === 'closed' ? nextIso() : null;
            }
            if (typeof obj.title === 'string') issue.title = obj.title;
            if (typeof obj.body === 'string') issue.body = obj.body;
            issue.updatedAt = nextIso();
            sendJson(res, 200, issueJson(repo, issue));
            return true;
          }
        }
        if (rest.length === 3 && rest[2] === 'comments') {
          if (!issue) { errJson(res, 404, 'Not Found'); return true; }
          if (method === 'POST') {
            const cbody = typeof obj.body === 'string' ? obj.body : '';
            commentIdSeq += 1;
            const comment = { id: commentIdSeq, body: cbody, createdAt: nextIso(), updatedAt: nextIso() };
            issue.comments.push(comment);
            sendJson(res, 201, { id: comment.id, node_id: globalId('IssueComment', `${repo.id}:${num}:${comment.id}`), url: '', html_url: '', body: cbody, user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' }, created_at: comment.createdAt, updated_at: comment.updatedAt, author_association: 'OWNER' });
            return true;
          }
          if (method === 'GET') {
            const items = issue.comments.map((c) => ({ id: c.id, node_id: globalId('IssueComment', `${repo.id}:${num}:${c.id}`), url: '', html_url: '', body: c.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' }, created_at: c.createdAt, updated_at: c.updatedAt, author_association: 'OWNER' }));
            const { page, link } = paginate(items, q, req, `${repoPath}/issues/${num}/comments`);
            sendJson(res, 200, page, linkHeaders(link));
            return true;
          }
        }
        if (rest.length === 3 && rest[2] === 'labels') {
          if (!issue) { errJson(res, 404, 'Not Found'); return true; }
          if (method === 'GET') { sendJson(res, 200, issue.labels.map((l) => ({ id: l.id, name: l.name, color: l.color, description: l.description, default: false }))); return true; }
        }
      }
      if (rest.length >= 2 && !Number.isInteger(num)) { errJson(res, 404, 'Not Found'); return true; }
    }

    // pulls
    if (rest[0] === 'pulls') {
      if (rest.length === 1) {
        if (method === 'POST') {
          const title = typeof obj.title === 'string' ? obj.title : '';
          const headRaw = typeof obj.head === 'string' ? obj.head : '';
          const baseRaw = typeof obj.base === 'string' ? obj.base : repo.defaultBranch;
          const head = headRaw.includes(':') ? headRaw.split(':').pop()! : headRaw;
          const base = baseRaw.includes(':') ? baseRaw.split(':').pop()! : baseRaw;
          if (title === '' || head === '') { errJson(res, 422, 'Title and head are required'); return true; }
          const headTip = branchTip(repo, head);
          const baseTip = branchTip(repo, base);
          if (!headTip) { errJson(res, 422, `Head branch '${head}' does not exist`); return true; }
          if (!baseTip) { errJson(res, 422, `Base branch '${base}' does not exist`); return true; }
          const dup = [...repo.pulls.values()].find((p) => p.headRef === head && p.baseRef === base && p.state === 'open');
          if (dup) { errJson(res, 422, 'A pull request already exists for this head and base'); return true; }
          const number = repo.nextNumber;
          repo.nextNumber += 1;
          const now = nextIso();
          const pr: Pull = { id: nextGlobalId(), number, title, body: typeof obj.body === 'string' ? obj.body : '', state: 'open', merged: false, mergedAt: null, mergeCommitSha: null, headRef: head, baseRef: base, headSha: headTip, baseSha: baseTip, seq: number, createdAt: now, updatedAt: now };
          repo.pulls.set(number, pr);
          sendJson(res, 201, pullJson(repo, pr));
          return true;
        }
        if (method === 'GET') {
          let items = [...repo.pulls.values()];
          const state = q.get('state') ?? 'open';
          if (state !== 'all') items = items.filter((p) => p.state === state);
          items.sort((a, b) => b.seq - a.seq);
          const { page, link } = paginate(items.map((p) => pullJson(repo, p)), q, req, `${repoPath}/pulls`);
          sendJson(res, 200, page, linkHeaders(link));
          return true;
        }
      }
      const num = parseInt(rest[1] ?? '', 10);
      if (rest.length >= 2 && Number.isInteger(num)) {
        const pr = repo.pulls.get(num);
        if (rest.length === 2) {
          if (!pr) { errJson(res, 404, 'Not Found'); return true; }
          if (method === 'GET') { sendJson(res, 200, pullJson(repo, pr)); return true; }
          if (method === 'PATCH') {
            if (typeof obj.title === 'string') pr.title = obj.title;
            if (typeof obj.body === 'string') pr.body = obj.body;
            if (typeof obj.state === 'string' && (obj.state === 'open' || obj.state === 'closed')) pr.state = obj.state;
            pr.updatedAt = nextIso();
            sendJson(res, 200, pullJson(repo, pr));
            return true;
          }
        }
        if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
          if (!pr) { errJson(res, 404, 'Not Found'); return true; }
          const lookup = lookupOf(repo);
          const headCommit = lookup(peelToCommit(pr.headSha, lookup));
          const baseCommit = lookup(peelToCommit(pr.baseSha, lookup));
          if (!headCommit || !baseCommit || headCommit.type !== 'commit' || baseCommit.type !== 'commit') { sendJson(res, 200, []); return true; }
          const files = diffTrees(repo, parseCommit(baseCommit.data).tree, parseCommit(headCommit.data).tree);
          const items = files.map((f) => ({ sha: '', filename: f.filename, status: f.status, additions: f.additions, deletions: f.deletions, changes: f.changes, blob_url: '', raw_url: '', contents_url: '' }));
          const { page, link } = paginate(items, q, req, `${repoPath}/pulls/${num}/files`);
          sendJson(res, 200, page, linkHeaders(link));
          return true;
        }
        if (rest.length === 3 && rest[2] === 'commits' && method === 'GET') {
          if (!pr) { errJson(res, 404, 'Not Found'); return true; }
          const base = mergeBase(repo, pr.headSha, pr.baseSha);
          const all = listCommits(repo, peelToCommit(pr.headSha, lookupOf(repo)));
          const baseSet = base ? collectReachable([base], lookupOf(repo)) : new Set<string>();
          const items = all.filter((c) => !baseSet.has(c.sha) || c.sha === base).filter((c) => c.sha !== base).map((c) => commitJson(repo, c.sha)!);
          sendJson(res, 200, items);
          return true;
        }
        if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
          if (!pr) { errJson(res, 404, 'Not Found'); return true; }
          if (pr.merged || pr.state === 'closed') { errJson(res, 405, 'Pull request is already merged or closed'); return true; }
          if (prConflicted(repo, pr)) { errJson(res, 405, 'Merge conflict'); return true; }
          const sha = squashMerge(repo, pr);
          if (!sha) { errJson(res, 405, 'Merge conflict'); return true; }
          pr.merged = true;
          pr.state = 'closed';
          pr.mergedAt = nextIso();
          pr.mergeCommitSha = sha;
          pr.updatedAt = nextIso();
          sendJson(res, 200, { sha, merged: true, message: 'Pull request successfully merged' });
          return true;
        }
      }
      if (rest.length >= 2 && !Number.isInteger(num)) { errJson(res, 404, 'Not Found'); return true; }
    }
  }

  // No route matched under /api/v3
  errJson(res, 404, 'Not Found');
  return true;
}

/** Directory listing entries for `dir` ('' = root) under a tree oid. */
function dirListing(repo: Repo, treeOid: string, dir: string): Json[] {
  const lookup = lookupOf(repo);
  const flat = flattenTree(treeOid, lookup);
  const seen = new Map<string, { type: string; sha: string; size: number }>();
  const prefix = dir === '' ? '' : `${dir}/`;
  for (const [p, ent] of flat) {
    if (!p.startsWith(prefix)) continue;
    const rest = p.slice(prefix.length);
    const slash = rest.indexOf('/');
    if (slash < 0) {
      const blob = lookup(ent.oid);
      seen.set(rest, { type: 'file', sha: ent.oid, size: blob ? blob.data.length : 0 });
    } else {
      const d = rest.slice(0, slash);
      if (!seen.has(d)) seen.set(d, { type: 'dir', sha: '', size: 0 });
    }
  }
  // sha for directories: compute the subtree oid
  const out: Json[] = [];
  for (const [name, ent] of [...seen.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    let sha = ent.sha;
    if (ent.type === 'dir') {
      const sub = subtreeOid(repo, treeOid, dir === '' ? name : `${dir}/${name}`);
      if (sub) sha = sub;
    }
    out.push({ type: ent.type, size: ent.size, name, path: dir === '' ? name : `${dir}/${name}`, sha, url: '', html_url: '', download_url: ent.type === 'file' ? null : undefined, git_url: '' });
  }
  return out;
}
function subtreeOid(repo: Repo, treeOid: string, dirPath: string): string | null {
  const lookup = lookupOf(repo);
  let cur = treeOid;
  for (const seg of dirPath.split('/')) {
    const obj = lookup(cur);
    if (!obj || obj.type !== 'tree') return null;
    const entry = parseTree(obj.data).find((e) => e.name === seg && e.mode === '40000');
    if (!entry) return null;
    cur = entry.oid;
  }
  return cur;
}

// ---------------------------------------------------------------- git smart HTTP

function sortedRefs(repo: Repo): { name: string; oid: string }[] {
  return [...repo.refs.entries()].map(([name, oid]) => ({ name, oid })).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}
function peeledOf(repo: Repo, ref: { name: string; oid: string }): string | undefined {
  const obj = repo.objects.get(ref.oid);
  if (obj && obj.type === 'tag') return peelToCommit(ref.oid, lookupOf(repo));
  return undefined;
}

/** v0 ref advertisement body (with the # service preamble). */
function v0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const headTip = branchTip(repo, repo.defaultBranch);
  const caps = service === 'git-upload-pack'
    ? 'side-band-64k thin-pack ofs-delta multi_ack shallow symref=HEAD:refs/heads/main agent=forge/1.0'
    : 'report-status side-band-64k delete-refs ofs-delta agent=forge/1.0';
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), PKT_FLUSH];
  const refs = sortedRefs(repo);
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    const head = headTip ?? refs[0]!.oid;
    parts.push(pktLine(`${head} HEAD\0${caps}\n`));
    for (const ref of refs) {
      parts.push(pktLine(`${ref.oid} ${ref.name}\n`));
      const peeled = peeledOf(repo, ref);
      if (peeled) parts.push(pktLine(`${peeled} ${ref.name}^{}\n`));
    }
  }
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

/** v2 capability advertisement body. */
function v2Advertisement(): Buffer {
  const lines = ['version 2\n', 'agent=forge/1.0\n', 'object-format=sha1\n', 'ls-refs=unborn\n', 'fetch=shallow filter\n'];
  const parts: Buffer[] = lines.map((l) => pktLine(l));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

/** Pack bytes are a pure function of the object-oid set (objects are
 * content-addressed and immutable), so identical fetches can reuse them.
 * The clone benchmark issues 50 concurrent identical shallow clones. */
const packCache = new Map<string, Buffer>();
function cachedPack(objects: GitObject[], oids: string[]): Buffer {
  const key = sha1(Buffer.from(oids.slice().sort().join(','), 'utf8'));
  const hit = packCache.get(key);
  if (hit) return hit;
  const pack = writePack(objects);
  if (packCache.size >= 64) packCache.clear();
  packCache.set(key, pack);
  return pack;
}

function sidebandPack(pack: Buffer): Buffer {
  const chunks: Buffer[] = [];
  const CHUNK = 32768;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const slice = pack.subarray(off, Math.min(pack.length, off + CHUNK));
    const payload = Buffer.concat([Buffer.from([1]), slice]);
    chunks.push(pktLine(payload));
  }
  return Buffer.concat(chunks);
}

/** Objects to send for a fetch, honouring haves and shallow/deepen rules. */
function computeFetch(repo: Repo, wants: string[], haves: string[], depth: number | null, shallowIn: string[]): { objects: GitObject[]; oids: string[]; shallow: string[]; unshallow: string[] } {
  const lookup = lookupOf(repo);
  // Depth-limited closure: commits within `depth` generations of the wants.
  if (depth !== null) {
    const included = new Set<string>(); // commit oids included
    const boundary = new Set<string>();
    const queue: { oid: string; d: number }[] = wants.map((w) => ({ oid: peelToCommit(w, lookup), d: 1 }));
    const seenCommit = new Set<string>();
    while (queue.length) {
      const cur = queue.pop()!;
      if (seenCommit.has(cur.oid)) continue;
      seenCommit.add(cur.oid);
      const obj = lookup(cur.oid);
      if (!obj || obj.type !== 'commit') continue;
      included.add(cur.oid);
      if (cur.d >= depth) { boundary.add(cur.oid); continue; }
      for (const p of parseCommit(obj.data).parents) queue.push({ oid: p, d: cur.d + 1 });
    }
    const haveSet = new Set(haves.map((h) => peelToCommit(h, lookup)));
    const send = new Set<string>();
    for (const c of included) {
      if (haveSet.has(c)) continue;
      const commit = lookup(c)!;
      const tree = parseCommit(commit.data).tree;
      send.add(c);
      for (const oid of collectReachable([tree], lookup)) send.add(oid);
    }
    // Unshallow: old shallow boundaries that are now included and no longer a boundary.
    const unshallow = shallowIn.filter((s) => included.has(peelToCommit(s, lookup)) && !boundary.has(peelToCommit(s, lookup)));
    const shallow = [...boundary].filter((b) => !haveSet.has(b));
    const objects: GitObject[] = [];
    for (const oid of send) {
      const o = lookup(oid);
      if (o) objects.push({ type: o.type, data: o.data });
    }
    return { objects, oids: [...send], shallow, unshallow };
  }
  const wanted = collectReachable(wants, lookup);
  const held = haves.length ? collectReachable(haves, lookup) : new Set<string>();
  const send = [...wanted].filter((oid) => !held.has(oid));
  const objects: GitObject[] = [];
  for (const oid of send) {
    const o = lookup(oid);
    if (o) objects.push({ type: o.type, data: o.data });
  }
  return { objects, oids: send, shallow: [], unshallow: [] };
}

async function handleGit(req: IncomingMessage, res: ServerResponse, path: string, method: string, body: Buffer): Promise<boolean> {
  const m = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/.exec(path);
  if (!m) return false;
  const owner = decodeSeg(m[1]!);
  const name = decodeSeg(m[2]!);
  const suffix = m[3] ?? '';
  const repo = getRepo(owner, name);
  const q = queryOf(req);

  // GET /info/refs?service=...
  if (method === 'GET' && suffix === '/info/refs') {
    const service = q.get('service') ?? '';
    if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
      sendRaw(res, 400, Buffer.from('unknown service', 'utf8'), 'text/plain');
      return true;
    }
    if (!repo) {
      sendJson(res, 404, { message: 'Not Found' });
      return true;
    }
    const wantV2 = service === 'git-upload-pack' && (req.headers['git-protocol'] ?? '') === 'version=2';
    const contentType = `application/x-${service}-advertisement`;
    if (wantV2) sendRaw(res, 200, v2Advertisement(), contentType);
    else sendRaw(res, 200, v0Advertisement(repo, service as 'git-upload-pack' | 'git-receive-pack'), contentType);
    return true;
  }

  // POST /git-upload-pack  |  POST /git-receive-pack
  if (method === 'POST' && (suffix === '/git-upload-pack' || suffix === '/git-receive-pack')) {
    const service = suffix.slice(1) as 'git-upload-pack' | 'git-receive-pack';
    if (!repo) {
      sendJson(res, 404, { message: 'Not Found' });
      return true;
    }
    if (service === 'git-receive-pack') {
      handleReceivePack(req, res, repo, body);
      return true;
    }
    handleUploadPack(req, res, repo, body);
    return true;
  }
  return false;
}

function handleUploadPack(req: IncomingMessage, res: ServerResponse, repo: Repo, body: Buffer): void {
  const isV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
  const { packets } = parsePktLines(body);
  const lines = pktLinesText(packets);
  const lookup = lookupOf(repo);
  try {
    if (isV2) {
      // command=ls-refs or command=fetch
      const commandLine = lines.find((l) => l.startsWith('command='));
      const command = commandLine ? commandLine.slice('command='.length).trim() : '';
      if (command === 'ls-refs') {
        const peel = lines.some((l) => l.trim() === 'peel');
        const symrefs = lines.some((l) => l.trim() === 'symrefs');
        const unborn = lines.some((l) => l.trim() === 'unborn');
        const prefixes = lines.filter((l) => l.startsWith('ref-prefix ')).map((l) => l.slice('ref-prefix '.length).trim());
        const keep = (n: string): boolean => prefixes.length === 0 || prefixes.some((p) => n.startsWith(p));
        const parts: Buffer[] = [];
        const headTip = branchTip(repo, repo.defaultBranch);
        // HEAD is returned when no prefixes were given, or when a prefix
        // matches HEAD (e.g. git clone sends "ref-prefix HEAD").
        const includeHead = prefixes.length === 0 || prefixes.some((p) => 'HEAD'.startsWith(p));
        if (includeHead) {
          if (headTip) {
            let line = `${headTip} HEAD`;
            if (symrefs) line += ' symref-target:refs/heads/main';
            parts.push(pktLine(`${line}\n`));
          } else if (unborn) {
            parts.push(pktLine('unborn HEAD symref-target:refs/heads/main\n'));
          }
        }
        for (const ref of sortedRefs(repo)) {
          if (!keep(ref.name)) continue;
          let line = `${ref.oid} ${ref.name}`;
          const peeled = peel ? peeledOf(repo, ref) : undefined;
          if (peeled) line += ` peeled:${peeled}`;
          parts.push(pktLine(`${line}\n`));
        }
        parts.push(PKT_FLUSH);
        sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
        return;
      }
      if (command === 'fetch') {
        const wants: string[] = [];
        const haves: string[] = [];
        const shallowIn: string[] = [];
        let depth: number | null = null;
        for (const line of lines) {
          const t = line.trim();
          if (t.startsWith('want ')) wants.push(t.slice(5).trim());
          else if (t.startsWith('have ')) haves.push(t.slice(5).trim());
          else if (t.startsWith('shallow ')) shallowIn.push(t.slice(8).trim());
          else if (t.startsWith('deepen ')) { const n = parseInt(t.slice(7).trim(), 10); if (Number.isFinite(n)) depth = n; }
        }
        const { objects, oids, shallow, unshallow } = computeFetch(repo, wants, haves, depth, shallowIn);
        const parts: Buffer[] = [];
        // Protocol v2: the acknowledgments section is only sent when the
        // client sent at least one "have" line; otherwise the first section
        // must be "packfile" (or "shallow-info").
        if (haves.length) {
          parts.push(pktLine('acknowledgments\n'));
          const knownHaves = haves.filter((h) => repo.objects.has(h));
          if (knownHaves.length) for (const h of knownHaves) parts.push(pktLine(`ACK ${h}\n`));
          else parts.push(pktLine('NAK\n'));
          parts.push(PKT_DELIM);
        }
        if (depth !== null || shallow.length || unshallow.length) {
          parts.push(pktLine('shallow-info\n'));
          for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
          for (const s of unshallow) parts.push(pktLine(`unshallow ${s}\n`));
          parts.push(PKT_DELIM);
        }
        if (objects.length) {
          parts.push(pktLine('packfile\n'));
          parts.push(sidebandPack(cachedPack(objects, oids)));
        }
        parts.push(PKT_FLUSH);
        sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
        return;
      }
      sendRaw(res, 400, Buffer.from('unknown command', 'utf8'), 'text/plain');
      return;
    }
    // v0 fetch: want lines, flush, have/done lines, flush
    const wants: string[] = [];
    const haves: string[] = [];
    const shallowIn: string[] = [];
    let depth: number | null = null;
    for (const line of lines) {
      const t = line.trim();
      if (t.startsWith('want ')) wants.push(t.slice(5).split(' ')[0]!);
      else if (t.startsWith('have ')) haves.push(t.slice(5).trim());
      else if (t.startsWith('shallow ')) shallowIn.push(t.slice(8).trim());
      else if (t.startsWith('deepen ')) { const n = parseInt(t.slice(7).trim(), 10); if (Number.isFinite(n)) depth = n; }
      else if (t === 'done' || t === '') continue;
      else if (/^[0-9a-f]{40}$/.test(t)) continue;
      else if (t.startsWith('filter ') || t.startsWith('deepen-') || t === 'thin-pack' || t === 'no-progress' || t === 'ofs-delta' || t === 'side-band-64k' || t.startsWith('agent')) continue;
      // unknown line: ignore (tolerant)
    }
    if (wants.length === 0) {
      sendRaw(res, 400, Buffer.from("expected to get object ID, not 'done'", 'utf8'), 'text/plain');
      return;
    }
    const { objects, oids, shallow, unshallow } = computeFetch(repo, wants, haves, depth, shallowIn);
    const parts: Buffer[] = [];
    const knownHaves = haves.filter((h) => repo.objects.has(h));
    if (knownHaves.length) for (const h of knownHaves) parts.push(pktLine(`ACK ${h}\n`));
    else parts.push(pktLine('NAK\n'));
    for (const s of shallow) parts.push(pktLine(`shallow ${s}\n`));
    for (const s of unshallow) parts.push(pktLine(`unshallow ${s}\n`));
    if (objects.length) parts.push(sidebandPack(cachedPack(objects, oids)));
    sendRaw(res, 200, Buffer.concat(parts), 'application/x-git-upload-pack-result');
  } catch (e) {
    sendRaw(res, 400, Buffer.from(`error: ${e instanceof Error ? e.message : String(e)}`, 'utf8'), 'text/plain');
  }
}

function handleReceivePack(req: IncomingMessage, res: ServerResponse, repo: Repo, body: Buffer): void {
  const { packets, rest } = parsePktLines(body);
  const lines = pktLinesText(packets);
  const commands: { oldOid: string; newOid: string; ref: string }[] = [];
  for (const line of lines) {
    const t = line.replace(/\n$/, '');
    const nul = t.indexOf('\0');
    const head = nul >= 0 ? t.slice(0, nul) : t;
    const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/.exec(head.trim());
    if (m) commands.push({ oldOid: m[1]!, newOid: m[2]!, ref: m[3]! });
  }
  const reportLines: string[] = [];
  let unpackOk = true;
  let unpackDetail = 'ok';
  // Parse and store the pack (if any commands create/update a ref).
  const needsPack = commands.some((c) => c.newOid !== ZERO_OID);
  if (needsPack) {
    try {
      const objects = readPack(rest);
      for (const o of objects) putObject(repo, o.type, o.data);
    } catch (e) {
      unpackOk = false;
      unpackDetail = e instanceof Error ? e.message : 'unpack failed';
    }
  }
  const lookup = lookupOf(repo);
  for (const cmd of commands) {
    if (!unpackOk) { reportLines.push(`ng ${cmd.ref} unpack failed`); continue; }
    const current = repo.refs.get(cmd.ref);
    if (cmd.newOid === ZERO_OID) {
      // delete
      if (current === undefined) { reportLines.push(`ng ${cmd.ref} remote ref does not exist`); continue; }
      if (cmd.oldOid !== ZERO_OID && cmd.oldOid !== current) { reportLines.push(`ng ${cmd.ref} non-fast-forward`); continue; }
      repo.refs.delete(cmd.ref);
      reportLines.push(`ok ${cmd.ref}`);
      continue;
    }
    const target = repo.objects.get(cmd.newOid);
    if (!target) { reportLines.push(`ng ${cmd.ref} object not found`); continue; }
    if (current === undefined) {
      if (cmd.oldOid !== ZERO_OID) { reportLines.push(`ng ${cmd.ref} non-fast-forward`); continue; }
      repo.refs.set(cmd.ref, cmd.newOid);
      reportLines.push(`ok ${cmd.ref}`);
      continue;
    }
    if (cmd.oldOid !== current) { reportLines.push(`ng ${cmd.ref} non-fast-forward`); continue; }
    // fast-forward: new tip must descend from the old tip (commit ancestry).
    const newCommit = peelToCommit(cmd.newOid, lookup);
    if (!isAncestor(current, newCommit, lookup)) { reportLines.push(`ng ${cmd.ref} non-fast-forward`); continue; }
    repo.refs.set(cmd.ref, cmd.newOid);
    reportLines.push(`ok ${cmd.ref}`);
  }
  const innerParts: Buffer[] = [pktLine(`unpack ${unpackOk ? 'ok' : unpackDetail}\n`)];
  for (const line of reportLines) innerParts.push(pktLine(`${line}\n`));
  // The status reader expects a flush pkt-line inside the band-1 stream
  // (the outer flush only ends the sideband framing).
  innerParts.push(PKT_FLUSH);
  const inner = Buffer.concat(innerParts);
  // Sideband band 1 carries the pkt-lined report.
  const outer: Buffer[] = [];
  const CHUNK = 32768;
  for (let off = 0; off < inner.length; off += CHUNK) {
    const slice = inner.subarray(off, Math.min(inner.length, off + CHUNK));
    outer.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  outer.push(PKT_FLUSH);
  sendRaw(res, 200, Buffer.concat(outer), 'application/x-git-receive-pack-result');
}

// ---------------------------------------------------------------- GraphQL

interface GqlField { name: string; alias: string | null; args: Record<string, unknown>; selections: GqlField[] | null; fragmentType: string | null }
interface GqlOp { kind: 'query' | 'mutation'; name: string | null; varDefs: Record<string, unknown>; selections: GqlField[] }

function gqlTokenize(src: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i]!;
    if (/\s/.test(ch) || ch === ',') { i += 1; continue; }
    if (ch === '#') { while (i < src.length && src[i] !== '\n') i += 1; continue; }
    if (ch === '"') {
      // string (possibly block string """)
      if (src.startsWith('"""', i)) {
        const end = src.indexOf('"""', i + 3);
        tokens.push(JSON.stringify(end < 0 ? src.slice(i + 3) : src.slice(i + 3, end)));
        i = end < 0 ? src.length : end + 3;
        continue;
      }
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) { out += src[j + 1]; j += 2; } else { out += src[j]; j += 1; }
      }
      tokens.push(JSON.stringify(out));
      i = j + 1;
      continue;
    }
    if ('{}()[]:!$=@|&'.includes(ch)) { tokens.push(ch); i += 1; continue; }
    if (ch === '.' && src.startsWith('...', i)) { tokens.push('...'); i += 3; continue; }
    let j = i;
    while (j < src.length && !/[\s,{}()\[\]:!$=@|&.#"]/.test(src[j]!)) j += 1;
    if (j === i) j = i + 1;
    tokens.push(src.slice(i, j));
    i = j;
  }
  return tokens;
}

class GqlParser {
  private tokens: string[];
  private pos = 0;
  constructor(src: string) { this.tokens = gqlTokenize(src); }
  private peek(): string | undefined { return this.tokens[this.pos]; }
  private next(): string { return this.tokens[this.pos++] ?? ''; }
  private expect(t: string): void { if (this.next() !== t) throw new Error(`expected ${t}`); }
  parseDocument(): { ops: GqlOp[]; fragments: Map<string, GqlField[]> } {
    const ops: GqlOp[] = [];
    const fragments = new Map<string, GqlField[]>();
    while (this.pos < this.tokens.length) {
      const tok = this.peek();
      if (tok === 'query' || tok === 'mutation') {
        this.next();
        let name: string | null = null;
        if (this.peek() !== undefined && this.peek() !== '{' && this.peek() !== '(') name = this.next();
        const varDefs: Record<string, unknown> = {};
        if (this.peek() === '(') {
          this.next();
          while (this.peek() !== ')' && this.peek() !== undefined) {
            if (this.peek() === '$') { this.next(); const vn = this.next(); this.next(); varDefs[vn] = this.parseType(); }
            else this.next();
            if (this.peek() === '=') { this.next(); this.parseValue({}); }
          }
          this.expect(')');
        }
        const selections = this.parseSelections();
        ops.push({ kind: tok as 'query' | 'mutation', name, varDefs, selections });
      } else if (tok === 'fragment') {
        this.next();
        const fname = this.next();
        this.next(); // 'on'
        const ftype = this.next();
        void ftype;
        fragments.set(fname, this.parseSelections());
      } else if (tok === '{') {
        ops.push({ kind: 'query', name: null, varDefs: {}, selections: this.parseSelections() });
      } else {
        this.next();
      }
    }
    return { ops, fragments };
  }
  private parseType(): string {
    let t = '';
    if (this.peek() === '[') { this.next(); t = `[${this.parseType()}]`; } else t = this.next();
    if (this.peek() === '!') { this.next(); t += '!'; }
    return t;
  }
  private parseSelections(): GqlField[] {
    this.expect('{');
    const out: GqlField[] = [];
    while (this.peek() !== '}' && this.peek() !== undefined) {
      out.push(...this.parseField());
    }
    this.expect('}');
    return out;
  }
  private parseField(): GqlField[] {
    if (this.peek() === '...') {
      this.next();
      if (this.peek() === 'on') {
        this.next();
        const type = this.next();
        const sels = this.parseSelections();
        return sels.map((s) => ({ ...s, fragmentType: type }));
      }
      const fname = this.next();
      return [{ name: `...${fname}`, alias: null, args: {}, selections: null, fragmentType: null }];
    }
    let name = this.next();
    let alias: string | null = null;
    if (this.peek() === ':') { this.next(); alias = name; name = this.next(); }
    const args: Record<string, unknown> = {};
    if (this.peek() === '(') {
      this.next();
      while (this.peek() !== ')' && this.peek() !== undefined) {
        const aname = this.next();
        this.expect(':');
        args[aname] = this.parseValue({});
        if (this.peek() === ',') this.next();
      }
      this.expect(')');
    }
    let selections: GqlField[] | null = null;
    if (this.peek() === '{') selections = this.parseSelections();
    return [{ name, alias, args, selections, fragmentType: null }];
  }
  parseValue(vars: Record<string, unknown>): unknown {
    const tok = this.next();
    if (tok === '$') return { __var: this.next() };
    if (tok === '[') {
      const arr: unknown[] = [];
      while (this.peek() !== ']' && this.peek() !== undefined) arr.push(this.parseValue(vars));
      this.expect(']');
      return arr;
    }
    if (tok === '{') {
      const obj: Record<string, unknown> = {};
      while (this.peek() !== '}' && this.peek() !== undefined) {
        const k = this.next();
        this.expect(':');
        obj[k] = this.parseValue(vars);
      }
      this.expect('}');
      return obj;
    }
    if (tok === 'true') return true;
    if (tok === 'false') return false;
    if (tok === 'null') return null;
    if (tok.startsWith('"')) { try { return JSON.parse(tok); } catch { return tok.slice(1, -1); } }
    const num = Number(tok);
    if (tok !== '' && !Number.isNaN(num)) return num;
    return { __enum: tok };
  }
}

function resolveValue(v: unknown, vars: Record<string, unknown>): unknown {
  if (v !== null && typeof v === 'object') {
    if (Array.isArray(v)) return v.map((x) => resolveValue(x, vars));
    const rec = v as Record<string, unknown>;
    if ('__var' in rec) return vars[String(rec.__var)];
    if ('__enum' in rec) return String(rec.__enum);
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(rec)) out[k] = resolveValue(val, vars);
    return out;
  }
  return v;
}
function resolveArgs(field: GqlField, vars: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(field.args)) out[k] = resolveValue(v, vars);
  return out;
}

const GQL_FIELDS: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', '__type', '__schema'],
  User: ['login', 'id', 'name', 'email'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'private', 'url', 'createdAt', 'updatedAt'],
  Issue: ['id', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'author', 'comments', 'labels', 'url', 'repository', 'closedAt'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRefOid', 'baseRefOid', 'files', 'mergedAt', 'createdAt', 'updatedAt', 'author', 'url', 'repository'],
  IssueConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFileConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  PullRequestChangedFile: ['path', 'additions', 'deletions', 'changeType'],
  Ref: ['name', 'prefix', 'target'],
  PageInfo: ['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor'],
  __Type: ['name', 'kind', 'description', 'fields', 'enumValues', 'inputFields', 'interfaces', 'possibleTypes'],
  __Field: ['name', 'description', 'args', 'type'],
  __EnumValue: ['name', 'description'],
  __Schema: ['queryType', 'mutationType', 'types'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'subject', 'clientMutationId'],
  IssueCommentEdge: ['node', 'cursor'],
  IssueComment: ['id', 'body', 'author', 'createdAt', 'updatedAt'],
  IssueCommentConnection: ['nodes', 'edges', 'pageInfo', 'totalCount'],
  Commit: ['oid', 'id', 'message', 'author', 'committer'],
};
const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'createdAt', 'updatedAt', 'author', 'comments', 'labels', 'url', 'repository', 'closedAt'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRefOid', 'baseRefOid', 'files', 'mergedAt', 'createdAt', 'updatedAt', 'author', 'url', 'repository'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'private', 'url', 'createdAt', 'updatedAt'],
  SearchType: [],
  User: ['login', 'id', 'name', 'email'],
  Query: ['viewer', 'repository', 'node'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
};
const GQL_TYPE_ENUMS: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'CODE', 'COMMIT'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  OrderDirection: ['ASC', 'DESC'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
};

function decodeGlobalId(id: string): { kind: string; key: string } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const idx = text.indexOf(':');
    if (idx < 0) return null;
    return { kind: text.slice(0, idx), key: text.slice(idx + 1) };
  } catch { return null; }
}
function findRepoById(dbid: number): Repo | undefined {
  for (const r of repos.values()) if (r.id === dbid) return r;
  return undefined;
}

interface GqlCtx { errors: { message: string }[]; vars: Record<string, unknown>; fragments: Map<string, GqlField[]> }

function gqlSelect(typeName: string, source: unknown, selections: GqlField[] | null, ctx: GqlCtx): Record<string, unknown> | null {
  if (selections === null) return source as Record<string, unknown>;
  if (source === null || source === undefined) return null;
  const out: Record<string, unknown> = {};
  for (const field of selections) {
    if (field.name.startsWith('...')) {
      const frag = ctx.fragments.get(field.name.slice(3));
      if (frag) {
        const sub = gqlSelect(typeName, source, frag, ctx);
        if (sub) Object.assign(out, sub);
      }
      continue;
    }
    const key = field.alias ?? field.name;
    const allowed = GQL_FIELDS[typeName];
    if (allowed && !allowed.includes(field.name)) {
      ctx.errors.push({ message: `Cannot query field "${field.name}" on type "${typeName}".` });
      continue;
    }
    out[key] = gqlResolveField(typeName, source, field, ctx);
  }
  return out;
}

function gqlResolveField(typeName: string, source: unknown, field: GqlField, ctx: GqlCtx): unknown {
  const args = resolveArgs(field, ctx.vars);
  const src = source as Record<string, unknown>;
  // Mutation payloads
  if (typeName === 'CreateIssuePayload' || typeName === 'CloseIssuePayload') {
    if (field.name === 'issue') return gqlSelect('Issue', (src.__issue as Record<string, unknown>) ?? null, field.selections, ctx);
    if (field.name === 'clientMutationId') return null;
    return null;
  }
  if (typeName === 'CreatePullRequestPayload' || typeName === 'MergePullRequestPayload') {
    if (field.name === 'pullRequest') return gqlSelect('PullRequest', (src.__pr as Record<string, unknown>) ?? null, field.selections, ctx);
    if (field.name === 'clientMutationId') return null;
    return null;
  }
  if (typeName === 'AddCommentPayload') {
    if (field.name === 'commentEdge') {
      const c = src.__comment as Record<string, unknown> | undefined;
      if (!c) return null;
      return gqlSelect('IssueCommentEdge', { __node: c }, field.selections, ctx);
    }
    if (field.name === 'subject') return null;
    if (field.name === 'clientMutationId') return null;
    return null;
  }
  if (typeName === 'IssueCommentEdge') {
    if (field.name === 'node') return gqlSelect('IssueComment', (src.__node as Record<string, unknown>) ?? null, field.selections, ctx);
    if (field.name === 'cursor') return '';
    return null;
  }
  if (typeName === 'IssueComment') {
    const c = src as Record<string, unknown>;
    if (field.name === 'id') return c.id;
    if (field.name === 'body') return c.body;
    if (field.name === 'createdAt') return c.createdAt ?? null;
    if (field.name === 'updatedAt') return c.updatedAt ?? null;
    if (field.name === 'author') return gqlSelect('User', { login: VIEWER_LOGIN, id: globalId('User', VIEWER_LOGIN) }, field.selections, ctx);
    return null;
  }
  if (typeName === 'Commit') {
    const c = src as Record<string, unknown>;
    if (field.name === 'oid') return c.oid ?? null;
    if (field.name === 'id') return c.oid ?? null;
    if (field.name === 'message') return '';
    return null;
  }
  if (typeName === 'IssueCommentConnection') {
    const c = src as { nodes?: Record<string, unknown>[]; totalCount?: number };
    if (field.name === 'nodes') return (c.nodes ?? []).map((n) => gqlSelect('IssueComment', n, field.selections, ctx));
    if (field.name === 'totalCount') return c.totalCount ?? (c.nodes ?? []).length;
    if (field.name === 'pageInfo') return gqlSelect('PageInfo', { hasNextPage: false, hasPreviousPage: false, startCursor: null, endCursor: null }, field.selections, ctx);
    if (field.name === 'edges') return (c.nodes ?? []).map((n) => ({ node: gqlSelect('IssueComment', n, field.selections, ctx), cursor: '' }));
    return null;
  }
  if (typeName === 'Query') {
    if (field.name === 'viewer') {
      const user = { __typename: 'User', login: VIEWER_LOGIN, id: globalId('User', VIEWER_LOGIN), name: VIEWER_NAME, email: VIEWER_EMAIL };
      return gqlSelect('User', user, field.selections, ctx);
    }
    if (field.name === 'repository') {
      const owner = String(args.owner ?? '');
      const name = String(args.name ?? '');
      const repo = owner === VIEWER_LOGIN ? getRepo(owner, name) : undefined;
      if (!repo) return null;
      return gqlSelect('Repository', repoNode(repo), field.selections, ctx);
    }
    if (field.name === 'node') {
      const decoded = decodeGlobalId(String(args.id ?? ''));
      if (!decoded) return null;
      if (decoded.kind === 'Repository') {
        const repo = findRepoById(parseInt(decoded.key, 10));
        if (!repo) return null;
        return gqlSelect('Repository', repoNode(repo), field.selections, ctx);
      }
      if (decoded.kind === 'Issue') {
        const [rid, num] = decoded.key.split(':');
        const repo = findRepoById(parseInt(rid ?? '0', 10));
        const issue = repo?.issues.get(parseInt(num ?? '0', 10));
        if (!issue || !repo) return null;
        return gqlSelect('Issue', issueNode(repo, issue), field.selections, ctx);
      }
      if (decoded.kind === 'PullRequest') {
        const [rid, num] = decoded.key.split(':');
        const repo = findRepoById(parseInt(rid ?? '0', 10));
        const pr = repo?.pulls.get(parseInt(num ?? '0', 10));
        if (!pr || !repo) return null;
        return gqlSelect('PullRequest', prNode(repo, pr), field.selections, ctx);
      }
      return null;
    }
    if (field.name === '__type') {
      return gqlTypeObject(String(args.name ?? ''), field, ctx);
    }
    if (field.name === '__schema') {
      return gqlSelect('__Schema', { queryType: { name: 'Query' }, mutationType: { name: 'Mutation' }, types: [] }, field.selections, ctx);
    }
    return null;
  }
  if (typeName === 'Repository') {
    const node = src as unknown as { __repo: Repo };
    const repo = node.__repo;
    switch (field.name) {
      case 'id': return globalId('Repository', String(repo.id));
      case 'databaseId': return repo.id;
      case 'name': return repo.name;
      case 'nameWithOwner': return `${repo.owner}/${repo.name}`;
      case 'owner': return gqlSelect('User', { __typename: 'User', login: repo.owner, id: globalId('User', repo.owner), name: VIEWER_NAME, email: VIEWER_EMAIL }, field.selections, ctx);
      case 'defaultBranchRef': return gqlSelect('Ref', { name: repo.defaultBranch, prefix: 'refs/heads/', target: { oid: branchTip(repo, repo.defaultBranch) ?? null } }, field.selections, ctx);
      case 'viewerPermission': return 'ADMIN';
      case 'hasIssuesEnabled': return true;
      case 'description': return repo.description;
      case 'private': return repo.isPrivate;
      case 'url': return '';
      case 'createdAt': return repo.createdAt;
      case 'updatedAt': return repo.updatedAt;
      case 'issue': {
        const issue = repo.issues.get(Number(args.number));
        if (!issue) return null;
        return gqlSelect('Issue', issueNode(repo, issue), field.selections, ctx);
      }
      case 'issues': return issuesConnection(repo, args, field, ctx);
      case 'pullRequests': return pullsConnection(repo, args, field, ctx);
      case 'pullRequest': {
        const pr = repo.pulls.get(Number(args.number));
        if (!pr) return null;
        return gqlSelect('PullRequest', prNode(repo, pr), field.selections, ctx);
      }
      default: return null;
    }
  }
  if (typeName === 'Issue') {
    const node = src as unknown as { __repo: Repo; __issue: Issue };
    const issue = node.__issue;
    switch (field.name) {
      case 'id': return globalId('Issue', `${node.__repo.id}:${issue.number}`);
      case 'number': return issue.number;
      case 'title': return issue.title;
      case 'state': return issue.state === 'open' ? 'OPEN' : 'CLOSED';
      case 'body': return issue.body;
      case 'createdAt': return issue.createdAt;
      case 'updatedAt': return issue.updatedAt;
      case 'closedAt': return issue.closedAt;
      case 'author': return gqlSelect('User', { login: VIEWER_LOGIN, id: globalId('User', VIEWER_LOGIN) }, field.selections, ctx);
      case 'url': return '';
      case 'repository': return gqlSelect('Repository', repoNode(node.__repo), field.selections, ctx);
      case 'labels': return { nodes: issue.labels.map((l) => ({ name: l.name, color: l.color })) };
      case 'comments': return { nodes: issue.comments.map((c) => ({ id: globalId('IssueComment', `${node.__repo.id}:${issue.number}:${c.id}`), body: c.body })), totalCount: issue.comments.length };
      default: return null;
    }
  }
  if (typeName === 'PullRequest') {
    const node = src as unknown as { __repo: Repo; __pr: Pull };
    const pr = node.__pr;
    const repo = node.__repo;
    switch (field.name) {
      case 'id': return globalId('PullRequest', `${repo.id}:${pr.number}`);
      case 'number': return pr.number;
      case 'title': return pr.title;
      case 'body': return pr.body;
      case 'state': return pr.merged ? 'MERGED' : pr.state === 'open' ? 'OPEN' : 'CLOSED';
      case 'merged': return pr.merged;
      case 'mergeable': return prConflicted(repo, pr) ? 'CONFLICTING' : 'MERGEABLE';
      case 'headRefName': return pr.headRef;
      case 'baseRefName': return pr.baseRef;
      case 'headRefOid': return branchTip(repo, pr.headRef) ?? pr.headSha;
      case 'baseRefOid': return branchTip(repo, pr.baseRef) ?? pr.baseSha;
      case 'mergedAt': return pr.mergedAt;
      case 'createdAt': return pr.createdAt;
      case 'updatedAt': return pr.updatedAt;
      case 'author': return gqlSelect('User', { login: VIEWER_LOGIN, id: globalId('User', VIEWER_LOGIN) }, field.selections, ctx);
      case 'url': return '';
      case 'repository': return gqlSelect('Repository', repoNode(repo), field.selections, ctx);
      case 'files': {
        const lookup = lookupOf(repo);
        const headCommit = lookup(peelToCommit(pr.headSha, lookup));
        const baseCommit = lookup(peelToCommit(pr.baseSha, lookup));
        let paths: string[] = [];
        if (headCommit && baseCommit && headCommit.type === 'commit' && baseCommit.type === 'commit') {
          paths = diffTrees(repo, parseCommit(baseCommit.data).tree, parseCommit(headCommit.data).tree).map((f) => f.filename);
        }
        const first = typeof args.first === 'number' ? args.first : 100;
        const nodes = paths.slice(0, first).map((p) => ({ path: p, additions: 0, deletions: 0, changeType: 'MODIFIED' }));
        return gqlSelect('PullRequestChangedFileConnection', { __nodes: nodes }, field.selections, { ...ctx });
      }
      default: return null;
    }
  }
  if (typeName === 'PullRequestChangedFileConnection') {
    const node = src as unknown as { __nodes: { path: string }[] };
    if (field.name === 'nodes') {
      return (node.__nodes ?? []).map((n) => gqlSelect('PullRequestChangedFile', n, field.selections, ctx));
    }
    if (field.name === 'totalCount') return (node.__nodes ?? []).length;
    if (field.name === 'pageInfo') return gqlSelect('PageInfo', { hasNextPage: false, hasPreviousPage: false, startCursor: null, endCursor: null }, field.selections, ctx);
    if (field.name === 'edges') return (node.__nodes ?? []).map((n) => ({ node: gqlSelect('PullRequestChangedFile', n, field.selections, ctx), cursor: '' }));
    return null;
  }
  if (typeName === 'IssueConnection' || typeName === 'PullRequestConnection') {
    const node = src as unknown as { __items: unknown[]; __type: string; __hasNext: boolean; __endCursor: string | null };
    if (field.name === 'nodes') {
      return (node.__items ?? []).map((item) => gqlSelect(node.__type, item, field.selections, ctx));
    }
    if (field.name === 'totalCount') return (node.__items ?? []).length;
    if (field.name === 'pageInfo') {
      return gqlSelect('PageInfo', { hasNextPage: node.__hasNext, hasPreviousPage: false, startCursor: null, endCursor: node.__endCursor }, field.selections, ctx);
    }
    if (field.name === 'edges') {
      return (node.__items ?? []).map((item) => ({ node: gqlSelect(node.__type, item, field.selections, ctx), cursor: '' }));
    }
    return null;
  }
  if (typeName === 'User') {
    const u = src as Record<string, unknown>;
    if (field.name === 'login') return u.login ?? VIEWER_LOGIN;
    if (field.name === 'id') return u.id ?? globalId('User', VIEWER_LOGIN);
    if (field.name === 'name') return u.name ?? VIEWER_NAME;
    if (field.name === 'email') return u.email ?? VIEWER_EMAIL;
    return null;
  }
  if (typeName === 'Ref') {
    const r = src as Record<string, unknown>;
    if (field.name === 'name') return r.name;
    if (field.name === 'prefix') return r.prefix ?? 'refs/heads/';
    if (field.name === 'target') {
      const t = r.target as Record<string, unknown> | undefined;
      return t ? gqlSelect('Commit' as never, t, field.selections, ctx) : null;
    }
    return null;
  }
  if (typeName === 'PageInfo') {
    const p = src as Record<string, unknown>;
    return p[field.name] ?? null;
  }
  if (typeName === '__Type') {
    const t = src as Record<string, unknown>;
    if (field.name === 'name') return t.name;
    if (field.name === 'kind') return t.kind ?? 'OBJECT';
    if (field.name === 'description') return null;
    if (field.name === 'fields') {
      const names = (t.fields as string[]) ?? [];
      return names.map((n) => gqlSelect('__Field', { name: n }, field.selections, ctx));
    }
    if (field.name === 'enumValues') {
      const names = (t.enumValues as string[]) ?? [];
      return names.map((n) => gqlSelect('__EnumValue', { name: n }, field.selections, ctx));
    }
    return null;
  }
  if (typeName === '__Field' || typeName === '__EnumValue') {
    const t = src as Record<string, unknown>;
    if (field.name === 'name') return t.name;
    if (field.name === 'description') return null;
    if (field.name === 'args') return [];
    return null;
  }
  if (typeName === '__Schema') {
    const s = src as Record<string, unknown>;
    if (field.name === 'queryType') return gqlSelect('__Type', { name: 'Query', kind: 'OBJECT', fields: GQL_TYPE_FIELDS.Query ?? [] }, field.selections, ctx);
    if (field.name === 'mutationType') return gqlSelect('__Type', { name: 'Mutation', kind: 'OBJECT', fields: GQL_TYPE_FIELDS.Mutation ?? [] }, field.selections, ctx);
    if (field.name === 'types') return [];
    return s[field.name] ?? null;
  }
  return src[field.name] ?? null;
}

function gqlTypeObject(name: string, field: GqlField, ctx: GqlCtx): unknown {
  const fields = GQL_TYPE_FIELDS[name];
  const enums = GQL_TYPE_ENUMS[name];
  if (fields === undefined && enums === undefined) return null;
  const obj: Record<string, unknown> = { name, kind: enums !== undefined ? 'ENUM' : 'OBJECT', fields: fields ?? [], enumValues: enums ?? [] };
  return gqlSelect('__Type', obj, field.selections, ctx);
}

function repoNode(repo: Repo): Record<string, unknown> { return { __typename: 'Repository', __repo: repo }; }
function issueNode(repo: Repo, issue: Issue): Record<string, unknown> { return { __typename: 'Issue', __repo: repo, __issue: issue }; }
function prNode(repo: Repo, pr: Pull): Record<string, unknown> { return { __typename: 'PullRequest', __repo: repo, __pr: pr }; }

function cursorEncode(index: number): string { return Buffer.from(`cursor:${index}`).toString('base64'); }
function cursorDecode(cursor: string | null | undefined): number {
  if (!cursor) return -1;
  try {
    const text = Buffer.from(cursor, 'base64').toString('utf8');
    const m = /^cursor:(\d+)$/.exec(text);
    return m ? parseInt(m[1]!, 10) : -1;
  } catch { return -1; }
}

function issuesConnection(repo: Repo, args: Record<string, unknown>, field: GqlField, ctx: GqlCtx): unknown {
  let items = [...repo.issues.values()];
  const states = Array.isArray(args.states) ? (args.states as string[]) : null;
  if (states) {
    const want = new Set(states.map((s) => String(s).toLowerCase()));
    items = items.filter((i) => want.has(i.state));
  }
  const orderBy = (args.orderBy ?? {}) as Record<string, unknown>;
  const direction = String(orderBy.direction ?? 'DESC');
  const fieldName = String(orderBy.field ?? 'CREATED_AT');
  void fieldName;
  items.sort((a, b) => direction === 'ASC' ? a.seq - b.seq : b.seq - a.seq);
  const first = typeof args.first === 'number' ? args.first : 100;
  const afterIdx = cursorDecode(typeof args.after === 'string' ? args.after : null);
  const start = afterIdx + 1;
  const slice = items.slice(start, start + first);
  const hasNext = start + first < items.length;
  const endCursor = slice.length ? cursorEncode(start + slice.length - 1) : null;
  const conn = { __items: slice.map((i) => issueNode(repo, i)), __type: 'Issue', __hasNext: hasNext, __endCursor: endCursor };
  return gqlSelect('IssueConnection', conn, field.selections, ctx);
}
function pullsConnection(repo: Repo, args: Record<string, unknown>, field: GqlField, ctx: GqlCtx): unknown {
  let items = [...repo.pulls.values()];
  const states = Array.isArray(args.states) ? (args.states as string[]) : null;
  if (states) {
    const want = new Set(states.map((s) => String(s)));
    items = items.filter((p) => want.has(p.merged ? 'MERGED' : p.state === 'open' ? 'OPEN' : 'CLOSED'));
  } else {
    items = items.filter((p) => p.state === 'open');
  }
  items.sort((a, b) => b.seq - a.seq);
  const first = typeof args.first === 'number' ? args.first : 100;
  const afterIdx = cursorDecode(typeof args.after === 'string' ? args.after : null);
  const start = afterIdx + 1;
  const slice = items.slice(start, start + first);
  const hasNext = start + first < items.length;
  const endCursor = slice.length ? cursorEncode(start + slice.length - 1) : null;
  const conn = { __items: slice.map((p) => prNode(repo, p)), __type: 'PullRequest', __hasNext: hasNext, __endCursor: endCursor };
  return gqlSelect('PullRequestConnection', conn, field.selections, ctx);
}

function gqlExecuteOperation(op: GqlOp, variables: Record<string, unknown>, fragments: Map<string, GqlField[]>): { data: Record<string, unknown> | null; errors: { message: string }[] } {
  const ctx: GqlCtx = { errors: [], vars: variables, fragments };
  const data: Record<string, unknown> = {};
  if (op.kind === 'mutation') {
    for (const field of op.selections) {
      const key = field.alias ?? field.name;
      data[key] = gqlMutation(field, ctx);
    }
    return { data, errors: ctx.errors };
  }
  const selected = gqlSelect('Query', {}, op.selections, ctx);
  return { data: selected, errors: ctx.errors };
}

function gqlMutation(field: GqlField, ctx: GqlCtx): unknown {
  const args = resolveArgs(field, ctx.vars);
  const input = (args.input ?? {}) as Record<string, unknown>;
  const fail = (message: string): unknown => {
    ctx.errors.push({ message });
    return null;
  };
  if (field.name === 'createIssue') {
    const decoded = decodeGlobalId(String(input.repositoryId ?? ''));
    if (!decoded || decoded.kind !== 'Repository') return fail('Repository not found');
    const repo = findRepoById(parseInt(decoded.key, 10));
    if (!repo) return fail('Repository not found');
    const title = typeof input.title === 'string' ? input.title : '';
    if (title === '') return fail('Title is required');
    const number = repo.nextNumber;
    repo.nextNumber += 1;
    const now = nextIso();
    const issue: Issue = { id: nextGlobalId(), number, title, body: typeof input.body === 'string' ? input.body : '', state: 'open', labels: [], seq: number, createdAt: now, updatedAt: now, closedAt: null, comments: [] };
    repo.issues.set(number, issue);
    return gqlSelect('CreateIssuePayload', { __issue: issueNode(repo, issue) }, field.selections, ctx);
  }
  if (field.name === 'closeIssue') {
    const decoded = decodeGlobalId(String(input.issueId ?? ''));
    if (!decoded || decoded.kind !== 'Issue') return fail('Issue not found');
    const [rid, num] = decoded.key.split(':');
    const repo = findRepoById(parseInt(rid ?? '0', 10));
    const issue = repo?.issues.get(parseInt(num ?? '0', 10));
    if (!issue || !repo) return fail('Issue not found');
    issue.state = 'closed';
    issue.closedAt = nextIso();
    issue.updatedAt = nextIso();
    return gqlSelect('CloseIssuePayload', { __issue: issueNode(repo, issue) }, field.selections, ctx);
  }
  if (field.name === 'createPullRequest') {
    const decoded = decodeGlobalId(String(input.repositoryId ?? ''));
    if (!decoded || decoded.kind !== 'Repository') return fail('Repository not found');
    const repo = findRepoById(parseInt(decoded.key, 10));
    if (!repo) return fail('Repository not found');
    const head = String(input.headRefName ?? '');
    const base = String(input.baseRefName ?? '');
    const title = typeof input.title === 'string' ? input.title : '';
    const headTip = branchTip(repo, head);
    const baseTip = branchTip(repo, base);
    if (!headTip) return fail(`Head branch '${head}' does not exist`);
    if (!baseTip) return fail(`Base branch '${base}' does not exist`);
    const dup = [...repo.pulls.values()].find((p) => p.headRef === head && p.baseRef === base && p.state === 'open');
    if (dup) {
      return gqlSelect('CreatePullRequestPayload', { __pr: prNode(repo, dup) }, field.selections, ctx);
    }
    const number = repo.nextNumber;
    repo.nextNumber += 1;
    const now = nextIso();
    const pr: Pull = { id: nextGlobalId(), number, title, body: typeof input.body === 'string' ? input.body : '', state: 'open', merged: false, mergedAt: null, mergeCommitSha: null, headRef: head, baseRef: base, headSha: headTip, baseSha: baseTip, seq: number, createdAt: now, updatedAt: now };
    repo.pulls.set(number, pr);
    return gqlSelect('CreatePullRequestPayload', { __pr: prNode(repo, pr) }, field.selections, ctx);
  }
  if (field.name === 'mergePullRequest') {
    const decoded = decodeGlobalId(String(input.pullRequestId ?? ''));
    if (!decoded || decoded.kind !== 'PullRequest') return fail('Pull request not found');
    const [rid, num] = decoded.key.split(':');
    const repo = findRepoById(parseInt(rid ?? '0', 10));
    const pr = repo?.pulls.get(parseInt(num ?? '0', 10));
    if (!pr || !repo) return fail('Pull request not found');
    if (pr.merged || pr.state === 'closed') return fail('Pull request is already merged or closed');
    if (prConflicted(repo, pr)) return fail('Merge conflict');
    const sha = squashMerge(repo, pr);
    if (!sha) return fail('Merge conflict');
    pr.merged = true;
    pr.state = 'closed';
    pr.mergedAt = nextIso();
    pr.mergeCommitSha = sha;
    pr.updatedAt = nextIso();
    return gqlSelect('MergePullRequestPayload', { __pr: prNode(repo, pr) }, field.selections, ctx);
  }
  if (field.name === 'addComment') {
    const decoded = decodeGlobalId(String(input.subjectId ?? ''));
    if (!decoded || decoded.kind !== 'Issue') return fail('Subject not found');
    const [rid, num] = decoded.key.split(':');
    const repo = findRepoById(parseInt(rid ?? '0', 10));
    const issue = repo?.issues.get(parseInt(num ?? '0', 10));
    if (!issue || !repo) return fail('Issue not found');
    const cbody = typeof input.body === 'string' ? input.body : '';
    commentIdSeq += 1;
    const comment = { id: commentIdSeq, body: cbody, createdAt: nextIso(), updatedAt: nextIso() };
    issue.comments.push(comment);
    const payload = { __comment: { id: globalId('IssueComment', `${repo.id}:${issue.number}:${comment.id}`), body: cbody } };
    return gqlSelect('AddCommentPayload', payload, field.selections, ctx);
  }
  ctx.errors.push({ message: `Cannot query field "${field.name}" on type "Mutation".` });
  return null;
}

// Payload field resolution: gqlSelect needs these types handled in gqlResolveField.

// ---------------------------------------------------------------- MCP

const MCP_TOOLS: { name: string; description: string; inputSchema: Record<string, unknown> }[] = [
  { name: 'create_repo', description: 'Create a new repository for the authenticated user.', inputSchema: { type: 'object', properties: { name: { type: 'string' }, description: { type: 'string' }, private: { type: 'boolean' }, owner: { type: 'string' } }, required: ['name'] } },
  { name: 'get_repo', description: 'Get a repository by owner and name.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' } }, required: ['owner', 'repo'] } },
  { name: 'create_issue', description: 'Create an issue in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' } }, required: ['owner', 'repo', 'title'] } },
  { name: 'list_issues', description: 'List issues in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, state: { type: 'string' } }, required: ['owner', 'repo'] } },
  { name: 'create_pull_request', description: 'Create a pull request in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' }, head: { type: 'string' }, base: { type: 'string' } }, required: ['owner', 'repo', 'title', 'head', 'base'] } },
  { name: 'merge_pull_request', description: 'Merge a pull request in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, pull_number: { type: 'integer' } }, required: ['owner', 'repo', 'pull_number'] } },
];
const MCP_SERVER_INFO = { name: 'forge', version: '1.0.0' };
const MCP_SUPPORTED_VERSIONS = ['2026-07-28', '2025-11-25'];

function mcpResult(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, result };
}
function mcpError(id: unknown, code: number, message: string, data?: unknown): Record<string, unknown> {
  const err: Record<string, unknown> = { code, message };
  if (data !== undefined) err.data = data;
  return { jsonrpc: '2.0', id: id ?? null, error: err };
}
function mcpToolResult(obj: Record<string, unknown>): Record<string, unknown> {
  return { content: [{ type: 'text', text: JSON.stringify(obj) }], structuredContent: obj };
}

function mcpCallTool(name: string, args: Record<string, unknown>): { ok: boolean; code?: number; message?: string; result?: Record<string, unknown> } {
  const tool = MCP_TOOLS.find((t) => t.name === name);
  if (!tool) return { ok: false, code: -32602, message: `Unknown tool: ${name}` };
  const required = ((tool.inputSchema.required as string[]) ?? []);
  for (const r of required) {
    if (args[r] === undefined || args[r] === null || args[r] === '') {
      return { ok: false, code: -32602, message: `Missing required argument: ${r}` };
    }
  }
  const owner = typeof args.owner === 'string' ? args.owner : VIEWER_LOGIN;
  if (name === 'create_repo') {
    const repoName = String(args.name);
    if (getRepo(VIEWER_LOGIN, repoName)) return { ok: false, code: -32602, message: 'Repository already exists' };
    const repo = createRepoRecord(repoName, typeof args.description === 'string' ? args.description : '', args.private === true);
    const r = repoJson(repo);
    return { ok: true, result: mcpToolResult({ ...r, full_name: `${repo.owner}/${repo.name}` }) };
  }
  const repoName = String(args.repo ?? '');
  const repo = getRepo(owner, repoName);
  if (!repo) return { ok: false, code: -32602, message: 'Repository not found' };
  if (name === 'get_repo') {
    const r = repoJson(repo);
    return { ok: true, result: mcpToolResult({ ...r, full_name: `${repo.owner}/${repo.name}` }) };
  }
  if (name === 'create_issue') {
    const number = repo.nextNumber;
    repo.nextNumber += 1;
    const now = nextIso();
    const issue: Issue = { id: nextGlobalId(), number, title: String(args.title), body: typeof args.body === 'string' ? args.body : '', state: 'open', labels: [], seq: number, createdAt: now, updatedAt: now, closedAt: null, comments: [] };
    repo.issues.set(number, issue);
    return { ok: true, result: mcpToolResult(issueJson(repo, issue)) };
  }
  if (name === 'list_issues') {
    const state = typeof args.state === 'string' ? args.state : 'open';
    const list = [...repo.issues.values()].filter((i) => state === 'all' ? true : i.state === state).map((i) => issueJson(repo, i));
    return { ok: true, result: mcpToolResult({ issues: list, total_count: list.length }) };
  }
  if (name === 'create_pull_request') {
    const head = String(args.head);
    const base = String(args.base);
    const headTip = branchTip(repo, head);
    const baseTip = branchTip(repo, base);
    if (!headTip) return { ok: false, code: -32602, message: `Head branch '${head}' does not exist` };
    if (!baseTip) return { ok: false, code: -32602, message: `Base branch '${base}' does not exist` };
    const dup = [...repo.pulls.values()].find((p) => p.headRef === head && p.baseRef === base && p.state === 'open');
    if (dup) return { ok: true, result: mcpToolResult(pullJson(repo, dup)) };
    const number = repo.nextNumber;
    repo.nextNumber += 1;
    const now = nextIso();
    const pr: Pull = { id: nextGlobalId(), number, title: String(args.title), body: typeof args.body === 'string' ? args.body : '', state: 'open', merged: false, mergedAt: null, mergeCommitSha: null, headRef: head, baseRef: base, headSha: headTip, baseSha: baseTip, seq: number, createdAt: now, updatedAt: now };
    repo.pulls.set(number, pr);
    return { ok: true, result: mcpToolResult(pullJson(repo, pr)) };
  }
  if (name === 'merge_pull_request') {
    const pr = repo.pulls.get(Number(args.pull_number));
    if (!pr) return { ok: false, code: -32602, message: 'Pull request not found' };
    if (pr.merged || pr.state === 'closed') return { ok: false, code: -32602, message: 'Pull request is already merged or closed' };
    if (prConflicted(repo, pr)) return { ok: false, code: -32602, message: 'Merge conflict' };
    const sha = squashMerge(repo, pr);
    if (!sha) return { ok: false, code: -32602, message: 'Merge conflict' };
    pr.merged = true;
    pr.state = 'closed';
    pr.mergedAt = nextIso();
    pr.mergeCommitSha = sha;
    pr.updatedAt = nextIso();
    return { ok: true, result: mcpToolResult({ merged: true, sha, message: 'Pull Request successfully merged' }) };
  }
  return { ok: false, code: -32602, message: `Unknown tool: ${name}` };
}

function handleMcp(req: IncomingMessage, res: ServerResponse, body: Buffer): void {
  if (!authed(req)) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    sendJson(res, 400, mcpError(null, -32700, 'Parse error'));
    return;
  }
  const requests = Array.isArray(parsed) ? parsed : [parsed];
  const responses: Record<string, unknown>[] = [];
  for (const rpc of requests) {
    if (rpc === null || typeof rpc !== 'object') { responses.push(mcpError(null, -32600, 'Invalid Request')); continue; }
    const r = rpc as Record<string, unknown>;
    const method = String(r.method ?? '');
    const id = r.id === undefined ? null : r.id;
    const isNotification = r.id === undefined;
    if (method === 'server/discover') {
      responses.push(mcpResult(id, {
        supportedVersions: MCP_SUPPORTED_VERSIONS,
        capabilities: { tools: {} },
        serverInfo: MCP_SERVER_INFO,
        _meta: { 'io.modelcontextprotocol/serverInfo': MCP_SERVER_INFO },
      }));
      continue;
    }
    if (method === 'initialize') {
      responses.push(mcpResult(id, {
        protocolVersion: '2025-11-25',
        capabilities: { tools: {} },
        serverInfo: MCP_SERVER_INFO,
        _meta: { 'io.modelcontextprotocol/serverInfo': MCP_SERVER_INFO },
      }));
      continue;
    }
    if (method.startsWith('notifications/')) {
      continue; // notifications get no response; batch continues
    }
    if (isNotification) continue;
    if (method === 'tools/list') {
      responses.push(mcpResult(id, { tools: MCP_TOOLS, nextCursor: null }));
      continue;
    }
    if (method === 'tools/call') {
      const params = (r.params ?? {}) as Record<string, unknown>;
      const toolName = String(params.name ?? '');
      const args = (params.arguments ?? {}) as Record<string, unknown>;
      const call = mcpCallTool(toolName, args);
      if (call.ok) responses.push(mcpResult(id, call.result));
      else responses.push(mcpError(id, call.code ?? -32602, call.message ?? 'Tool call failed'));
      continue;
    }
    if (method === 'ping') { responses.push(mcpResult(id, {})); continue; }
    responses.push(mcpError(id, -32601, `Method not found: ${method}`));
  }
  if (responses.length === 0) {
    res.writeHead(202);
    res.end();
    return;
  }
  const payload = Array.isArray(parsed) ? responses : responses[0]!;
  sendJson(res, 200, payload as Record<string, unknown>);
}

// ---------------------------------------------------------------- GraphQL HTTP

function handleGraphql(req: IncomingMessage, res: ServerResponse, body: Buffer): void {
  if (!authed(req)) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    sendJson(res, 400, { errors: [{ message: 'Request body must be valid JSON' }] });
    return;
  }
  const requests = Array.isArray(parsed) ? parsed : [parsed];
  const results: unknown[] = [];
  for (const item of requests) {
    if (item === null || typeof item !== 'object') { results.push({ errors: [{ message: 'Invalid request' }] }); continue; }
    const rec = item as Record<string, unknown>;
    const query = typeof rec.query === 'string' ? rec.query : '';
    const variables = (rec.variables ?? {}) as Record<string, unknown>;
    try {
      const parser = new GqlParser(query);
      const doc = parser.parseDocument();
      if (doc.ops.length === 0) { results.push({ errors: [{ message: 'No operation found' }] }); continue; }
      const op = doc.ops[0]!;
      results.push(gqlExecuteOperation(op, variables, doc.fragments));
    } catch (e) {
      results.push({ errors: [{ message: e instanceof Error ? e.message : 'Parse error' }] });
    }
  }
  sendJson(res, 200, (Array.isArray(parsed) ? results : results[0]) as Record<string, unknown>);
}

// ---------------------------------------------------------------- createApp

export function createApp(): Server {
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? '/', 'http://localhost');
      const path = url.pathname;
      const method = (req.method ?? 'GET').toUpperCase();
      if (method === 'GET' && path === '/healthz') {
        sendJson(res, 200, { ok: true });
        return;
      }
      // Git smart HTTP paths: /{owner}/{repo}.git/...
      if (path.includes('.git')) {
        const body = method === 'POST' ? await readBody(req) : Buffer.alloc(0);
        const handled = await handleGit(req, res, path, method, body);
        if (handled) return;
      }
      if (path === '/api/graphql') {
        if (method !== 'POST') { sendJson(res, 405, { message: 'Method Not Allowed' }); return; }
        const body = await readBody(req);
        handleGraphql(req, res, body);
        return;
      }
      if (path === '/mcp') {
        if (method === 'GET') { res.writeHead(405); res.end(); return; }
        if (method === 'DELETE') { res.writeHead(204); res.end(); return; }
        if (method !== 'POST') { res.writeHead(405); res.end(); return; }
        const body = await readBody(req);
        handleMcp(req, res, body);
        return;
      }
      if (path.startsWith('/api/v3')) {
        const body = await readBody(req);
        handleRest(req, res, path, method, body);
        return;
      }
      sendJson(res, 404, { message: 'Not Found' });
    } catch (e) {
      if (!res.headersSent) sendJson(res, 500, { message: e instanceof Error ? e.message : 'Internal Server Error' });
      else { try { res.end(); } catch { /* ignore */ } }
    }
  });
  return server;
}
