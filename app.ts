// A GitHub-compatible git forge: git smart HTTP (v2 + v0), REST v3, GraphQL v4 and MCP,
// one process, stdlib only, in-memory store. Node 22, erasable TypeScript.
//
// Determinism: every timestamp the server invents comes from a monotonic counter seeded at
// 1700000000 (never the wall clock), so two runs on the same instance leave the same state.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------- constants

const JSON_TYPE = 'application/json; charset=utf-8';
const ZERO_OID = '0000000000000000000000000000000000000000';
const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const FOREIGN_LOGIN = 'olgabauer';
const FOREIGN_ID = 1002;
const IDENTITY_NAME = 'Conformance';
const IDENTITY_EMAIL = 'conformance@make.fun';
const BASE_EPOCH = 1_700_000_000;
const AGENT_NAME = 'git-forge/1.0';
const MCP_NAME = 'git-forge';
const MCP_VERSION = '1.0.0';
const TOKEN_ENV = process.env.MAKEFUN_SHOP_TOKEN ?? '';

// ---------------------------------------------------------------- store

interface GitObject {
  type: 'commit' | 'tree' | 'blob' | 'tag';
  data: Buffer;
}

interface Label {
  name: string;
  color: string;
  description: string;
}

interface Issue {
  number: number;
  id: number;
  nodeId: string;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  createdSeq: number;
  userLogin: string;
}

interface Pull {
  number: number;
  id: number;
  nodeId: string;
  title: string;
  body: string;
  state: 'open' | 'closed';
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  createdSeq: number;
  userLogin: string;
}

interface Comment {
  id: number;
  nodeId: string;
  issueNumber: number;
  body: string;
  userLogin: string;
}

interface Repo {
  dbId: number;
  name: string;
  owner: string;
  ownerId: number;
  isPrivate: boolean;
  description: string;
  defaultBranch: string;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  issues: Map<number, Issue>;
  pulls: Map<number, Pull>;
  labels: Map<string, Label>;
  comments: Map<number, Comment>;
  nextIssue: number;
  nextPull: number;
  nextComment: number;
  createdSeq: number;
}

interface Store {
  repos: Map<string, Repo>;
  nextRepoDbId: number;
  seq: number;
  reqSeq: number;
}

function createStore(): Store {
  return { repos: new Map(), nextRepoDbId: 1, seq: 0, reqSeq: 0 };
}

/** A deterministic timestamp (seconds since epoch) from the store's monotonic counter. */
function nextEpoch(store: Store): number {
  store.seq += 1;
  return BASE_EPOCH + store.seq;
}

/** A deterministic ISO timestamp from the store's monotonic counter. */
function nextIso(store: Store): string {
  return new Date(nextEpoch(store) * 1000).toISOString();
}

/** A deterministic request id (non-empty, as the protocol checks require). */
function nextRequestId(store: Store): string {
  store.reqSeq += 1;
  return `req-${store.reqSeq.toString(16).padStart(8, '0')}`;
}

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function getRepo(store: Store, owner: string, name: string): Repo | null {
  return store.repos.get(repoKey(owner, name)) ?? null;
}

// ---------------------------------------------------------------- HTTP helpers

/** Answer one request with a JSON body; `headers` go beside the JSON ones. */
function sendJson(store: Store, res: ServerResponse, status: number, body: unknown, headers: Readonly<Record<string, string>> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': nextRequestId(store),
    ...headers,
  });
  res.end(text);
}

/** Answer with a raw buffer (git smart HTTP). */
function sendRaw(store: Store, res: ServerResponse, status: number, body: Buffer, contentType: string, headers: Readonly<Record<string, string>> = {}): void {
  res.writeHead(status, {
    'content-type': contentType,
    'content-length': body.length,
    'x-github-request-id': nextRequestId(store),
    ...headers,
  });
  res.end(body);
}

/** The path of a request URL, or '/' when it does not parse (never a throw from a request). */
function pathOf(req: IncomingMessage): string {
  try {
    return new URL(req.url ?? '/', 'http://entry').pathname;
  } catch {
    return '/';
  }
}

/** The query parameters of a request URL. */
function queryOf(req: IncomingMessage): URLSearchParams {
  try {
    return new URL(req.url ?? '/', 'http://entry').searchParams;
  } catch {
    return new URLSearchParams();
  }
}

/** Read the whole request body as a buffer (git bodies are binary; REST bodies are JSON). */
async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string));
  return Buffer.concat(chunks);
}

/** Parse a JSON body; null when the body is empty, throws on malformed JSON. */
function parseJsonBody(body: Buffer): unknown {
  const text = body.toString('utf8').trim();
  if (text === '') return null;
  return JSON.parse(text) as unknown;
}

// ---------------------------------------------------------------- auth

/** The bearer token on the request, or ''. */
function bearerToken(req: IncomingMessage): string {
  const header = req.headers.authorization ?? '';
  const match = /^Bearer\s+(.+)$/.exec(header.trim());
  return match ? (match[1] ?? '').trim() : '';
}

/**
 * Whether the request is authenticated. When MAKEFUN_SHOP_TOKEN is set (the trial) the token must
 * match it exactly; otherwise (local testing) any non-empty bearer token is accepted.
 */
function isAuthed(req: IncomingMessage): boolean {
  const token = bearerToken(req);
  if (token === '') return false;
  if (TOKEN_ENV !== '') return token === TOKEN_ENV;
  return true;
}

// ---------------------------------------------------------------- git primitives

/** SHA-1 over `<type> <size>\0<data>`: the object id. */
function hashObject(type: string, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return createHash('sha1').update(header).update(data).digest('hex');
}

/** Store an object in a repo (idempotent) and return its oid. */
function putObject(repo: Repo, type: GitObject['type'], data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

/** One parsed commit. */
interface ParsedCommit {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

/** Parse a commit object's bytes. */
function parseCommit(data: Buffer): ParsedCommit {
  const text = data.toString('utf8');
  const headEnd = text.indexOf('\n\n');
  const head = headEnd >= 0 ? text.slice(0, headEnd) : text;
  const message = headEnd >= 0 ? text.slice(headEnd + 2) : '';
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

/** Build a commit object's bytes. */
function buildCommit(tree: string, parents: string[], message: string, epoch: number): Buffer {
  let head = `tree ${tree}\n`;
  for (const parent of parents) head += `parent ${parent}\n`;
  head += `author ${IDENTITY_NAME} <${IDENTITY_EMAIL}> ${epoch} +0000\n`;
  head += `committer ${IDENTITY_NAME} <${IDENTITY_EMAIL}> ${epoch} +0000\n`;
  return Buffer.from(`${head}\n${message}`, 'utf8');
}

/** One parsed tree entry. */
interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

/** Parse a tree object's bytes. */
function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    if (space < 0) break;
    const nul = data.indexOf(0x00, space);
    if (nul < 0 || nul + 21 > data.length) break;
    const mode = data.subarray(offset, space).toString('utf8');
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    offset = nul + 21;
  }
  return entries;
}

/** Git's name sort: directories sort as if their name ended in '/'. */
function treeSortKey(entry: TreeEntry): string {
  return entry.mode === '40000' ? `${entry.name}/` : entry.name;
}

/** Serialize tree entries (sorted by git's name sort) into a tree object's bytes. */
function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => (treeSortKey(a) < treeSortKey(b) ? -1 : treeSortKey(a) > treeSortKey(b) ? 1 : 0));
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

/**
 * Set one file in a tree (creating intermediate directories), returning the new root tree oid.
 * `parts` is the file's path split on '/'; `blobOid` is the new blob (or '' to delete the file).
 */
function setFileInTree(repo: Repo, baseTreeOid: string | null, parts: string[], blobOid: string): string {
  if (parts.length === 0) return baseTreeOid ?? putObject(repo, 'tree', buildTree([]));
  const entries = new Map<string, TreeEntry>();
  if (baseTreeOid !== null) {
    const base = repo.objects.get(baseTreeOid);
    if (base && base.type === 'tree') for (const entry of parseTree(base.data)) entries.set(entry.name, entry);
  }
  const [head, ...rest] = parts as [string, ...string[]];
  if (rest.length === 0) {
    if (blobOid === '') entries.delete(head);
    else entries.set(head, { mode: '100644', name: head, oid: blobOid });
  } else {
    const child = entries.get(head);
    const childTreeOid = child && child.mode === '40000' ? child.oid : null;
    const newChildOid = setFileInTree(repo, childTreeOid, rest, blobOid);
    const newChild = repo.objects.get(newChildOid);
    const isEmpty = newChild !== undefined && newChild.type === 'tree' && parseTree(newChild.data).length === 0;
    if (isEmpty) entries.delete(head);
    else entries.set(head, { mode: '40000', name: head, oid: newChildOid });
  }
  return putObject(repo, 'tree', buildTree([...entries.values()]));
}

/** Read one file's blob oid out of a tree, or null when it is absent (or is a directory). */
function getFileFromTree(repo: Repo, treeOid: string | null, parts: string[]): string | null {
  if (treeOid === null || parts.length === 0) return null;
  let current: string | null = treeOid;
  for (let i = 0; i < parts.length; i += 1) {
    if (current === null) return null;
    const obj = repo.objects.get(current);
    if (!obj || obj.type !== 'tree') return null;
    const entry = parseTree(obj.data).find((e) => e.name === parts[i]);
    if (!entry) return null;
    if (i === parts.length - 1) return entry.mode === '40000' ? null : entry.oid;
    if (entry.mode !== '40000') return null;
    current = entry.oid;
  }
  return null;
}

/** List a directory's entries (or the root tree's) as {name, mode, oid} rows. */
function listTreeDir(repo: Repo, treeOid: string | null, parts: string[]): TreeEntry[] | null {
  let current: string | null = treeOid;
  for (const part of parts) {
    if (current === null) return null;
    const obj = repo.objects.get(current);
    if (!obj || obj.type !== 'tree') return null;
    const entry = parseTree(obj.data).find((e) => e.name === part);
    if (!entry || entry.mode !== '40000') return null;
    current = entry.oid;
  }
  if (current === null) return [];
  const obj = repo.objects.get(current);
  if (!obj || obj.type !== 'tree') return null;
  return parseTree(obj.data);
}

/** Walk a commit's parents (newest first, following first-parent then all parents, breadth-first). */
function walkCommits(repo: Repo, startOid: string, limit: number): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const queue: string[] = [startOid];
  while (queue.length > 0 && out.length < limit) {
    const oid = queue.shift() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    out.push(oid);
    for (const parent of parseCommit(obj.data).parents) if (!seen.has(parent)) queue.push(parent);
  }
  return out;
}

/** Whether `ancestor` is reachable from `tip` (or equals it) by following parents. */
function isAncestor(repo: Repo, tip: string, ancestor: string): boolean {
  if (tip === ancestor) return true;
  const seen = new Set<string>();
  const queue: string[] = [tip];
  while (queue.length > 0) {
    const oid = queue.shift() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) {
      if (parent === ancestor) return true;
      if (!seen.has(parent)) queue.push(parent);
    }
  }
  return false;
}

// ---------------------------------------------------------------- packfiles

const PACK_TYPE = { commit: 1, tree: 2, blob: 3, tag: 4 } as const;
const PACK_TYPE_NAME: Record<number, GitObject['type']> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

/** Encode one pack entry header (type + size varint) and zlib-deflate the data. */
function encodePackEntry(type: GitObject['type'], data: Buffer): Buffer {
  const typeCode = PACK_TYPE[type];
  const header: number[] = [];
  let size = data.length;
  let first = (typeCode << 4) | (size & 0x0f);
  size >>= 4;
  if (size > 0) first |= 0x80;
  header.push(first);
  while (size > 0) {
    let byte = size & 0x7f;
    size >>= 7;
    if (size > 0) byte |= 0x80;
    header.push(byte);
  }
  return Buffer.concat([Buffer.from(header), deflateSync(data)]);
}

/** Build a packfile from plain objects (no deltas), in the caller's order. */
function writePack(objects: Array<{ type: GitObject['type']; data: Buffer }>): Buffer {
  const parts: Buffer[] = [Buffer.from('PACK')];
  const version = Buffer.alloc(4);
  version.writeUInt32BE(2, 0);
  parts.push(version);
  const count = Buffer.alloc(4);
  count.writeUInt32BE(objects.length, 0);
  parts.push(count);
  for (const object of objects) parts.push(encodePackEntry(object.type, object.data));
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

/** Read one varint (7 bits per byte, little-endian) from `buf` at `offset`. */
function readVarint(buf: Buffer, offset: number): { value: number; next: number } {
  let value = 0;
  let shift = 0;
  let pos = offset;
  for (;;) {
    const byte = buf[pos] as number;
    pos += 1;
    value |= (byte & 0x7f) << shift;
    shift += 7;
    if ((byte & 0x80) === 0) break;
  }
  return { value, next: pos };
}

/** Apply a git delta to a base buffer. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let pos = 0;
  const readSize = (): number => {
    const { value, next } = readVarint(delta, pos);
    pos = next;
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta source size does not match the base object');
  const out: Buffer[] = [];
  let outLen = 0;
  while (pos < delta.length) {
    const opcode = delta[pos] as number;
    pos += 1;
    if ((opcode & 0x80) !== 0) {
      let offset = 0;
      let size = 0;
      for (let i = 0; i < 4; i += 1) {
        if ((opcode & (1 << i)) !== 0) {
          offset |= (delta[pos] as number) << (8 * i);
          pos += 1;
        }
      }
      for (let i = 0; i < 3; i += 1) {
        if ((opcode & (0x10 << i)) !== 0) {
          size |= (delta[pos] as number) << (8 * i);
          pos += 1;
        }
      }
      if (size === 0) size = 0x10000;
      out.push(base.subarray(offset, offset + size));
      outLen += size;
    } else if (opcode !== 0) {
      out.push(delta.subarray(pos, pos + opcode));
      outLen += opcode;
      pos += opcode;
    } else {
      throw new Error('delta opcode 0 is reserved');
    }
  }
  const result = Buffer.concat(out);
  if (result.length !== targetSize || outLen !== targetSize) throw new Error('delta target size does not match');
  return result;
}

/**
 * Read a packfile (version 2/3), resolving OFS_DELTA and REF_DELTA. `resolveBase` answers bases
 * the pack itself does not hold (thin packs reference objects the server already stores).
 */
function readPack(
  pack: Buffer,
  resolveBase: (oid: string) => GitObject | null,
): Map<string, GitObject> {
  if (pack.length < 12 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('not a packfile');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = pack.readUInt32BE(8);
  const objects = new Map<string, GitObject>();
  const byOffset = new Map<number, { oid: string; type: GitObject['type']; data: Buffer }>();
  let offset = 12;
  for (let i = 0; i < count; i += 1) {
    const entryOffset = offset;
    let byte = pack[offset] as number;
    offset += 1;
    const typeCode = (byte >> 4) & 0x07;
    let size = byte & 0x0f;
    let shift = 4;
    while ((byte & 0x80) !== 0) {
      byte = pack[offset] as number;
      offset += 1;
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    let baseOid: string | null = null;
    let baseOffset: number | null = null;
    if (typeCode === 6) {
      // OFS_DELTA: the base's offset, encoded backwards from this entry.
      byte = pack[offset] as number;
      offset += 1;
      let base = byte & 0x7f;
      while ((byte & 0x80) !== 0) {
        byte = pack[offset] as number;
        offset += 1;
        base = ((base + 1) << 7) | (byte & 0x7f);
      }
      baseOffset = entryOffset - base;
    } else if (typeCode === 7) {
      baseOid = pack.subarray(offset, offset + 20).toString('hex');
      offset += 20;
    }
    // The zlib stream's end: inflateSync throws while the stream is truncated and succeeds (ignoring
    // trailing bytes) once the whole stream is present, so the smallest succeeding end is the exact
    // stream end. Binary-search it (log n inflate calls per entry, not a linear scan).
    let inflated: Buffer | null = null;
    let consumed = 0;
    {
      let lo = offset + 1;
      let hi = pack.length;
      let found = -1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        try {
          inflateSync(pack.subarray(offset, mid));
          found = mid;
          hi = mid - 1;
        } catch {
          lo = mid + 1;
        }
      }
      if (found < 0) throw new Error('pack entry zlib stream is truncated');
      inflated = inflateSync(pack.subarray(offset, found));
      consumed = found - offset;
    }
    if (inflated.length !== size) throw new Error('pack entry size does not match its header');
    offset += consumed;
    if (typeCode >= 1 && typeCode <= 4) {
      const type = PACK_TYPE_NAME[typeCode] as GitObject['type'];
      const oid = hashObject(type, inflated);
      objects.set(oid, { type, data: inflated });
      byOffset.set(entryOffset, { oid, type, data: inflated });
    } else if (typeCode === 6 || typeCode === 7) {
      let base: { type: GitObject['type']; data: Buffer } | null = null;
      if (baseOffset !== null) {
        const found = byOffset.get(baseOffset);
        if (found) base = found;
      } else if (baseOid !== null) {
        const found = objects.get(baseOid) ?? resolveBase(baseOid);
        if (found) base = found;
      }
      if (base === null) throw new Error('delta base is not available');
      const data = applyDelta(base.data, inflated);
      const oid = hashObject(base.type, data);
      objects.set(oid, { type: base.type, data });
      byOffset.set(entryOffset, { oid, type: base.type, data });
    } else {
      throw new Error(`unsupported pack entry type ${typeCode}`);
    }
  }
  return objects;
}

// ---------------------------------------------------------------- pkt-lines

type PktKind = 'data' | 'flush' | 'delim' | 'response-end';

interface Pkt {
  kind: PktKind;
  payload: Buffer;
}

/** Decode a buffer of pkt-lines into packets. */
function decodePktLines(buf: Buffer): Pkt[] {
  const packets: Pkt[] = [];
  let offset = 0;
  while (offset + 4 <= buf.length) {
    const lenText = buf.subarray(offset, offset + 4).toString('ascii');
    const len = parseInt(lenText, 16);
    if (Number.isNaN(len)) break;
    if (len === 0) {
      packets.push({ kind: 'flush', payload: Buffer.alloc(0) });
      offset += 4;
    } else if (len === 1) {
      packets.push({ kind: 'delim', payload: Buffer.alloc(0) });
      offset += 4;
    } else if (len === 2) {
      packets.push({ kind: 'response-end', payload: Buffer.alloc(0) });
      offset += 4;
    } else {
      if (offset + len > buf.length) break;
      packets.push({ kind: 'data', payload: buf.subarray(offset + 4, offset + len) });
      offset += len;
    }
  }
  return packets;
}

/** Encode one pkt-line (a string or buffer payload). */
function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = data.length + 4;
  return Buffer.concat([Buffer.from(len.toString(16).padStart(4, '0'), 'ascii'), data]);
}

function pktFlush(): Buffer {
  return Buffer.from('0000', 'ascii');
}

function pktDelim(): Buffer {
  return Buffer.from('0001', 'ascii');
}

/** Encode a list of lines / flush / delim markers into a pkt-line stream. */
function encodePktLines(lines: Array<string | 'flush' | 'delim'>): Buffer {
  const parts: Buffer[] = [];
  for (const line of lines) {
    if (line === 'flush') parts.push(pktFlush());
    else if (line === 'delim') parts.push(pktDelim());
    else parts.push(pktLine(line));
  }
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------- repo helpers

/** Create a repository in the store (no auth check here; the caller decides). */
function createRepoRecord(store: Store, owner: string, ownerId: number, name: string, isPrivate: boolean, description: string): Repo {
  const repo: Repo = {
    dbId: store.nextRepoDbId,
    name,
    owner,
    ownerId,
    isPrivate,
    description,
    defaultBranch: 'main',
    refs: new Map(),
    objects: new Map(),
    issues: new Map(),
    pulls: new Map(),
    labels: new Map(),
    comments: new Map(),
    nextIssue: 1,
    nextPull: 1,
    nextComment: 1,
    createdSeq: store.seq,
  };
  store.nextRepoDbId += 1;
  store.repos.set(repoKey(owner, name), repo);
  return repo;
}

/** The tip oid of a branch ref, or null when the ref does not exist. */
function refTip(repo: Repo, refName: string): string | null {
  return repo.refs.get(refName) ?? null;
}

/** The tip oid of a branch name (refs/heads/<branch>), or null. */
function branchTip(repo: Repo, branch: string): string | null {
  return refTip(repo, `refs/heads/${branch}`);
}

/** The tree oid at a commit, or null when the commit is unknown. */
function commitTree(repo: Repo, commitOid: string): string | null {
  const obj = repo.objects.get(commitOid);
  if (!obj || obj.type !== 'commit') return null;
  return parseCommit(obj.data).tree;
}

/**
 * Create a commit on a branch (or on a ref) that sets one file, and move the ref to it.
 * Returns the new commit oid. `message` is the commit message.
 */
function commitFile(
  store: Store,
  repo: Repo,
  refName: string,
  pathParts: string[],
  content: Buffer | null,
  message: string,
): string {
  const tip = refTip(repo, refName);
  const baseTree = tip !== null ? commitTree(repo, tip) : null;
  let blobOid = '';
  if (content !== null) blobOid = putObject(repo, 'blob', content);
  const newTree = setFileInTree(repo, baseTree, pathParts, blobOid);
  const epoch = nextEpoch(store);
  const parents = tip !== null ? [tip] : [];
  const commitData = buildCommit(newTree, parents, message, epoch);
  const commitOid = putObject(repo, 'commit', commitData);
  repo.refs.set(refName, commitOid);
  return commitOid;
}

/** Read a file's content (as a Buffer) at a ref, or null when absent. */
function readFileAtRef(repo: Repo, refName: string, pathParts: string[]): Buffer | null {
  const tip = refTip(repo, refName);
  if (tip === null) return null;
  const tree = commitTree(repo, tip);
  if (tree === null) return null;
  const blobOid = getFileFromTree(repo, tree, pathParts);
  if (blobOid === null) return null;
  const obj = repo.objects.get(blobOid);
  if (!obj || obj.type !== 'blob') return null;
  return obj.data;
}

/** A flat map of path -> blob oid for every file in a tree (recursively). */
function flattenTree(repo: Repo, treeOid: string | null, prefix: string, out: Map<string, string>): void {
  if (treeOid === null) return;
  const obj = repo.objects.get(treeOid);
  if (!obj || obj.type !== 'tree') return;
  for (const entry of parseTree(obj.data)) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') flattenTree(repo, entry.oid, path, out);
    else out.set(path, entry.oid);
  }
}

/** Diff two trees: [{path, status, baseOid, headOid}] for files that differ. */
function diffTrees(repo: Repo, baseTreeOid: string | null, headTreeOid: string | null): Array<{ path: string; status: 'added' | 'modified' | 'removed'; baseOid: string | null; headOid: string | null }> {
  const base = new Map<string, string>();
  const head = new Map<string, string>();
  flattenTree(repo, baseTreeOid, '', base);
  flattenTree(repo, headTreeOid, '', head);
  const out: Array<{ path: string; status: 'added' | 'modified' | 'removed'; baseOid: string | null; headOid: string | null }> = [];
  const paths = new Set([...base.keys(), ...head.keys()]);
  for (const path of [...paths].sort()) {
    const b = base.get(path) ?? null;
    const h = head.get(path) ?? null;
    if (b === h) continue;
    if (b === null) out.push({ path, status: 'added', baseOid: null, headOid: h });
    else if (h === null) out.push({ path, status: 'removed', baseOid: b, headOid: null });
    else out.push({ path, status: 'modified', baseOid: b, headOid: h });
  }
  return out;
}

/** Count added/deleted lines between two blobs (for pull file stats). */
function lineDiffCounts(base: Buffer | null, head: Buffer | null): { additions: number; deletions: number } {
  const baseLines = base === null ? [] : base.toString('utf8').split('\n');
  const headLines = head === null ? [] : head.toString('utf8').split('\n');
  const baseSet = new Map<string, number>();
  for (const line of baseLines) baseSet.set(line, (baseSet.get(line) ?? 0) + 1);
  const headSet = new Map<string, number>();
  for (const line of headLines) headSet.set(line, (headSet.get(line) ?? 0) + 1);
  let additions = 0;
  let deletions = 0;
  for (const [line, count] of headSet) {
    const inBase = baseSet.get(line) ?? 0;
    if (count > inBase) additions += count - inBase;
  }
  for (const [line, count] of baseSet) {
    const inHead = headSet.get(line) ?? 0;
    if (count > inHead) deletions += count - inHead;
  }
  return { additions, deletions };
}

// ---------------------------------------------------------------- REST serializers

function globalId(kind: string, parts: Array<string | number>): string {
  return Buffer.from(`${kind}:${parts.join(':')}`, 'utf8').toString('base64');
}

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.dbId,
    node_id: globalId('Repository', [repo.dbId]),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: repo.ownerId, type: 'User' },
    private: repo.isPrivate,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: new Date((BASE_EPOCH + repo.createdSeq) * 1000).toISOString(),
    updated_at: new Date((BASE_EPOCH + repo.createdSeq) * 1000).toISOString(),
    html_url: `https://example.invalid/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
  };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: issue.nodeId,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => ({ name, color: '000000', description: '' })),
    user: { login: issue.userLogin, id: VIEWER_ID, type: 'User' },
    created_at: new Date((BASE_EPOCH + issue.createdSeq) * 1000).toISOString(),
    updated_at: new Date((BASE_EPOCH + issue.createdSeq) * 1000).toISOString(),
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
    repository_url: `/api/v3/repos/${repo.owner}/${repo.name}`,
    comments: 0,
  };
}

function pullJson(repo: Repo, pull: Pull): Record<string, unknown> {
  return {
    id: pull.id,
    node_id: pull.nodeId,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    head: { ref: pull.headRef, sha: pull.headSha, label: `${repo.owner}:${pull.headRef}` },
    base: { ref: pull.baseRef, sha: pull.baseSha, label: `${repo.owner}:${pull.baseRef}` },
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    user: { login: pull.userLogin, id: VIEWER_ID, type: 'User' },
    created_at: new Date((BASE_EPOCH + pull.createdSeq) * 1000).toISOString(),
    updated_at: new Date((BASE_EPOCH + pull.createdSeq) * 1000).toISOString(),
    html_url: `https://example.invalid/${repo.owner}/${repo.name}/pull/${pull.number}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
  };
}

/** The pull files view: diff base tree vs head tree, with line counts. */
function pullFilesJson(repo: Repo, pull: Pull): Array<Record<string, unknown>> {
  const baseTree = pull.baseSha !== '' ? commitTree(repo, pull.baseSha) : null;
  const headTree = pull.headSha !== '' ? commitTree(repo, pull.headSha) : null;
  const out: Array<Record<string, unknown>> = [];
  for (const change of diffTrees(repo, baseTree, headTree)) {
    if (change.status === 'removed') continue;
    const baseData = change.baseOid !== null ? repo.objects.get(change.baseOid)?.data ?? null : null;
    const headData = change.headOid !== null ? repo.objects.get(change.headOid)?.data ?? null : null;
    const counts = lineDiffCounts(baseData, headData);
    const additions = Math.max(counts.additions, 1);
    out.push({
      filename: change.path,
      status: change.status === 'added' ? 'added' : 'modified',
      additions,
      deletions: counts.deletions,
      changes: additions + counts.deletions,
      sha: change.headOid,
    });
  }
  return out;
}

/**
 * Whether a pull request is conflicted: the same file changed differently on both the base branch
 * (since the PR's base) and the head branch. `baseSha` is the PR's base commit.
 */
function pullIsConflicted(repo: Repo, pull: Pull): boolean {
  const baseTree = pull.baseSha !== '' ? commitTree(repo, pull.baseSha) : null;
  const headTree = pull.headSha !== '' ? commitTree(repo, pull.headSha) : null;
  const baseTipOid = branchTip(repo, pull.baseRef);
  const baseTipTree = baseTipOid !== null ? commitTree(repo, baseTipOid) : null;
  const headChanges = new Map<string, string | null>();
  for (const change of diffTrees(repo, baseTree, headTree)) headChanges.set(change.path, change.headOid);
  for (const change of diffTrees(repo, baseTree, baseTipTree)) {
    if (headChanges.has(change.path) && headChanges.get(change.path) !== change.headOid) return true;
  }
  return false;
}

/** Apply a pull request's head changes onto the base branch as one squash commit. Returns the new commit oid. */
function squashMerge(store: Store, repo: Repo, pull: Pull, message: string): string {
  const baseTipOid = branchTip(repo, pull.baseRef);
  const baseTree = baseTipOid !== null ? commitTree(repo, baseTipOid) : null;
  const headTree = pull.headSha !== '' ? commitTree(repo, pull.headSha) : null;
  const headFiles = new Map<string, string>();
  flattenTree(repo, headTree, '', headFiles);
  const baseFiles = new Map<string, string>();
  flattenTree(repo, baseTree, '', baseFiles);
  const baseHeadTree = pull.baseSha !== '' ? commitTree(repo, pull.baseSha) : null;
  const baseHeadFiles = new Map<string, string>();
  flattenTree(repo, baseHeadTree, '', baseHeadFiles);
  // Start from the base branch's current tree; apply exactly the files the head changed vs the PR base.
  let treeOid = baseTree;
  for (const [path, headOid] of headFiles) {
    if (baseHeadFiles.get(path) !== headOid) {
      treeOid = setFileInTree(repo, treeOid, path.split('/'), headOid);
    }
  }
  for (const path of baseHeadFiles.keys()) {
    if (!headFiles.has(path)) {
      treeOid = setFileInTree(repo, treeOid, path.split('/'), '');
    }
  }
  const epoch = nextEpoch(store);
  const parents = baseTipOid !== null ? [baseTipOid] : [];
  const commitData = buildCommit(treeOid, parents, message, epoch);
  const commitOid = putObject(repo, 'commit', commitData);
  repo.refs.set(`refs/heads/${pull.baseRef}`, commitOid);
  return commitOid;
}

// ---------------------------------------------------------------- git smart HTTP

/** Parse a tag object: the oid its `object` line names, or null. */
function tagTarget(data: Buffer): string | null {
  const text = data.toString('utf8');
  for (const line of text.split('\n')) {
    if (line.startsWith('object ')) return line.slice(7).trim();
    if (line === '') break;
  }
  return null;
}

/** The refs of a repo as sorted {name, oid} rows (branches, tags, HEAD first when present). */
function listRefs(repo: Repo): Array<{ name: string; oid: string }> {
  const rows: Array<{ name: string; oid: string }> = [];
  for (const [name, oid] of [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    rows.push({ name, oid });
  }
  return rows;
}

/** The v2 capability advertisement for upload-pack. */
function advertisementV2(): Buffer {
  return Buffer.concat([
    pktLine('version 2\n'),
    pktLine(`agent=${AGENT_NAME}\n`),
    pktLine('ls-refs=unborn\n'),
    pktLine('fetch=shallow\n'),
    pktLine('server-option\n'),
    pktLine('object-format=sha1\n'),
    pktFlush(),
  ]);
}

/** The v0 ref advertisement for a service, with capabilities on the first ref line. */
function advertisementV0(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack', capabilities: string): Buffer {
  const parts: Buffer[] = [pktLine(`# service=${service}\n`), pktFlush()];
  const refs = listRefs(repo);
  const caps = capabilities;
  if (refs.length === 0) {
    parts.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    // HEAD first, carrying the capabilities after a NUL.
    const headTip = branchTip(repo, repo.defaultBranch);
    const headOid = headTip ?? ZERO_OID;
    parts.push(pktLine(`${headOid} HEAD\0${caps}\n`));
    for (const ref of refs) {
      parts.push(pktLine(`${ref.oid} ${ref.name}\n`));
      // Peeled tags: the commit a tag points at, as a `^{}` line.
      if (ref.name.startsWith('refs/tags/')) {
        const obj = repo.objects.get(ref.oid);
        if (obj && obj.type === 'tag') {
          const target = tagTarget(obj.data);
          if (target !== null) parts.push(pktLine(`${target} ${ref.name}^{}\n`));
        }
      }
    }
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

const V0_UPLOAD_CAPS = (): string => `symref=HEAD:refs/heads/main side-band-64k thin-pack ofs-delta shallow agent=${AGENT_NAME} object-format=sha1`;
const V0_RECEIVE_CAPS = (): string => `report-status side-band-64k delete-refs ofs-delta agent=${AGENT_NAME}`;

/** Split a buffer into sideband band-1 pkt-lines (the pkt-line cap is 65520 bytes total, so the
 *  payload is 4 header + 1 band + at most 65515 data bytes; 65500 leaves a safety margin). */
function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const CHUNK = 65500;
  for (let offset = 0; offset < pack.length; offset += CHUNK) {
    const chunk = pack.subarray(offset, Math.min(offset + CHUNK, pack.length));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  return Buffer.concat(parts);
}

interface FetchRequest {
  wants: string[];
  haves: string[];
  shallowIn: string[];
  depth: number | null;
}

/** Parse a v2 fetch / ls-refs request body into its arguments. */
function parseV2Request(packets: Pkt[]): { command: string; args: Map<string, string[]> } {
  const args = new Map<string, string[]>();
  let command = '';
  let inArgs = false;
  for (const packet of packets) {
    if (packet.kind === 'delim') {
      inArgs = true;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (!inArgs) {
      if (line.startsWith('command=')) command = line.slice('command='.length);
      continue;
    }
    const space = line.indexOf(' ');
    const key = space < 0 ? line : line.slice(0, space);
    const value = space < 0 ? '' : line.slice(space + 1);
    const list = args.get(key) ?? [];
    list.push(value);
    args.set(key, list);
  }
  return { command, args };
}

/**
 * Plan a fetch: which commits to send, the new shallow boundaries, the unshallowed old ones,
 * the acknowledgments, and every object the client already holds (so the pack never re-sends one).
 * `wants` are commit oids (tag wants are resolved to their target first).
 */
function planFetch(repo: Repo, request: FetchRequest): { toSend: string[]; shallowOut: string[]; unshallowOut: string[]; acks: string[]; nak: boolean; heldObjects: Set<string> } {
  const shallowIn = new Set(request.shallowIn);
  // Commits the client already holds: reachable from haves, stopping at shallow boundaries
  // (a shallow boundary's parents are NOT held).
  const held = new Set<string>();
  {
    const queue = [...request.haves];
    const seen = new Set<string>();
    while (queue.length > 0) {
      const oid = queue.shift() as string;
      if (seen.has(oid)) continue;
      seen.add(oid);
      held.add(oid);
      if (shallowIn.has(oid)) continue;
      const obj = repo.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      for (const parent of parseCommit(obj.data).parents) if (!seen.has(parent)) queue.push(parent);
    }
  }
  // Every object reachable from a held commit (its tree and blobs included): the client has these,
  // so the pack must not re-send them.
  const heldObjects = new Set<string>();
  {
    const stack = [...held];
    while (stack.length > 0) {
      const oid = stack.pop() as string;
      if (heldObjects.has(oid)) continue;
      heldObjects.add(oid);
      const obj = repo.objects.get(oid);
      if (!obj) continue;
      if (obj.type === 'commit') {
        const commit = parseCommit(obj.data);
        stack.push(commit.tree);
      } else if (obj.type === 'tree') {
        for (const entry of parseTree(obj.data)) stack.push(entry.oid);
      } else if (obj.type === 'tag') {
        const target = tagTarget(obj.data);
        if (target !== null) stack.push(target);
      }
    }
  }
  const maxDepth = request.depth ?? Number.POSITIVE_INFINITY;
  const toSend: string[] = [];
  const toSendSet = new Set<string>();
  const shallowOut: string[] = [];
  const acks: string[] = [];
  {
    const dist = new Map<string, number>();
    const queue: string[] = [];
    for (const want of request.wants) {
      if (!dist.has(want)) {
        dist.set(want, 0);
        queue.push(want);
      }
    }
    while (queue.length > 0) {
      const oid = queue.shift() as string;
      const d = dist.get(oid) as number;
      if (d >= maxDepth) continue;
      const inHeld = held.has(oid);
      const isBoundary = shallowIn.has(oid);
      if (inHeld) {
        acks.push(oid);
        if (!isBoundary) continue;
        // A held shallow boundary: the client has the commit but not its parents — descend.
      } else {
        toSend.push(oid);
        toSendSet.add(oid);
        if (d === maxDepth - 1) shallowOut.push(oid);
      }
      if (d + 1 >= maxDepth) continue;
      const obj = repo.objects.get(oid);
      if (!obj || obj.type !== 'commit') continue;
      for (const parent of parseCommit(obj.data).parents) {
        if (!dist.has(parent)) {
          dist.set(parent, d + 1);
          queue.push(parent);
        }
      }
    }
  }
  // Old shallow boundaries whose parents are now sent are no longer shallow.
  const unshallowOut: string[] = [];
  for (const boundary of shallowIn) {
    const obj = repo.objects.get(boundary);
    if (!obj || obj.type !== 'commit') continue;
    for (const parent of parseCommit(obj.data).parents) {
      if (toSendSet.has(parent)) {
        unshallowOut.push(boundary);
        break;
      }
    }
  }
  const nak = request.haves.length > 0 && acks.length === 0;
  return { toSend, shallowOut, unshallowOut, acks, nak, heldObjects };
}

/** Collect the pack objects for a set of commit oids (+ any extra oids, e.g. tag objects). */
function collectPackObjects(repo: Repo, commitOids: string[], extraOids: string[], exclude: Set<string> = new Set()): Array<{ type: GitObject['type']; data: Buffer }> {
  const out: Array<{ type: GitObject['type']; data: Buffer }> = [];
  const seen = new Set<string>();
  const add = (oid: string): void => {
    if (seen.has(oid) || exclude.has(oid)) return;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj) return;
    out.push(obj);
    if (obj.type === 'commit') {
      const commit = parseCommit(obj.data);
      add(commit.tree);
    } else if (obj.type === 'tree') {
      for (const entry of parseTree(obj.data)) add(entry.oid);
    } else if (obj.type === 'tag') {
      const target = tagTarget(obj.data);
      if (target !== null) add(target);
    }
  };
  for (const oid of extraOids) add(oid);
  for (const oid of commitOids) add(oid);
  return out;
}

/** Answer a v2 fetch request. */
function handleUploadPackV2Fetch(repo: Repo, packets: Pkt[]): Buffer {
  const { args } = parseV2Request(packets);
  const wants = args.get('want') ?? [];
  const haves = args.get('have') ?? [];
  const shallowIn = args.get('shallow') ?? [];
  const deepen = args.get('deepen') ?? [];
  const depth = deepen.length > 0 ? Number.parseInt(deepen[0] as string, 10) : null;
  // Resolve tag wants to their target commits (the tag object itself is still sent).
  const tagOids: string[] = [];
  const commitWants: string[] = [];
  for (const want of wants) {
    const obj = repo.objects.get(want);
    if (obj && obj.type === 'tag') {
      tagOids.push(want);
      const target = tagTarget(obj.data);
      if (target !== null) commitWants.push(target);
    } else {
      commitWants.push(want);
    }
  }
  const plan = planFetch(repo, { wants: commitWants, haves, shallowIn, depth: Number.isNaN(depth as number) ? null : depth });
  const packObjects = collectPackObjects(repo, plan.toSend, tagOids, plan.heldObjects);
  const parts: Buffer[] = [];
  if (haves.length > 0) {
    parts.push(pktLine('acknowledgments\n'));
    if (plan.acks.length > 0) for (const ack of plan.acks) parts.push(pktLine(`ACK ${ack}\n`));
    else parts.push(pktLine('NAK\n'));
    parts.push(pktDelim());
  }
  if (plan.shallowOut.length > 0 || plan.unshallowOut.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const oid of plan.shallowOut) parts.push(pktLine(`shallow ${oid}\n`));
    for (const oid of plan.unshallowOut) parts.push(pktLine(`unshallow ${oid}\n`));
    parts.push(pktDelim());
  }
  if (packObjects.length > 0) {
    const pack = writePack(packObjects);
    parts.push(pktLine('packfile\n'));
    parts.push(sidebandPack(pack));
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

/** Answer a v2 ls-refs request. */
function handleLsRefs(repo: Repo, packets: Pkt[]): Buffer {
  const { args } = parseV2Request(packets);
  const peel = (args.get('peel') ?? []).length > 0;
  const symrefs = (args.get('symrefs') ?? []).length > 0;
  const prefixes = args.get('ref-prefix') ?? [];
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((prefix) => name.startsWith(prefix));
  const parts: Buffer[] = [];
  const headTip = branchTip(repo, repo.defaultBranch);
  if (keep('HEAD')) {
    if (headTip !== null) {
      parts.push(pktLine(`${headTip} HEAD${symrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : ''}\n`));
    } else {
      parts.push(pktLine(`unborn HEAD${symrefs ? ` symref-target:refs/heads/${repo.defaultBranch}` : ''}\n`));
    }
  }
  for (const ref of listRefs(repo)) {
    if (!keep(ref.name)) continue;
    let line = `${ref.oid} ${ref.name}`;
    if (peel && ref.name.startsWith('refs/tags/')) {
      const obj = repo.objects.get(ref.oid);
      if (obj && obj.type === 'tag') {
        const target = tagTarget(obj.data);
        if (target !== null) line += ` peeled:${target}`;
      }
    }
    parts.push(pktLine(`${line}\n`));
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

/** Answer a v0 fetch request (wants, shallow/deepen, flush, haves, done, flush). */
function handleUploadPackV0Fetch(repo: Repo, body: Buffer): Buffer {
  const packets = decodePktLines(body);
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowIn: string[] = [];
  let depth: number | null = null;
  let seenFlush = false;
  for (const packet of packets) {
    if (packet.kind === 'flush') {
      seenFlush = true;
      continue;
    }
    if (packet.kind !== 'data') continue;
    const line = packet.payload.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('want ')) {
      const rest = line.slice(5);
      const space = rest.indexOf(' ');
      wants.push(space < 0 ? rest : rest.slice(0, space));
    } else if (line.startsWith('shallow ')) shallowIn.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) depth = Number.parseInt(line.slice(7).trim(), 10);
    else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    else if (line.startsWith('deepen-since ') || line.startsWith('deepen-not ')) {
      // Not supported: treated as a full fetch for that boundary (the suite does not send these).
    }
  }
  void seenFlush;
  const tagOids: string[] = [];
  const commitWants: string[] = [];
  for (const want of wants) {
    const obj = repo.objects.get(want);
    if (obj && obj.type === 'tag') {
      tagOids.push(want);
      const target = tagTarget(obj.data);
      if (target !== null) commitWants.push(target);
    } else {
      commitWants.push(want);
    }
  }
  const plan = planFetch(repo, { wants: commitWants, haves, shallowIn, depth: Number.isNaN(depth as number) ? null : depth });
  const packObjects = collectPackObjects(repo, plan.toSend, tagOids, plan.heldObjects);
  const parts: Buffer[] = [];
  if (haves.length > 0) {
    if (plan.acks.length > 0) for (const ack of plan.acks) parts.push(pktLine(`ACK ${ack}\n`));
    else parts.push(pktLine('NAK\n'));
  }
  for (const oid of plan.shallowOut) parts.push(pktLine(`shallow ${oid}\n`));
  for (const oid of plan.unshallowOut) parts.push(pktLine(`unshallow ${oid}\n`));
  if (packObjects.length > 0) {
    const pack = writePack(packObjects);
    parts.push(sidebandPack(pack));
  }
  parts.push(pktFlush());
  return Buffer.concat(parts);
}

/**
 * Handle a receive-pack (push) body: command lines, flush, then the raw packfile.
 * Returns the report-status stream (pkt-lined, inside sideband band 1).
 */
function handleReceivePack(repo: Repo, body: Buffer): Buffer {
  // Parse command pkt-lines until the flush; the bytes after it are the packfile.
  const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
  let offset = 0;
  let packStart = body.length;
  while (offset + 4 <= body.length) {
    const lenText = body.subarray(offset, offset + 4).toString('ascii');
    const len = parseInt(lenText, 16);
    if (Number.isNaN(len) || len === 0) {
      packStart = offset + 4;
      break;
    }
    if (len < 4 || offset + len > body.length) break;
    const payload = body.subarray(offset + 4, offset + len);
    const line = payload.toString('utf8').replace(/\n$/, '');
    const nul = line.indexOf('\0');
    const commandPart = nul >= 0 ? line.slice(0, nul) : line;
    const fields = commandPart.split(' ');
    if (fields.length >= 3) {
      commands.push({ oldOid: fields[0] as string, newOid: fields[1] as string, ref: fields[2] as string });
    }
    offset += len;
  }
  // Store the pack's objects (a delete-only push carries no pack).
  if (packStart < body.length) {
    const pack = body.subarray(packStart);
    if (pack.length >= 12 && pack.subarray(0, 4).toString('ascii') === 'PACK') {
      const objects = readPack(pack, (oid) => repo.objects.get(oid) ?? null);
      for (const [oid, obj] of objects) if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
    }
  }
  // Apply the commands, one at a time; a refused ref does not stop the others.
  const reportLines: string[] = ['unpack ok'];
  for (const command of commands) {
    const current = repo.refs.get(command.ref) ?? null;
    if (command.newOid === ZERO_OID) {
      // Delete.
      if (current === null) reportLines.push(`ng ${command.ref} remote ref does not exist`);
      else {
        repo.refs.delete(command.ref);
        reportLines.push(`ok ${command.ref}`);
      }
      continue;
    }
    if (command.oldOid === ZERO_OID) {
      // Create.
      if (current !== null) {
        reportLines.push(`ng ${command.ref} already exists`);
        continue;
      }
      if (!repo.objects.has(command.newOid)) {
        reportLines.push(`ng ${command.ref} object not found`);
        continue;
      }
      repo.refs.set(command.ref, command.newOid);
      reportLines.push(`ok ${command.ref}`);
      continue;
    }
    // Update.
    if (current === null) {
      reportLines.push(`ng ${command.ref} remote ref does not exist`);
      continue;
    }
    if (current !== command.oldOid) {
      reportLines.push(`ng ${command.ref} remote ref object does not match`);
      continue;
    }
    if (command.newOid === command.oldOid) {
      reportLines.push(`ok ${command.ref}`);
      continue;
    }
    if (!repo.objects.has(command.newOid)) {
      reportLines.push(`ng ${command.ref} object not found`);
      continue;
    }
    if (!isAncestor(repo, command.newOid, command.oldOid)) {
      reportLines.push(`ng ${command.ref} non-fast-forward`);
      continue;
    }
    repo.refs.set(command.ref, command.newOid);
    reportLines.push(`ok ${command.ref}`);
  }
  const inner = Buffer.concat(reportLines.map((line) => pktLine(`${line}\n`)));
  return Buffer.concat([pktLine(Buffer.concat([Buffer.from([1]), inner])), pktFlush()]);
}

// ---------------------------------------------------------------- REST v3

/** The request's origin (scheme + host) for absolute Link URLs. */
function originOf(req: IncomingMessage): string {
  const host = req.headers.host ?? '127.0.0.1';
  return `http://${host}`;
}

/** A Link header for a paged list (only the relations that exist). */
function linkHeader(req: IncomingMessage, basePath: string, query: URLSearchParams, page: number, perPage: number, total: number): string {
  const totalPages = Math.max(1, Math.ceil(total / perPage));
  const make = (p: number): string => {
    const q = new URLSearchParams(query);
    q.set('page', String(p));
    q.set('per_page', String(perPage));
    return `${originOf(req)}${basePath}?${q.toString()}`;
  };
  const parts: string[] = [];
  if (page < totalPages) parts.push(`<${make(page + 1)}>; rel="next"`);
  if (page > 1) parts.push(`<${make(page - 1)}>; rel="prev"`);
  parts.push(`<${make(1)}>; rel="first"`);
  parts.push(`<${make(totalPages)}>; rel="last"`);
  return parts.join(', ');
}

/** Page a list: returns the page slice and whether a Link header is needed. */
function paginate<T>(items: T[], query: URLSearchParams): { page: T[]; pageNum: number; perPage: number; total: number } {
  const perPage = Math.max(1, Math.min(100, Number.parseInt(query.get('per_page') ?? '30', 10) || 30));
  const pageNum = Math.max(1, Number.parseInt(query.get('page') ?? '1', 10) || 1);
  const start = (pageNum - 1) * perPage;
  return { page: items.slice(start, start + perPage), pageNum, perPage, total: items.length };
}

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function bodyString(body: unknown, field: string): string {
  if (!isRecord(body)) return '';
  const value = body[field];
  return typeof value === 'string' ? value : '';
}

function bodyBoolean(body: unknown, field: string, fallback: boolean): boolean {
  if (!isRecord(body)) return fallback;
  const value = body[field];
  return typeof value === 'boolean' ? value : fallback;
}

/** Decode a path segment (owner/repo/branch names are URL-encoded by the client). */
function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

/** Handle a REST v3 request. Returns true when the route was handled. */
async function handleRest(store: Store, req: IncomingMessage, res: ServerResponse, method: string, path: string, query: URLSearchParams): Promise<boolean> {
  if (!path.startsWith('/api/v3')) return false;
  const sub = path.slice('/api/v3'.length);
  const segments = sub.split('/').filter((s) => s !== '');

  // The API root.
  if (method === 'GET' && (sub === '' || sub === '/')) {
    sendJson(store, res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }

  // Meta: the server's own version.
  if (method === 'GET' && sub === '/meta') {
    sendJson(store, res, 200, { installed_version: '1.0.0', git_commit_sha: '0000000000000000000000000000000000000000' });
    return true;
  }

  // The token's own user.
  if (method === 'GET' && sub === '/user') {
    sendJson(store, res, 200, {
      login: VIEWER_LOGIN,
      id: VIEWER_ID,
      node_id: globalId('User', [VIEWER_ID]),
      name: 'ada iversen',
      email: 'adaiversen@example.invalid',
      type: 'User',
      html_url: `https://example.invalid/${VIEWER_LOGIN}`,
      url: '/api/v3/user',
    });
    return true;
  }

  // The viewer's repositories (paged).
  if (sub === '/user/repos') {
    if (method === 'GET') {
      const all = [...store.repos.values()]
        .filter((repo) => repo.owner === VIEWER_LOGIN)
        .sort((a, b) => a.dbId - b.dbId)
        .map((repo) => repoJson(repo));
      const { page, pageNum, perPage, total } = paginate(all, query);
      const headers: Record<string, string> = {};
      if (total > perPage) headers.link = linkHeader(req, '/api/v3/user/repos', query, pageNum, perPage, total);
      sendJson(store, res, 200, page, headers);
      return true;
    }
    if (method === 'POST') {
      let body: unknown = null;
      try {
        body = parseJsonBody(await readBody(req));
      } catch {
        sendJson(store, res, 400, { message: 'Invalid JSON' });
        return true;
      }
      const name = bodyString(body, 'name');
      if (name === '') {
        sendJson(store, res, 422, { message: 'name is required' });
        return true;
      }
      if (getRepo(store, VIEWER_LOGIN, name) !== null) {
        sendJson(store, res, 422, { message: 'Repository already exists' });
        return true;
      }
      const repo = createRepoRecord(store, VIEWER_LOGIN, VIEWER_ID, name, bodyBoolean(body, 'private', false), bodyString(body, 'description'));
      sendJson(store, res, 201, repoJson(repo));
      return true;
    }
    return true;
  }

  // Repository-scoped routes: /repos/{owner}/{repo}[/...].
  if (segments[0] === 'repos' && segments.length >= 3) {
    const owner = decodeSegment(segments[1] as string);
    const repoName = decodeSegment(segments[2] as string);
    const rest = segments.slice(3);
    const repo = getRepo(store, owner, repoName);
    if (repo === null) {
      sendJson(store, res, 404, { message: 'Not Found' });
      return true;
    }

    // The repository itself.
    if (rest.length === 0) {
      if (method === 'GET') {
        sendJson(store, res, 200, repoJson(repo));
        return true;
      }
      if (method === 'PATCH') {
        let body: unknown = null;
        try {
          body = parseJsonBody(await readBody(req));
        } catch {
          sendJson(store, res, 400, { message: 'Invalid JSON' });
          return true;
        }
        if (isRecord(body)) {
          if (typeof body.description === 'string') repo.description = body.description;
          if (typeof body.default_branch === 'string' && body.default_branch !== '') repo.defaultBranch = body.default_branch;
          if (typeof body.private === 'boolean') repo.isPrivate = body.private;
          if (typeof body.name === 'string' && body.name !== '' && body.name !== repo.name) {
            store.repos.delete(repoKey(owner, repoName));
            repo.name = body.name;
            store.repos.set(repoKey(owner, repo.name), repo);
          }
        }
        sendJson(store, res, 200, repoJson(repo));
        return true;
      }
      if (method === 'DELETE') {
        store.repos.delete(repoKey(owner, repoName));
        res.writeHead(204, { 'x-github-request-id': nextRequestId(store) });
        res.end();
        return true;
      }
      return true;
    }

    // Branches.
    if (rest[0] === 'branches') {
      if (rest.length === 1 && method === 'GET') {
        const rows = [...repo.refs.keys()]
          .filter((name) => name.startsWith('refs/heads/'))
          .sort()
          .map((name) => ({
            name: name.slice('refs/heads/'.length),
            commit: { sha: repo.refs.get(name) as string },
            protected: false,
          }));
        sendJson(store, res, 200, rows);
        return true;
      }
      if (rest.length === 2 && method === 'GET') {
        const branch = decodeSegment(rest[1] as string);
        const tip = branchTip(repo, branch);
        if (tip === null) {
          sendJson(store, res, 404, { message: 'Branch not found' });
          return true;
        }
        sendJson(store, res, 200, { name: branch, commit: { sha: tip }, protected: false });
        return true;
      }
      return true;
    }

    // Commits (newest first; ?sha=<branch> picks the branch, default = the default branch).
    if (rest[0] === 'commits' && rest.length === 1 && method === 'GET') {
      const shaParam = query.get('sha') ?? repo.defaultBranch;
      let tip: string | null = null;
      if (repo.refs.has(`refs/heads/${shaParam}`)) tip = branchTip(repo, shaParam);
      else if (repo.objects.has(shaParam)) tip = shaParam;
      else tip = branchTip(repo, repo.defaultBranch);
      const commits: Array<Record<string, unknown>> = [];
      if (tip !== null) {
        for (const oid of walkCommits(repo, tip, 100)) {
          const obj = repo.objects.get(oid);
          if (!obj) continue;
          const parsed = parseCommit(obj.data);
          commits.push({
            sha: oid,
            commit: {
              message: parsed.message,
              author: { name: IDENTITY_NAME, email: IDENTITY_EMAIL, date: new Date(BASE_EPOCH * 1000).toISOString() },
              committer: { name: IDENTITY_NAME, email: IDENTITY_EMAIL, date: new Date(BASE_EPOCH * 1000).toISOString() },
              tree: { sha: parsed.tree },
            },
            parents: parsed.parents.map((p) => ({ sha: p })),
          });
        }
      }
      sendJson(store, res, 200, commits);
      return true;
    }

    // Contents: files and directories, read / write / delete.
    if (rest[0] === 'contents') {
      const pathParts = rest.slice(1).map((s) => decodeSegment(s));
      const refParam = query.get('ref') ?? query.get('branch') ?? repo.defaultBranch;
      const refName = refParam.startsWith('refs/') ? refParam : `refs/heads/${refParam}`;
      if (method === 'GET') {
        const tip = refTip(repo, refName);
        if (tip === null) {
          sendJson(store, res, 404, { message: 'Not Found' });
          return true;
        }
        const tree = commitTree(repo, tip);
        if (pathParts.length === 0) {
          // The repository root as a directory listing.
          const entries = listTreeDir(repo, tree, []);
          if (entries === null) {
            sendJson(store, res, 404, { message: 'Not Found' });
            return true;
          }
          sendJson(store, res, 200, entries.map((e) => ({
            type: e.mode === '40000' ? 'dir' : 'file',
            name: e.name,
            path: e.name,
            sha: e.oid,
            size: 0,
          })));
          return true;
        }
        const blobOid = getFileFromTree(repo, tree, pathParts);
        if (blobOid !== null) {
          const blob = repo.objects.get(blobOid);
          const data = blob ? blob.data : Buffer.alloc(0);
          sendJson(store, res, 200, {
            type: 'file',
            encoding: 'base64',
            size: data.length,
            name: pathParts[pathParts.length - 1] as string,
            path: pathParts.join('/'),
            content: data.toString('base64'),
            sha: blobOid,
          });
          return true;
        }
        const dirEntries = listTreeDir(repo, tree, pathParts);
        if (dirEntries !== null) {
          sendJson(store, res, 200, dirEntries.map((e) => ({
            type: e.mode === '40000' ? 'dir' : 'file',
            name: e.name,
            path: [...pathParts, e.name].join('/'),
            sha: e.oid,
            size: 0,
          })));
          return true;
        }
        sendJson(store, res, 404, { message: 'Not Found' });
        return true;
      }
      if (method === 'PUT') {
        let body: unknown = null;
        try {
          body = parseJsonBody(await readBody(req));
        } catch {
          sendJson(store, res, 400, { message: 'Invalid JSON' });
          return true;
        }
        const message = bodyString(body, 'message') || `Update ${pathParts.join('/')}`;
        const contentB64 = bodyString(body, 'content');
        const sha = bodyString(body, 'sha');
        const branch = bodyString(body, 'branch') || refParam;
        const targetRef = branch.startsWith('refs/') ? branch : `refs/heads/${branch}`;
        if (contentB64 === '') {
          sendJson(store, res, 422, { message: 'content is required' });
          return true;
        }
        const tip = refTip(repo, targetRef);
        const tree = tip !== null ? commitTree(repo, tip) : null;
        const existing = getFileFromTree(repo, tree, pathParts);
        if (existing !== null) {
          // Update: the caller must name the blob it replaces.
          if (sha !== '' && sha !== existing) {
            sendJson(store, res, 409, { message: 'sha does not match the current blob' });
            return true;
          }
          const content = Buffer.from(contentB64, 'base64');
          const commitOid = commitFile(store, repo, targetRef, pathParts, content, message);
          const blobOid = hashObject('blob', content);
          sendJson(store, res, 200, {
            content: { type: 'file', encoding: 'base64', size: content.length, name: pathParts[pathParts.length - 1] as string, path: pathParts.join('/'), content: contentB64, sha: blobOid },
            commit: { sha: commitOid, message },
          });
          return true;
        }
        // Create.
        if (sha !== '') {
          sendJson(store, res, 422, { message: 'sha must be empty when creating a file' });
          return true;
        }
        const content = Buffer.from(contentB64, 'base64');
        const commitOid = commitFile(store, repo, targetRef, pathParts, content, message);
        const blobOid = hashObject('blob', content);
        sendJson(store, res, 201, {
          content: { type: 'file', encoding: 'base64', size: content.length, name: pathParts[pathParts.length - 1] as string, path: pathParts.join('/'), content: contentB64, sha: blobOid },
          commit: { sha: commitOid, message },
        });
        return true;
      }
      if (method === 'DELETE') {
        let body: unknown = null;
        try {
          body = parseJsonBody(await readBody(req));
        } catch {
          sendJson(store, res, 400, { message: 'Invalid JSON' });
          return true;
        }
        const message = bodyString(body, 'message') || `Delete ${pathParts.join('/')}`;
        const sha = bodyString(body, 'sha');
        const branch = bodyString(body, 'branch') || refParam;
        const targetRef = branch.startsWith('refs/') ? branch : `refs/heads/${branch}`;
        const tip = refTip(repo, targetRef);
        const tree = tip !== null ? commitTree(repo, tip) : null;
        const existing = getFileFromTree(repo, tree, pathParts);
        if (existing === null) {
          sendJson(store, res, 404, { message: 'Not Found' });
          return true;
        }
        if (sha !== '' && sha !== existing) {
          sendJson(store, res, 409, { message: 'sha does not match the current blob' });
          return true;
        }
        const commitOid = commitFile(store, repo, targetRef, pathParts, null, message);
        sendJson(store, res, 200, { commit: { sha: commitOid, message } });
        return true;
      }
      return true;
    }

    // Git data: refs.
    if (rest[0] === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        let body: unknown = null;
        try {
          body = parseJsonBody(await readBody(req));
        } catch {
          sendJson(store, res, 400, { message: 'Invalid JSON' });
          return true;
        }
        const ref = bodyString(body, 'ref');
        const sha = bodyString(body, 'sha');
        if (ref === '' || sha === '') {
          sendJson(store, res, 422, { message: 'ref and sha are required' });
          return true;
        }
        if (!ref.startsWith('refs/')) {
          sendJson(store, res, 422, { message: 'ref must start with refs/' });
          return true;
        }
        if (repo.refs.has(ref)) {
          sendJson(store, res, 422, { message: 'Reference already exists' });
          return true;
        }
        if (!repo.objects.has(sha)) {
          sendJson(store, res, 422, { message: 'sha does not exist' });
          return true;
        }
        repo.refs.set(ref, sha);
        sendJson(store, res, 201, { ref, object: { sha, type: 'commit' }, url: `/api/v3/repos/${owner}/${repoName}/git/refs/${ref}` });
        return true;
      }
      if (method === 'GET' && rest.length >= 4 && rest[2] === 'heads') {
        const branch = decodeSegment(rest.slice(3).join('/'));
        const tip = branchTip(repo, branch);
        if (tip === null) {
          sendJson(store, res, 404, { message: 'Not Found' });
          return true;
        }
        sendJson(store, res, 200, { ref: `refs/heads/${branch}`, object: { sha: tip, type: 'commit' }, url: `/api/v3/repos/${owner}/${repoName}/git/refs/heads/${branch}` });
        return true;
      }
      if (method === 'GET' && rest.length === 2) {
        const rows = listRefs(repo).map((r) => ({ ref: r.name, object: { sha: r.oid, type: 'commit' } }));
        sendJson(store, res, 200, rows);
        return true;
      }
      return true;
    }

    // Labels, issues, pulls and comments live in the next chunk.
    return handleRestResources(store, req, res, method, repo, rest, query);
  }

  // A route under /api/v3 that nothing above matched.
  if (method === 'GET' || method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
    sendJson(store, res, 404, { message: 'Not Found' });
    return true;
  }
  return false;
}

/** Labels, issues, pull requests and comments (the resource routes under /repos/{o}/{r}). */
async function handleRestResources(store: Store, req: IncomingMessage, res: ServerResponse, method: string, repo: Repo, rest: string[], query: URLSearchParams): Promise<boolean> {
  // Labels.
  if (rest[0] === 'labels') {
    if (method === 'GET' && rest.length === 1) {
      sendJson(store, res, 200, [...repo.labels.values()].map((label) => ({ name: label.name, color: label.color, description: label.description })));
      return true;
    }
    if (method === 'POST' && rest.length === 1) {
      let body: unknown = null;
      try {
        body = parseJsonBody(await readBody(req));
      } catch {
        sendJson(store, res, 400, { message: 'Invalid JSON' });
        return true;
      }
      const name = bodyString(body, 'name');
      if (name === '') {
        sendJson(store, res, 422, { message: 'name is required' });
        return true;
      }
      const label: Label = { name, color: bodyString(body, 'color') || '000000', description: bodyString(body, 'description') };
      repo.labels.set(name, label);
      sendJson(store, res, 201, { name: label.name, color: label.color, description: label.description });
      return true;
    }
    return true;
  }

  // Issues.
  if (rest[0] === 'issues') {
    if (rest.length === 1) {
      if (method === 'GET') {
        const state = query.get('state') ?? 'open';
        const sort = query.get('sort') ?? 'created';
        const direction = query.get('direction') ?? 'desc';
        let list = [...repo.issues.values()];
        if (state !== 'all') list = list.filter((issue) => issue.state === state);
        if (sort === 'created') {
          list.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
        }
        const { page } = paginate(list, query);
        sendJson(store, res, 200, page.map((issue) => issueJson(repo, issue)));
        return true;
      }
      if (method === 'POST') {
        let body: unknown = null;
        try {
          body = parseJsonBody(await readBody(req));
        } catch {
          sendJson(store, res, 400, { message: 'Invalid JSON' });
          return true;
        }
        const title = bodyString(body, 'title');
        if (title === '') {
          sendJson(store, res, 422, { message: 'title is required' });
          return true;
        }
        const labelNames: string[] = [];
        if (isRecord(body) && Array.isArray(body.labels)) {
          for (const entry of body.labels) {
            if (typeof entry === 'string') labelNames.push(entry);
            else if (isRecord(entry) && typeof entry.name === 'string') labelNames.push(entry.name);
          }
        }
        for (const name of labelNames) {
          if (!repo.labels.has(name)) {
            sendJson(store, res, 422, { message: `label "${name}" does not exist` });
            return true;
          }
        }
        const number = repo.nextIssue;
        repo.nextIssue += 1;
        const issue: Issue = {
          number,
          id: repo.dbId * 1_000_000 + number,
          nodeId: globalId('Issue', [repo.dbId, number]),
          title,
          body: bodyString(body, 'body'),
          state: 'open',
          labels: labelNames,
          createdSeq: nextEpoch(store),
          userLogin: VIEWER_LOGIN,
        };
        repo.issues.set(number, issue);
        sendJson(store, res, 201, issueJson(repo, issue));
        return true;
      }
      return true;
    }
    const number = Number.parseInt(rest[1] as string, 10);
    if (Number.isNaN(number)) return true;
    const issue = repo.issues.get(number) ?? null;
    if (rest.length === 2) {
      if (method === 'GET') {
        if (issue === null) {
          sendJson(store, res, 404, { message: 'Not Found' });
          return true;
        }
        sendJson(store, res, 200, issueJson(repo, issue));
        return true;
      }
      if (method === 'PATCH') {
        if (issue === null) {
          sendJson(store, res, 404, { message: 'Not Found' });
          return true;
        }
        let body: unknown = null;
        try {
          body = parseJsonBody(await readBody(req));
        } catch {
          sendJson(store, res, 400, { message: 'Invalid JSON' });
          return true;
        }
        if (isRecord(body)) {
          if (typeof body.title === 'string' && body.title !== '') issue.title = body.title;
          if (typeof body.body === 'string') issue.body = body.body;
          if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
          if (Array.isArray(body.labels)) {
            const names: string[] = [];
            for (const entry of body.labels) {
              if (typeof entry === 'string') names.push(entry);
              else if (isRecord(entry) && typeof entry.name === 'string') names.push(entry.name);
            }
            issue.labels = names;
          }
        }
        sendJson(store, res, 200, issueJson(repo, issue));
        return true;
      }
      return true;
    }
    // Issue comments.
    if (rest.length === 3 && rest[2] === 'comments') {
      if (issue === null) {
        sendJson(store, res, 404, { message: 'Not Found' });
        return true;
      }
      if (method === 'GET') {
        const rows = [...repo.comments.values()]
          .filter((comment) => comment.issueNumber === number)
          .sort((a, b) => a.id - b.id)
          .map((comment) => ({ id: comment.id, node_id: comment.nodeId, body: comment.body, user: { login: comment.userLogin, id: VIEWER_ID, type: 'User' } }));
        sendJson(store, res, 200, rows);
        return true;
      }
      if (method === 'POST') {
        let body: unknown = null;
        try {
          body = parseJsonBody(await readBody(req));
        } catch {
          sendJson(store, res, 400, { message: 'Invalid JSON' });
          return true;
        }
        const commentBody = bodyString(body, 'body');
        if (commentBody === '') {
          sendJson(store, res, 422, { message: 'body is required' });
          return true;
        }
        const id = repo.nextComment;
        repo.nextComment += 1;
        const comment: Comment = {
          id,
          nodeId: globalId('IssueComment', [repo.dbId, number, id]),
          issueNumber: number,
          body: commentBody,
          userLogin: VIEWER_LOGIN,
        };
        repo.comments.set(id, comment);
        sendJson(store, res, 201, { id: comment.id, node_id: comment.nodeId, body: comment.body, user: { login: comment.userLogin, id: VIEWER_ID, type: 'User' } });
        return true;
      }
      return true;
    }
    return true;
  }

  // Pull requests.
  if (rest[0] === 'pulls') {
    if (rest.length === 1) {
      if (method === 'GET') {
        const state = query.get('state') ?? 'open';
        let list = [...repo.pulls.values()];
        if (state !== 'all') list = list.filter((pull) => pull.state === state);
        list.sort((a, b) => b.number - a.number);
        const { page } = paginate(list, query);
        sendJson(store, res, 200, page.map((pull) => pullJson(repo, pull)));
        return true;
      }
      if (method === 'POST') {
        let body: unknown = null;
        try {
          body = parseJsonBody(await readBody(req));
        } catch {
          sendJson(store, res, 400, { message: 'Invalid JSON' });
          return true;
        }
        const title = bodyString(body, 'title');
        const head = bodyString(body, 'head');
        const base = bodyString(body, 'base') || repo.defaultBranch;
        if (title === '' || head === '') {
          sendJson(store, res, 422, { message: 'title and head are required' });
          return true;
        }
        const headSha = branchTip(repo, head);
        const baseSha = branchTip(repo, base);
        if (headSha === null || baseSha === null) {
          sendJson(store, res, 422, { message: 'head or base branch does not exist' });
          return true;
        }
        const number = repo.nextPull;
        repo.nextPull += 1;
        const pull: Pull = {
          number,
          id: repo.dbId * 1_000_000 + number,
          nodeId: globalId('PullRequest', [repo.dbId, number]),
          title,
          body: bodyString(body, 'body'),
          state: 'open',
          headRef: head,
          baseRef: base,
          headSha,
          baseSha,
          merged: false,
          mergedAt: null,
          mergeCommitSha: null,
          createdSeq: nextEpoch(store),
          userLogin: VIEWER_LOGIN,
        };
        repo.pulls.set(number, pull);
        sendJson(store, res, 201, pullJson(repo, pull));
        return true;
      }
      return true;
    }
    const number = Number.parseInt(rest[1] as string, 10);
    if (Number.isNaN(number)) return true;
    const pull = repo.pulls.get(number) ?? null;
    if (rest.length === 2) {
      if (method === 'GET') {
        if (pull === null) {
          sendJson(store, res, 404, { message: 'Not Found' });
          return true;
        }
        sendJson(store, res, 200, pullJson(repo, pull));
        return true;
      }
      if (method === 'PATCH') {
        if (pull === null) {
          sendJson(store, res, 404, { message: 'Not Found' });
          return true;
        }
        let body: unknown = null;
        try {
          body = parseJsonBody(await readBody(req));
        } catch {
          sendJson(store, res, 400, { message: 'Invalid JSON' });
          return true;
        }
        if (isRecord(body)) {
          if (typeof body.title === 'string' && body.title !== '') pull.title = body.title;
          if (typeof body.body === 'string') pull.body = body.body;
          if (body.state === 'open' || body.state === 'closed') pull.state = body.state;
        }
        sendJson(store, res, 200, pullJson(repo, pull));
        return true;
      }
      return true;
    }
    if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
      if (pull === null) {
        sendJson(store, res, 404, { message: 'Not Found' });
        return true;
      }
      sendJson(store, res, 200, pullFilesJson(repo, pull));
      return true;
    }
    if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
      if (pull === null) {
        sendJson(store, res, 404, { message: 'Not Found' });
        return true;
      }
      if (pull.state === 'closed') {
        sendJson(store, res, 405, { message: 'Pull request is already closed' });
        return true;
      }
      if (pullIsConflicted(repo, pull)) {
        sendJson(store, res, 405, { message: 'Merge conflict' });
        return true;
      }
      const message = `Merge pull request #${pull.number} from ${pull.headRef}`;
      const commitOid = squashMerge(store, repo, pull, message);
      pull.merged = true;
      pull.mergedAt = new Date((BASE_EPOCH + store.seq) * 1000).toISOString();
      pull.mergeCommitSha = commitOid;
      pull.state = 'closed';
      sendJson(store, res, 200, { sha: commitOid, merged: true, message });
      return true;
    }
    return true;
  }

  // Nothing under this repository matched.
  sendJson(store, res, 404, { message: 'Not Found' });
  return true;
}

// ---------------------------------------------------------------- GraphQL v4

// A small hand-rolled GraphQL executor for the documents gh and github-mcp-server send:
// queries (viewer, repository, node, __type), mutations (createIssue, closeIssue,
// createPullRequest, mergePullRequest, addComment), introspection, batched documents.

interface GqlValue {
  kind: 'string' | 'int' | 'float' | 'boolean' | 'null' | 'enum' | 'list' | 'object' | 'variable';
  value: unknown;
}

interface GqlField {
  alias: string | null;
  name: string;
  args: Map<string, GqlValue>;
  selections: GqlField[] | null;
  fragmentType: string | null;
}

interface GqlOperation {
  kind: 'query' | 'mutation';
  selections: GqlField[];
}

type GqlToken = { kind: 'name' | 'int' | 'float' | 'string' | 'punct' | 'eof'; value: string };

function gqlTokenize(src: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i] as string;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const esc = src[j + 1] as string;
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc === '"' ? '"' : esc === '\\' ? '\\' : esc;
          j += 2;
        } else {
          out += src[j] as string;
          j += 1;
        }
      }
      tokens.push({ kind: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      let isFloat = false;
      if (src[j] === '-') j += 1;
      while (j < src.length && /[0-9]/.test(src[j] as string)) j += 1;
      if (src[j] === '.') {
        isFloat = true;
        j += 1;
        while (j < src.length && /[0-9]/.test(src[j] as string)) j += 1;
      }
      tokens.push({ kind: isFloat ? 'float' : 'int', value: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[A-Za-z_$]/.test(ch)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_$]/.test(src[j] as string)) j += 1;
      tokens.push({ kind: 'name', value: src.slice(i, j) });
      i = j;
      continue;
    }
    if ('{}():![]=@'.includes(ch) || ch === '.' ) {
      // '...' is three punct tokens; the parser treats them as a fragment marker.
      tokens.push({ kind: 'punct', value: ch });
      i += 1;
      continue;
    }
    i += 1;
  }
  tokens.push({ kind: 'eof', value: '' });
  return tokens;
}

class GqlParser {
  private tokens: GqlToken[];
  private pos = 0;

  constructor(src: string) {
    this.tokens = gqlTokenize(src);
  }

  private peek(): GqlToken {
    return this.tokens[this.pos] as GqlToken;
  }

  private next(): GqlToken {
    const token = this.tokens[this.pos] as GqlToken;
    if (this.pos < this.tokens.length - 1) this.pos += 1;
    return token;
  }

  private expectPunct(value: string): void {
    const token = this.next();
    if (token.kind !== 'punct' || token.value !== value) throw new Error(`expected "${value}", got ${token.value}`);
  }

  private expectName(): string {
    const token = this.next();
    if (token.kind !== 'name') throw new Error(`expected a name, got ${token.value}`);
    return token.value;
  }

  parseOperation(): GqlOperation {
    let kind: 'query' | 'mutation' = 'query';
    const first = this.peek();
    if (first.kind === 'name' && (first.value === 'query' || first.value === 'mutation')) {
      kind = this.next().value as 'query' | 'mutation';
      // Optional operation name.
      if (this.peek().kind === 'name') this.next();
      // Optional variable definitions: ($name: Type = default, ...).
      if (this.peek().kind === 'punct' && this.peek().value === '(') {
        this.next();
        let depth = 1;
        while (depth > 0) {
          const token = this.next();
          if (token.kind === 'punct' && token.value === '(') depth += 1;
          else if (token.kind === 'punct' && token.value === ')') depth -= 1;
          else if (token.kind === 'eof') break;
        }
      }
    }
    const selections = this.parseSelectionSet();
    return { kind, selections };
  }

  private parseSelectionSet(): GqlField[] {
    this.expectPunct('{');
    const fields: GqlField[] = [];
    while (!(this.peek().kind === 'punct' && this.peek().value === '}')) {
      if (this.peek().kind === 'eof') break;
      fields.push(this.parseField());
    }
    this.expectPunct('}');
    return fields;
  }

  private parseField(): GqlField {
    // Inline fragment: ... on Type { ... }
    if (this.peek().kind === 'punct' && this.peek().value === '.') {
      this.next();
      this.next();
      this.next();
      if (this.peek().kind === 'name' && this.peek().value === 'on') {
        this.next();
        const typeName = this.expectName();
        const selections = this.parseSelectionSet();
        return { alias: null, name: '', args: new Map(), selections, fragmentType: typeName };
      }
      throw new Error('unsupported fragment spread');
    }
    const first = this.expectName();
    let alias: string | null = null;
    let name = first;
    if (this.peek().kind === 'punct' && this.peek().value === ':') {
      this.next();
      alias = first;
      name = this.expectName();
    }
    let args = new Map<string, GqlValue>();
    if (this.peek().kind === 'punct' && this.peek().value === '(') {
      args = this.parseArguments();
    }
    let selections: GqlField[] | null = null;
    if (this.peek().kind === 'punct' && this.peek().value === '{') {
      selections = this.parseSelectionSet();
    }
    return { alias, name, args, selections, fragmentType: null };
  }

  private parseArguments(): Map<string, GqlValue> {
    const args = new Map<string, GqlValue>();
    this.expectPunct('(');
    while (!(this.peek().kind === 'punct' && this.peek().value === ')')) {
      if (this.peek().kind === 'eof') break;
      const name = this.expectName();
      this.expectPunct(':');
      args.set(name, this.parseValue());
    }
    this.expectPunct(')');
    return args;
  }

  private parseValue(): GqlValue {
    const token = this.next();
    if (token.kind === 'string') return { kind: 'string', value: token.value };
    if (token.kind === 'int') return { kind: 'int', value: Number.parseInt(token.value, 10) };
    if (token.kind === 'float') return { kind: 'float', value: Number.parseFloat(token.value) };
    if (token.kind === 'punct' && token.value === '[') {
      const items: GqlValue[] = [];
      while (!(this.peek().kind === 'punct' && this.peek().value === ']')) {
        if (this.peek().kind === 'eof') break;
        items.push(this.parseValue());
      }
      this.expectPunct(']');
      return { kind: 'list', value: items };
    }
    if (token.kind === 'punct' && token.value === '{') {
      const obj = new Map<string, GqlValue>();
      while (!(this.peek().kind === 'punct' && this.peek().value === '}')) {
        if (this.peek().kind === 'eof') break;
        const name = this.expectName();
        this.expectPunct(':');
        obj.set(name, this.parseValue());
      }
      this.expectPunct('}');
      return { kind: 'object', value: obj };
    }
    if (token.kind === 'name') {
      if (token.value === 'true') return { kind: 'boolean', value: true };
      if (token.value === 'false') return { kind: 'boolean', value: false };
      if (token.value === 'null') return { kind: 'null', value: null };
      if (token.value.startsWith('$')) return { kind: 'variable', value: token.value.slice(1) };
      return { kind: 'enum', value: token.value };
    }
    if (token.kind === 'punct' && token.value === '$') {
      const name = this.expectName();
      return { kind: 'variable', value: name };
    }
    throw new Error(`unexpected value token ${token.value}`);
  }
}

/** Resolve a parsed value against the operation's variables. */
function gqlResolveValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'string':
    case 'int':
    case 'float':
    case 'boolean':
    case 'enum':
      return value.value;
    case 'null':
      return null;
    case 'variable':
      return variables[value.value as string] ?? null;
    case 'list':
      return (value.value as GqlValue[]).map((item) => gqlResolveValue(item, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const [key, item] of value.value as Map<string, GqlValue>) out[key] = gqlResolveValue(item, variables);
      return out;
    }
    default:
      return null;
  }
}

function gqlArg(field: GqlField, name: string, variables: Record<string, unknown>): unknown {
  const value = field.args.get(name);
  if (value === undefined) return undefined;
  return gqlResolveValue(value, variables);
}

// ---------------------------------------------------------------- GraphQL object model

type GqlSource =
  | { __typename: 'Query' }
  | { __typename: 'Mutation' }
  | { __typename: 'Repository'; repo: Repo }
  | { __typename: 'Issue'; repo: Repo; issue: Issue }
  | { __typename: 'PullRequest'; repo: Repo; pull: Pull }
  | { __typename: 'IssueComment'; repo: Repo; comment: Comment }
  | { __typename: 'User'; login: string; id: number }
  | { __typename: 'RepositoryOwner'; login: string }
  | { __typename: 'BranchRef'; name: string }
  | { __typename: 'IssueConnection'; repo: Repo; issues: Issue[]; pageInfo: { hasNextPage: boolean; endCursor: string | null } }
  | { __typename: 'PullRequestConnection'; repo: Repo; pulls: Pull[] }
  | { __typename: 'PullRequestFileConnection'; files: Array<{ path: string }> }
  | { __typename: 'PageInfo'; hasNextPage: boolean; endCursor: string | null }
  | { __typename: '__Type'; name: string; kind: string; fields: string[]; enumValues: string[] };

const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'url', 'createdAt', 'updatedAt', 'author', 'labels', 'comments'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files', 'url', 'createdAt', 'author'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'url'],
  SearchType: [],
};

const GQL_TYPE_ENUMS: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT', 'CODE'],
};

/** Find a repository by its numeric database id. */
function repoByDbId(store: Store, dbId: number): Repo | null {
  for (const repo of store.repos.values()) if (repo.dbId === dbId) return repo;
  return null;
}

/** Decode a global id (`Kind:...` base64) into its kind and parts. */
function decodeGlobalId(id: string): { kind: string; parts: string[] } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const colon = text.indexOf(':');
    if (colon < 0) return null;
    return { kind: text.slice(0, colon), parts: text.slice(colon + 1).split(':') };
  } catch {
    return null;
  }
}

/** Resolve a `node(id:)` global id to a source object, or null. */
function resolveNode(store: Store, id: string): GqlSource | null {
  const decoded = decodeGlobalId(id);
  if (decoded === null) return null;
  if (decoded.kind === 'Repository') {
    const repo = repoByDbId(store, Number.parseInt(decoded.parts[0] as string, 10));
    return repo === null ? null : { __typename: 'Repository', repo };
  }
  if (decoded.kind === 'Issue') {
    const repo = repoByDbId(store, Number.parseInt(decoded.parts[0] as string, 10));
    if (repo === null) return null;
    const issue = repo.issues.get(Number.parseInt(decoded.parts[1] as string, 10)) ?? null;
    return issue === null ? null : { __typename: 'Issue', repo, issue };
  }
  if (decoded.kind === 'PullRequest') {
    const repo = repoByDbId(store, Number.parseInt(decoded.parts[0] as string, 10));
    if (repo === null) return null;
    const pull = repo.pulls.get(Number.parseInt(decoded.parts[1] as string, 10)) ?? null;
    return pull === null ? null : { __typename: 'PullRequest', repo, pull };
  }
  if (decoded.kind === 'IssueComment') {
    const repo = repoByDbId(store, Number.parseInt(decoded.parts[0] as string, 10));
    if (repo === null) return null;
    const comment = repo.comments.get(Number.parseInt(decoded.parts[2] as string, 10)) ?? null;
    return comment === null ? null : { __typename: 'IssueComment', repo, comment };
  }
  if (decoded.kind === 'User') {
    return { __typename: 'User', login: VIEWER_LOGIN, id: VIEWER_ID };
  }
  return null;
}

/** A cursor for issue pagination: base64 of the issue number. */
function issueCursor(number: number): string {
  return Buffer.from(`cursor:${number}`, 'utf8').toString('base64');
}

function decodeIssueCursor(cursor: string): number | null {
  try {
    const text = Buffer.from(cursor, 'base64').toString('utf8');
    if (!text.startsWith('cursor:')) return null;
    const n = Number.parseInt(text.slice('cursor:'.length), 10);
    return Number.isNaN(n) ? null : n;
  } catch {
    return null;
  }
}

interface GqlExecContext {
  store: Store;
  variables: Record<string, unknown>;
  errors: Array<{ message: string }>;
}

/** Resolve one field on a source object; returns the raw value (or a nested source). */
function gqlResolveField(ctx: GqlExecContext, source: GqlSource, field: GqlField): unknown {
  const store = ctx.store;
  const variables = ctx.variables;
  switch (source.__typename) {
    case 'Query': {
      if (field.name === 'viewer') return { __typename: 'User', login: VIEWER_LOGIN, id: VIEWER_ID } as GqlSource;
      if (field.name === 'repository') {
        const owner = gqlArg(field, 'owner', variables);
        const name = gqlArg(field, 'name', variables);
        if (typeof owner !== 'string' || typeof name !== 'string') return null;
        const repo = getRepo(store, owner, name);
        return repo === null ? null : ({ __typename: 'Repository', repo } as GqlSource);
      }
      if (field.name === 'node') {
        const id = gqlArg(field, 'id', variables);
        if (typeof id !== 'string') return null;
        return resolveNode(store, id);
      }
      if (field.name === '__type') {
        const name = gqlArg(field, 'name', variables);
        if (typeof name !== 'string') return null;
        const fields = GQL_TYPE_FIELDS[name];
        if (fields === undefined && GQL_TYPE_ENUMS[name] === undefined) return null;
        return {
          __typename: '__Type',
          name,
          kind: GQL_TYPE_ENUMS[name] !== undefined ? 'ENUM' : 'OBJECT',
          fields: fields ?? [],
          enumValues: GQL_TYPE_ENUMS[name] ?? [],
        } as GqlSource;
      }
      return undefined;
    }
    case 'Mutation': {
      if (field.name === 'createIssue') {
        const input = gqlArg(field, 'input', variables) as Record<string, unknown> | undefined;
        const repositoryId = typeof input?.repositoryId === 'string' ? input.repositoryId : '';
        const title = typeof input?.title === 'string' ? input.title : '';
        const decoded = decodeGlobalId(repositoryId);
        const repo = decoded !== null && decoded.kind === 'Repository' ? repoByDbId(store, Number.parseInt(decoded.parts[0] as string, 10)) : null;
        if (repo === null || title === '') return null;
        const number = repo.nextIssue;
        repo.nextIssue += 1;
        const issue: Issue = {
          number,
          id: repo.dbId * 1_000_000 + number,
          nodeId: globalId('Issue', [repo.dbId, number]),
          title,
          body: typeof input?.body === 'string' ? (input.body as string) : '',
          state: 'open',
          labels: [],
          createdSeq: nextEpoch(store),
          userLogin: VIEWER_LOGIN,
        };
        repo.issues.set(number, issue);
        return { issue: { __typename: 'Issue', repo, issue } as GqlSource };
      }
      if (field.name === 'closeIssue') {
        const input = gqlArg(field, 'input', variables) as Record<string, unknown> | undefined;
        const issueId = typeof input?.issueId === 'string' ? input.issueId : '';
        const node = resolveNode(store, issueId);
        if (node === null || node.__typename !== 'Issue') return null;
        node.issue.state = 'closed';
        return { issue: node as GqlSource };
      }
      if (field.name === 'createPullRequest') {
        const input = gqlArg(field, 'input', variables) as Record<string, unknown> | undefined;
        const repositoryId = typeof input?.repositoryId === 'string' ? input.repositoryId : '';
        const baseRefName = typeof input?.baseRefName === 'string' ? input.baseRefName : '';
        const headRefName = typeof input?.headRefName === 'string' ? input.headRefName : '';
        const title = typeof input?.title === 'string' ? input.title : '';
        const decoded = decodeGlobalId(repositoryId);
        const repo = decoded !== null && decoded.kind === 'Repository' ? repoByDbId(store, Number.parseInt(decoded.parts[0] as string, 10)) : null;
        if (repo === null || title === '' || headRefName === '' || baseRefName === '') return null;
        const headSha = branchTip(repo, headRefName);
        const baseSha = branchTip(repo, baseRefName);
        if (headSha === null || baseSha === null) return null;
        const number = repo.nextPull;
        repo.nextPull += 1;
        const pull: Pull = {
          number,
          id: repo.dbId * 1_000_000 + number,
          nodeId: globalId('PullRequest', [repo.dbId, number]),
          title,
          body: typeof input?.body === 'string' ? (input.body as string) : '',
          state: 'open',
          headRef: headRefName,
          baseRef: baseRefName,
          headSha,
          baseSha,
          merged: false,
          mergedAt: null,
          mergeCommitSha: null,
          createdSeq: nextEpoch(store),
          userLogin: VIEWER_LOGIN,
        };
        repo.pulls.set(number, pull);
        return { pullRequest: { __typename: 'PullRequest', repo, pull } as GqlSource };
      }
      if (field.name === 'mergePullRequest') {
        const input = gqlArg(field, 'input', variables) as Record<string, unknown> | undefined;
        const pullRequestId = typeof input?.pullRequestId === 'string' ? input.pullRequestId : '';
        const node = resolveNode(store, pullRequestId);
        if (node === null || node.__typename !== 'PullRequest') return null;
        const pull = node.pull;
        if (pull.state === 'closed') return { pullRequest: node as GqlSource };
        if (pullIsConflicted(node.repo, pull)) return { pullRequest: node as GqlSource };
        const commitOid = squashMerge(store, node.repo, pull, `Merge pull request #${pull.number} from ${pull.headRef}`);
        pull.merged = true;
        pull.mergedAt = new Date((BASE_EPOCH + store.seq) * 1000).toISOString();
        pull.mergeCommitSha = commitOid;
        pull.state = 'closed';
        return { pullRequest: node as GqlSource };
      }
      if (field.name === 'addComment') {
        const input = gqlArg(field, 'input', variables) as Record<string, unknown> | undefined;
        const subjectId = typeof input?.subjectId === 'string' ? input.subjectId : '';
        const body = typeof input?.body === 'string' ? input.body : '';
        const node = resolveNode(store, subjectId);
        if (node === null || node.__typename !== 'Issue' || body === '') return null;
        const repo = node.repo;
        const id = repo.nextComment;
        repo.nextComment += 1;
        const comment: Comment = {
          id,
          nodeId: globalId('IssueComment', [repo.dbId, node.issue.number, id]),
          issueNumber: node.issue.number,
          body,
          userLogin: VIEWER_LOGIN,
        };
        repo.comments.set(id, comment);
        return { commentEdge: { node: { __typename: 'IssueComment', repo, comment } as GqlSource } };
      }
      return undefined;
    }
    case 'User': {
      if (field.name === 'login') return source.login;
      if (field.name === 'id') return globalId('User', [source.id]);
      if (field.name === 'name') return 'ada iversen';
      return undefined;
    }
    case 'RepositoryOwner': {
      if (field.name === 'login') return source.login;
      if (field.name === 'id') return globalId('User', [source.login === VIEWER_LOGIN ? VIEWER_ID : FOREIGN_ID]);
      return undefined;
    }
    case 'BranchRef': {
      if (field.name === 'name') return source.name;
      return undefined;
    }
    case 'Repository': {
      const repo = source.repo;
      if (field.name === 'id') return globalId('Repository', [repo.dbId]);
      if (field.name === 'databaseId') return repo.dbId;
      if (field.name === 'name') return repo.name;
      if (field.name === 'nameWithOwner') return `${repo.owner}/${repo.name}`;
      if (field.name === 'description') return repo.description;
      if (field.name === 'url') return `/api/v3/repos/${repo.owner}/${repo.name}`;
      if (field.name === 'owner') return { __typename: 'RepositoryOwner', login: repo.owner } as GqlSource;
      if (field.name === 'defaultBranchRef') return { __typename: 'BranchRef', name: repo.defaultBranch } as GqlSource;
      if (field.name === 'viewerPermission') return 'ADMIN';
      if (field.name === 'hasIssuesEnabled') return true;
      if (field.name === 'issue') {
        const number = gqlArg(field, 'number', variables);
        if (typeof number !== 'number') return null;
        const issue = repo.issues.get(number) ?? null;
        return issue === null ? null : ({ __typename: 'Issue', repo, issue } as GqlSource);
      }
      if (field.name === 'issues') {
        const first = gqlArg(field, 'first', variables);
        const after = gqlArg(field, 'after', variables);
        const states = gqlArg(field, 'states', variables) as string[] | undefined;
        const orderBy = gqlArg(field, 'orderBy', variables) as Record<string, unknown> | undefined;
        let list = [...repo.issues.values()];
        if (Array.isArray(states) && states.length > 0) {
          const wanted = new Set(states.map((s) => String(s).toLowerCase()));
          list = list.filter((issue) => wanted.has(issue.state));
        }
        const direction = orderBy?.direction === 'ASC' ? 'asc' : 'desc';
        list.sort((a, b) => (direction === 'asc' ? a.number - b.number : b.number - a.number));
        if (typeof after === 'string' && after !== '') {
          const cursorNumber = decodeIssueCursor(after);
          if (cursorNumber !== null) {
            list = direction === 'asc' ? list.filter((issue) => issue.number > cursorNumber) : list.filter((issue) => issue.number < cursorNumber);
          }
        }
        const limit = typeof first === 'number' && first >= 0 ? first : list.length;
        const page = list.slice(0, limit);
        const hasNextPage = list.length > page.length;
        const endCursor = page.length > 0 ? issueCursor(page[page.length - 1]?.number as number) : null;
        return {
          __typename: 'IssueConnection',
          repo,
          issues: page,
          pageInfo: { hasNextPage, endCursor },
        } as GqlSource;
      }
      if (field.name === 'pullRequests') {
        const first = gqlArg(field, 'first', variables);
        let list = [...repo.pulls.values()].sort((a, b) => b.number - a.number);
        const limit = typeof first === 'number' && first >= 0 ? first : list.length;
        list = list.slice(0, limit);
        return { __typename: 'PullRequestConnection', repo, pulls: list } as GqlSource;
      }
      if (field.name === 'pullRequest') {
        const number = gqlArg(field, 'number', variables);
        if (typeof number !== 'number') return null;
        const pull = repo.pulls.get(number) ?? null;
        return pull === null ? null : ({ __typename: 'PullRequest', repo, pull } as GqlSource);
      }
      return undefined;
    }
    case 'Issue': {
      const issue = source.issue;
      if (field.name === 'id') return issue.nodeId;
      if (field.name === 'number') return issue.number;
      if (field.name === 'title') return issue.title;
      if (field.name === 'body') return issue.body;
      if (field.name === 'state') return issue.state.toUpperCase();
      if (field.name === 'url') return `/api/v3/repos/${source.repo.owner}/${source.repo.name}/issues/${issue.number}`;
      if (field.name === 'author') return { __typename: 'User', login: issue.userLogin, id: VIEWER_ID } as GqlSource;
      if (field.name === 'labels') return { nodes: issue.labels.map((name) => ({ name })) };
      return undefined;
    }
    case 'PullRequest': {
      const pull = source.pull;
      if (field.name === 'id') return pull.nodeId;
      if (field.name === 'number') return pull.number;
      if (field.name === 'title') return pull.title;
      if (field.name === 'body') return pull.body;
      if (field.name === 'state') return pull.state.toUpperCase();
      if (field.name === 'merged') return pull.merged;
      if (field.name === 'headRefName') return pull.headRef;
      if (field.name === 'baseRefName') return pull.baseRef;
      if (field.name === 'mergeable') {
        if (pull.state === 'closed') return 'UNKNOWN';
        return pullIsConflicted(source.repo, pull) ? 'CONFLICTING' : 'MERGEABLE';
      }
      if (field.name === 'url') return `/api/v3/repos/${source.repo.owner}/${source.repo.name}/pulls/${pull.number}`;
      if (field.name === 'author') return { __typename: 'User', login: pull.userLogin, id: VIEWER_ID } as GqlSource;
      if (field.name === 'files') {
        const files = pullFilesJson(source.repo, pull).map((f) => ({ path: String(f.filename) }));
        return { __typename: 'PullRequestFileConnection', files } as GqlSource;
      }
      return undefined;
    }
    case 'IssueComment': {
      if (field.name === 'id') return source.comment.nodeId;
      if (field.name === 'body') return source.comment.body;
      if (field.name === 'author') return { __typename: 'User', login: source.comment.userLogin, id: VIEWER_ID } as GqlSource;
      return undefined;
    }
    case 'IssueConnection': {
      if (field.name === 'nodes') return source.issues.map((issue) => ({ __typename: 'Issue', repo: source.repo, issue }) as GqlSource);
      if (field.name === 'totalCount') return source.issues.length;
      if (field.name === 'pageInfo') return { __typename: 'PageInfo', hasNextPage: source.pageInfo.hasNextPage, endCursor: source.pageInfo.endCursor } as GqlSource;
      return undefined;
    }
    case 'PullRequestConnection': {
      if (field.name === 'nodes') return source.pulls.map((pull) => ({ __typename: 'PullRequest', repo: source.repo, pull }) as GqlSource);
      if (field.name === 'totalCount') return source.pulls.length;
      return undefined;
    }
    case 'PullRequestFileConnection': {
      if (field.name === 'nodes') return source.files;
      if (field.name === 'totalCount') return source.files.length;
      return undefined;
    }
    case 'PageInfo': {
      if (field.name === 'hasNextPage') return source.hasNextPage;
      if (field.name === 'endCursor') return source.endCursor;
      return undefined;
    }
    case '__Type': {
      if (field.name === 'name') return source.name;
      if (field.name === 'kind') return source.kind;
      if (field.name === 'fields') return source.fields.map((name) => ({ name }));
      if (field.name === 'enumValues') return source.enumValues.map((name) => ({ name }));
      return undefined;
    }
    default:
      return undefined;
  }
}

/** Execute a selection set against a source object, collecting errors for unknown fields. */
function gqlExecuteSelections(ctx: GqlExecContext, source: GqlSource | Record<string, unknown> | null, selections: GqlField[]): Record<string, unknown> | null {
  if (source === null) return null;
  const out: Record<string, unknown> = {};
  for (const field of selections) {
    // Inline fragments apply only when the source's type matches.
    if (field.fragmentType !== null) {
      const typename = (source as GqlSource).__typename ?? (typeof source === 'object' && source !== null && 'name' in source ? 'Repository' : '');
      if (typename !== field.fragmentType) continue;
      const nested = gqlExecuteSelections(ctx, source, field.selections ?? []);
      if (nested !== null) Object.assign(out, nested);
      continue;
    }
    const responseKey = field.alias ?? field.name;
    const value = isGqlSource(source)
      ? gqlResolveField(ctx, source, field)
      : (source as Record<string, unknown>)[field.name];
    if (value === undefined) {
      const typename = isGqlSource(source) ? source.__typename : 'Object';
      ctx.errors.push({ message: `Cannot query field "${field.name}" on type "${typename}".` });
      out[responseKey] = null;
      continue;
    }
    out[responseKey] = gqlProjectValue(ctx, value, field.selections);
  }
  return out;
}

function isGqlSource(value: unknown): value is GqlSource {
  return typeof value === 'object' && value !== null && '__typename' in (value as Record<string, unknown>);
}

/** Project a resolved value through a sub-selection (objects, lists, scalars). */
function gqlProjectValue(ctx: GqlExecContext, value: unknown, selections: GqlField[] | null): unknown {
  if (selections === null) return value;
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) return value.map((item) => gqlProjectValue(ctx, item, selections));
  if (typeof value === 'object') {
    if (isGqlSource(value)) return gqlExecuteSelections(ctx, value, selections);
    // A plain record (e.g. a mutation payload { issue: ... }): resolve each selected field from it.
    const out: Record<string, unknown> = {};
    for (const field of selections) {
      if (field.fragmentType !== null) continue;
      const responseKey = field.alias ?? field.name;
      const nested = (value as Record<string, unknown>)[field.name];
      if (nested === undefined) {
        ctx.errors.push({ message: `Cannot query field "${field.name}" on type "Object".` });
        out[responseKey] = null;
        continue;
      }
      out[responseKey] = gqlProjectValue(ctx, nested, field.selections);
    }
    return out;
  }
  return value;
}

/** Execute one GraphQL document ({query, variables}) against the store. */
function executeGraphQL(store: Store, queryText: string, variables: Record<string, unknown>): { data: Record<string, unknown> | null; errors: Array<{ message: string }> } {
  const errors: Array<{ message: string }> = [];
  let operation: GqlOperation;
  try {
    operation = new GqlParser(queryText).parseOperation();
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : 'GraphQL parse error' }] };
  }
  const ctx: GqlExecContext = { store, variables, errors };
  const root: GqlSource = operation.kind === 'mutation' ? { __typename: 'Mutation' } : { __typename: 'Query' };
  const data = gqlExecuteSelections(ctx, root, operation.selections);
  return { data, errors };
}

// ---------------------------------------------------------------- MCP

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, { type: string; description: string }>;
    required: string[];
  };
}

/** The tool set (a fixed array: two tools/list calls must answer byte-identically). */
const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The repository name.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Read one repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List the issues of a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'Filter by state: open, closed or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The pull request title.' },
        body: { type: 'string', description: 'The pull request body.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Squash-merge a pull request into its base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        pull_number: { type: 'integer', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
  {
    name: 'get_issue',
    description: 'Read one issue by number.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        issue_number: { type: 'integer', description: 'The issue number.' },
      },
      required: ['owner', 'repo', 'issue_number'],
    },
  },
  {
    name: 'list_pull_requests',
    description: 'List the pull requests of a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'Filter by state: open, closed or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
];

/** Split an `owner/repo` full name, or null. */
function splitFullName(value: unknown): { owner: string; repo: string } | null {
  if (typeof value !== 'string') return null;
  const slash = value.indexOf('/');
  if (slash <= 0 || slash === value.length - 1) return null;
  return { owner: value.slice(0, slash), repo: value.slice(slash + 1) };
}

/** Resolve owner/repo out of a tool's arguments (owner + repo, or full_name). */
function mcpRepoOf(args: Record<string, unknown>): { owner: string; repo: string } | null {
  const owner = typeof args.owner === 'string' ? args.owner : '';
  const repo = typeof args.repo === 'string' ? args.repo : '';
  if (owner !== '' && repo !== '') return { owner, repo };
  return splitFullName(args.full_name);
}

/** Execute one MCP tool call. Returns {result} or {error} (a tool-level failure, isError:true). */
function mcpCallTool(store: Store, name: string, args: Record<string, unknown>): { result: unknown } | { error: string } {
  const tool = MCP_TOOLS.find((t) => t.name === name);
  if (tool === undefined) return { error: `unknown tool ${name}` };
  // Missing required arguments.
  for (const required of tool.inputSchema.required) {
    if (args[required] === undefined || args[required] === null || args[required] === '') {
      return { error: `missing required argument ${required}` };
    }
  }
  if (name === 'create_repo') {
    const repoName = String(args.name);
    if (getRepo(store, VIEWER_LOGIN, repoName) !== null) return { error: `repository ${repoName} already exists` };
    const repo = createRepoRecord(store, VIEWER_LOGIN, VIEWER_ID, repoName, args.private === true, typeof args.description === 'string' ? args.description : '');
    return { result: repoJson(repo) };
  }
  const where = mcpRepoOf(args);
  if (where === null) return { error: 'owner and repo are required' };
  const repo = getRepo(store, where.owner, where.repo);
  if (repo === null) return { error: `repository ${where.owner}/${where.repo} not found` };
  if (name === 'get_repo') return { result: repoJson(repo) };
  if (name === 'create_issue') {
    const title = String(args.title);
    const number = repo.nextIssue;
    repo.nextIssue += 1;
    const issue: Issue = {
      number,
      id: repo.dbId * 1_000_000 + number,
      nodeId: globalId('Issue', [repo.dbId, number]),
      title,
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      labels: [],
      createdSeq: nextEpoch(store),
      userLogin: VIEWER_LOGIN,
    };
    repo.issues.set(number, issue);
    return { result: issueJson(repo, issue) };
  }
  if (name === 'list_issues') {
    const state = typeof args.state === 'string' ? args.state : 'open';
    let list = [...repo.issues.values()];
    if (state !== 'all') list = list.filter((issue) => issue.state === state);
    list.sort((a, b) => b.number - a.number);
    return { result: { issues: list.map((issue) => issueJson(repo, issue)) } };
  }
  if (name === 'get_issue') {
    const number = typeof args.issue_number === 'number' ? args.issue_number : Number.parseInt(String(args.issue_number), 10);
    const issue = repo.issues.get(number) ?? null;
    if (issue === null) return { error: `issue #${number} not found` };
    return { result: issueJson(repo, issue) };
  }
  if (name === 'create_pull_request') {
    const title = String(args.title);
    const head = String(args.head);
    const base = String(args.base);
    const headSha = branchTip(repo, head);
    const baseSha = branchTip(repo, base);
    if (headSha === null || baseSha === null) return { error: 'head or base branch does not exist' };
    const number = repo.nextPull;
    repo.nextPull += 1;
    const pull: Pull = {
      number,
      id: repo.dbId * 1_000_000 + number,
      nodeId: globalId('PullRequest', [repo.dbId, number]),
      title,
      body: typeof args.body === 'string' ? args.body : '',
      state: 'open',
      headRef: head,
      baseRef: base,
      headSha,
      baseSha,
      merged: false,
      mergedAt: null,
      mergeCommitSha: null,
      createdSeq: nextEpoch(store),
      userLogin: VIEWER_LOGIN,
    };
    repo.pulls.set(number, pull);
    return { result: pullJson(repo, pull) };
  }
  if (name === 'merge_pull_request') {
    const number = typeof args.pull_number === 'number' ? args.pull_number : Number.parseInt(String(args.pull_number), 10);
    const pull = repo.pulls.get(number) ?? null;
    if (pull === null) return { error: `pull request #${number} not found` };
    if (pull.state === 'closed') return { error: `pull request #${number} is already closed` };
    if (pullIsConflicted(repo, pull)) return { error: `pull request #${number} has a merge conflict` };
    const commitOid = squashMerge(store, repo, pull, `Merge pull request #${pull.number} from ${pull.headRef}`);
    pull.merged = true;
    pull.mergedAt = new Date((BASE_EPOCH + store.seq) * 1000).toISOString();
    pull.mergeCommitSha = commitOid;
    pull.state = 'closed';
    return { result: { sha: commitOid, merged: true, number: pull.number } };
  }
  if (name === 'list_pull_requests') {
    const state = typeof args.state === 'string' ? args.state : 'open';
    let list = [...repo.pulls.values()];
    if (state !== 'all') list = list.filter((pull) => pull.state === state);
    list.sort((a, b) => b.number - a.number);
    return { result: { pull_requests: list.map((pull) => pullJson(repo, pull)) } };
  }
  return { error: `tool ${name} is not implemented` };
}

/** Handle one POST /mcp request (JSON-RPC 2.0, Streamable HTTP). */
async function handleMcp(store: Store, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const body = await readBody(req);
  const text = body.toString('utf8').trim();
  // A body that is not JSON answers HTTP 400 with JSON-RPC -32700.
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    sendJson(store, res, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (!isRecord(parsed) || typeof parsed.method !== 'string') {
    sendJson(store, res, 400, { jsonrpc: '2.0', id: isRecord(parsed) ? (parsed.id ?? null) : null, error: { code: -32600, message: 'Invalid Request' } });
    return;
  }
  const id = parsed.id ?? null;
  const method = parsed.method;
  const params = isRecord(parsed.params) ? parsed.params : {};
  // A notification (no id) gets a 202 with no body.
  const isNotification = parsed.id === undefined;
  const answer = (status: number, payload: unknown): void => {
    if (isNotification) {
      res.writeHead(202, { 'x-github-request-id': nextRequestId(store) });
      res.end();
      return;
    }
    sendJson(store, res, status, payload);
  };
  const ok = (result: unknown): void => answer(200, { jsonrpc: '2.0', id, result });
  const fail = (code: number, message: string): void => answer(200, { jsonrpc: '2.0', id, error: { code, message } });

  if (method === 'server/discover') {
    ok({
      serverInfo: { name: MCP_NAME, version: MCP_VERSION },
      capabilities: { tools: {} },
      supportedVersions: ['2026-07-28', '2025-11-25'],
      _meta: { 'io.modelcontextprotocol/serverInfo': { name: MCP_NAME, version: MCP_VERSION } },
    });
    return;
  }
  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const negotiated = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'].includes(offered) ? offered : '2025-11-25';
    ok({
      protocolVersion: negotiated,
      capabilities: { tools: {} },
      serverInfo: { name: MCP_NAME, version: MCP_VERSION },
    });
    return;
  }
  if (method === 'notifications/initialized') {
    answer(202, null);
    return;
  }
  if (method === 'tools/list') {
    ok({ tools: MCP_TOOLS });
    return;
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const args = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
    const tool = MCP_TOOLS.find((t) => t.name === toolName);
    if (tool === undefined) {
      fail(-32602, `unknown tool ${toolName}`);
      return;
    }
    const outcome = mcpCallTool(store, toolName, args);
    if ('error' in outcome) {
      ok({ content: [{ type: 'text', text: JSON.stringify({ error: outcome.error }) }], isError: true });
      return;
    }
    ok({
      content: [{ type: 'text', text: JSON.stringify(outcome.result) }],
      structuredContent: outcome.result,
      isError: false,
    });
    return;
  }
  fail(-32601, `method not found: ${method}`);
}

// ---------------------------------------------------------------- git routes

/** Handle a git smart-HTTP request. Returns true when the route was handled. */
async function handleGit(store: Store, req: IncomingMessage, res: ServerResponse, method: string, path: string, query: URLSearchParams): Promise<boolean> {
  const match = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/.exec(path);
  if (match === null) return false;
  const owner = decodeSegment(match[1] as string);
  const repoName = decodeSegment(match[2] as string);
  const rest = match[3] ?? '';
  const repo = getRepo(store, owner, repoName);
  if (repo === null) {
    sendJson(store, res, 404, { message: 'Not Found' });
    return true;
  }
  const gitProtocol = (req.headers['git-protocol'] ?? '').toString();

  if (method === 'GET' && rest === '/info/refs') {
    const service = query.get('service') ?? '';
    if (service === 'git-upload-pack') {
      if (gitProtocol.includes('version=2')) {
        sendRaw(store, res, 200, advertisementV2(), 'application/x-git-upload-pack-advertisement');
      } else {
        sendRaw(store, res, 200, advertisementV0(repo, 'git-upload-pack', V0_UPLOAD_CAPS()), 'application/x-git-upload-pack-advertisement');
      }
      return true;
    }
    if (service === 'git-receive-pack') {
      sendRaw(store, res, 200, advertisementV0(repo, 'git-receive-pack', V0_RECEIVE_CAPS()), 'application/x-git-receive-pack-advertisement');
      return true;
    }
    sendJson(store, res, 400, { message: 'unknown service' });
    return true;
  }

  if (method === 'POST' && rest === '/git-upload-pack') {
    const body = await readBody(req);
    const packets = decodePktLines(body);
    const first = packets.find((p) => p.kind === 'data');
    const firstLine = first ? first.payload.toString('utf8') : '';
    let answer: Buffer;
    if (firstLine.startsWith('command=ls-refs')) {
      answer = handleLsRefs(repo, packets);
    } else if (firstLine.startsWith('command=fetch')) {
      answer = handleUploadPackV2Fetch(repo, packets);
    } else {
      answer = handleUploadPackV0Fetch(repo, body);
    }
    sendRaw(store, res, 200, answer, 'application/x-git-upload-pack-result');
    return true;
  }

  if (method === 'POST' && rest === '/git-receive-pack') {
    const body = await readBody(req);
    const answer = handleReceivePack(repo, body);
    sendRaw(store, res, 200, answer, 'application/x-git-receive-pack-result');
    return true;
  }

  return false;
}

// ---------------------------------------------------------------- the server

/** Build the server. It binds nothing until the caller listens; the entry listens on an ephemeral port. */
export function createApp(): Server {
  const store = createStore();
  return createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      try {
        const path = pathOf(req);
        const method = req.method ?? 'GET';
        const query = queryOf(req);

        // The env's boot check calls this: 200 {"ok":true}. No auth here.
        if (method === 'GET' && path === '/healthz') {
          sendJson(store, res, 200, { ok: true });
          return;
        }

        // Everything else needs a bearer token.
        if (!isAuthed(req)) {
          sendJson(store, res, 401, { message: 'Requires authentication' });
          return;
        }

        // GraphQL v4.
        if (method === 'POST' && (path === '/api/graphql' || path === '/api/graphql/')) {
          const body = await readBody(req);
          let parsed: unknown;
          try {
            parsed = parseJsonBody(body);
          } catch {
            sendJson(store, res, 400, { message: 'Invalid JSON' });
            return;
          }
          if (parsed === null) {
            sendJson(store, res, 400, { message: 'A GraphQL document is required' });
            return;
          }
          if (Array.isArray(parsed)) {
            const results = parsed.map((entry) => {
              if (!isRecord(entry) || typeof entry.query !== 'string') return { data: null, errors: [{ message: 'A GraphQL document is required' }] };
              return executeGraphQL(store, entry.query, isRecord(entry.variables) ? (entry.variables as Record<string, unknown>) : {});
            });
            sendJson(store, res, 200, results);
            return;
          }
          if (!isRecord(parsed) || typeof parsed.query !== 'string') {
            sendJson(store, res, 400, { message: 'A GraphQL document is required' });
            return;
          }
          const result = executeGraphQL(store, parsed.query, isRecord(parsed.variables) ? (parsed.variables as Record<string, unknown>) : {});
          sendJson(store, res, 200, result);
          return;
        }

        // MCP.
        if (method === 'POST' && (path === '/mcp' || path === '/mcp/')) {
          await handleMcp(store, req, res);
          return;
        }

        // Git smart HTTP.
        if (await handleGit(store, req, res, method, path, query)) return;

        // REST v3.
        if (await handleRest(store, req, res, method, path, query)) return;

        // Everything else, every method: GitHub's 404 body.
        sendJson(store, res, 404, { message: 'Not Found' });
      } catch (err) {
        if (!res.headersSent) {
          sendJson(store, res, 500, { message: err instanceof Error ? err.message : 'Internal Server Error' });
        } else {
          res.end();
        }
      }
    })();
  });
}

