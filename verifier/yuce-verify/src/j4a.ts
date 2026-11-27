// Level J4a (amendment 6): the withdrawal cascade recomputed. The state J3
// builds is kept for the whole journal (P6-2), the commands that withdraw
// evidence and judge links are applied at their place (P6-3, P6-5, P6-6), and
// at every seal the two projections are computed (P6-7, P6-8) and compared
// with the seal.

import { occurrences } from "./cdc.ts";
import type { HashAdapter } from "./hash.ts";
import { concatBytes, toHex, utf8 } from "./hash.ts";
import type { JsonObject, JsonValue } from "./json.ts";
import { isObject, jcs } from "./json.ts";
import { domainHash } from "./trees.ts";

export const PROJECTION_DOMAIN = { status: "R2R-PROJ-STATUS/2", dependencies: "R2R-PROJ-DEPS/2" } as const;
/** P6-6: the domain of a link id. There is no zero byte after it. */
export const LINK_DOMAIN = "R2R-AUDIT-LINK/1";
/** P6-8: the projections of a run with no record. */
export const EMPTY_PROJECTIONS = {
  status: "88f19ee44d285b626e63507ebd361e8ce71ccc967e93d303dad85d908ac5a875",
  dependencies: "65ec2af34b368787092fa5d7b6e498b243c7b7eaedf11eb45f3033fd5ba49133",
} as const;

/** What J4a keeps of an observation (P6-2). */
export interface Observation {
  docId: string;
  quote: string;
  quoteBytes: Uint8Array;
  /** The anchor id (the evidence id of P3-8). */
  anchor: string;
  /** The version id the quote was bound to. */
  version: string;
  start: number;
  end: number;
}

/** An accepted record as J4a and the observation report need it (P6-2). */
export interface CascadeRecord {
  /** Position in record order, from 0. */
  index: number;
  id: string;
  kind: string;
  /** The actor of the frame that accepted it. */
  actor: string;
  /** The position of the frame that accepted it. */
  frame: number;
  /** The resolved based_on, in line order; for an answer, its resolved answer_ids. */
  grounds: readonly string[];
  /** A relation's ends, as full ids and the relation name. */
  ends: { from: string; rel: string; to: string } | null;
  text: string | null;
  /** A claim's subject and object (absent: null). */
  subject: string | null;
  object: string | null;
  /** A question's about_record, resolved to a full id (rules 4). */
  about: string | null;
  obs: Observation | null;
}

export type LinkStatus = "proposed" | "accepted" | "rejected" | string;

/** A row of the links table (P6-2, P6-6). A reference that names no record is kept as null. */
export interface Link {
  id: string;
  from: string;
  rel: string;
  to: string;
  status: LinkStatus;
  basis: readonly (string | null)[];
  acceptanceBasis: readonly (string | null)[] | null;
}

/** Why an anchor was revoked: the first command that revoked it (observation report, section 3). */
export type RevocationReason = "withdrawn" | "revoked";

/** The current documents, as level J3 keeps them. */
export interface DocumentView {
  bytes(docId: string): Uint8Array | undefined;
  version(docId: string): Promise<string | undefined>;
}

export type StatusRow = [string, string, boolean, boolean, string[]];
export type DependencyPair = [string, string];

/** The values of P6-7 for every record, in record order, and the projections of P6-8. */
export interface CascadeStatus {
  grounded: boolean[];
  established: boolean[];
  /** P6-7: proof of every record; null when no link is accepted (then no link is effective). */
  proof: boolean[] | null;
  rows: StatusRow[];
  pairs: DependencyPair[];
  status: string;
  dependencies: string;
}

export async function linkId(adapter: HashAdapter, from: string, rel: string, to: string): Promise<string> {
  const domain = utf8(LINK_DOMAIN);
  return toHex(await adapter.sha256(concatBytes([domain, utf8(jcs([from, rel, to]))])));
}

export async function projectionHashes(adapter: HashAdapter, rows: readonly StatusRow[], pairs: readonly DependencyPair[]): Promise<{ status: string; dependencies: string }> {
  return {
    status: toHex(await domainHash(adapter, PROJECTION_DOMAIN.status, utf8(jcs(rows as unknown as JsonValue)))),
    dependencies: toHex(await domainHash(adapter, PROJECTION_DOMAIN.dependencies, utf8(jcs(pairs as unknown as JsonValue)))),
  };
}

const tripleKey = (from: string, rel: string, to: string): string => jcs([from, rel, to]);
const HEX64 = /^[0-9a-fA-F]{64}$/;

/** The state of level J4a across frames. */
export class Cascade {
  private readonly records: CascadeRecord[] = [];
  private readonly byId = new Map<string, CascadeRecord>();
  private readonly byDoc = new Map<string, CascadeRecord[]>();
  /** P6-2: the revoked anchor ids, with the reason of the first revocation. */
  readonly revoked = new Map<string, RevocationReason>();
  /** P6-2: per document name, the texts withdrawn from it (key: the text, value: its bytes). */
  readonly withdrawn = new Map<string, Map<string, Uint8Array>>();
  /** P6-2: the links, keyed by the triple. */
  private readonly links = new Map<string, Link>();
  private readonly linkIds = new Map<string, string>();
  /**
   * Observation report, section 6: frames that record a refused answer (`task-repair:`) or a late one
   * (`task-conflict:`). Not part of the projections.
   */
  rejectedSubmissions = 0;
  lateSubmissions = 0;

  constructor(
    private readonly adapter: HashAdapter,
    private readonly docs: DocumentView,
  ) {}

  get accepted(): readonly CascadeRecord[] {
    return this.records;
  }

  record(id: string): CascadeRecord | undefined {
    return this.byId.get(id);
  }

  get allLinks(): readonly Link[] {
    return [...this.links.values()];
  }

  /** P6-2, P6-3: a record accepted by J3; an accepted relation creates its link right away (P6-6). */
  async addRecord(r: Omit<CascadeRecord, "index">): Promise<void> {
    const rec: CascadeRecord = { ...r, index: this.records.length };
    this.records.push(rec);
    this.byId.set(rec.id, rec);
    if (rec.obs !== null) {
      const list = this.byDoc.get(rec.obs.docId);
      if (list === undefined) this.byDoc.set(rec.obs.docId, [rec]);
      else list.push(rec);
    }
    if (rec.kind === "relation" && rec.ends !== null) await this.createLink(rec.ends.from, rec.ends.rel, rec.ends.to, rec.grounds);
  }

  /** P6-3: a command other than submit and put_document that ran (as a frame, or as a batch operation with a result). */
  async command(command: JsonValue): Promise<void> {
    if (!isObject(command)) return;
    switch (command.get("kind")) {
      case "revoke":
        return this.revoke(command);
      case "revoke_text":
        return this.revokeText(command);
      case "add_link":
        return this.addLink(command);
      case "set_link_status":
        return this.setLinkStatus(command);
      default:
        // P6-3: checkpoint, seal, close and the ontology commands change no row or pair.
        return;
    }
  }

  /**
   * Observation report, section 6: a `batch` frame with outcome `value` whose `command.checkpoint.key`
   * starts with `task-repair:` (a refused answer) or `task-conflict:` (a late one), and whose
   * `outcome.result.checkpointed` is `true`.
   */
  noteFrame(command: JsonValue, outcome: JsonValue | undefined): void {
    if (!isObject(command) || command.get("kind") !== "batch" || !isObject(outcome) || outcome.get("kind") !== "value") return;
    const checkpoint = command.get("checkpoint");
    const key = isObject(checkpoint) ? checkpoint.get("key") : undefined;
    const result = outcome.get("result");
    if (typeof key !== "string" || !isObject(result) || result.get("checkpointed") !== true) return;
    if (key.startsWith("task-repair:")) this.rejectedSubmissions++;
    else if (key.startsWith("task-conflict:")) this.lateSubmissions++;
  }

  /** P6-5: the re-close step of a put_document, after the new bytes and version are in place. */
  async reclose(docId: string): Promise<void> {
    const texts = this.withdrawn.get(docId);
    if (texts === undefined) return;
    for (const t of [...texts.values()]) this.close(docId, t, await this.hits(docId, t));
  }

  // -------------------------------------------------------------------------
  // P6-5: withdrawals
  // -------------------------------------------------------------------------

  /** hits(D, T): live observations bound to the current version of D whose span overlaps an occurrence of T. */
  private async hits(docId: string, t: Uint8Array): Promise<CascadeRecord[]> {
    if (t.length === 0) return [];
    const bytes = this.docs.bytes(docId);
    const candidates = this.byDoc.get(docId);
    if (bytes === undefined || candidates === undefined) return [];
    const found = occurrences(bytes, t, Number.MAX_SAFE_INTEGER);
    if (found.length === 0) return [];
    const version = await this.docs.version(docId);
    const out: CascadeRecord[] = [];
    for (const r of candidates) {
      const o = r.obs!;
      if (o.version !== version || this.revoked.has(o.anchor)) continue;
      // Strict overlap: s < o + |T| and o < e.
      if (found.some((p) => o.start < p + t.length && p < o.end)) out.push(r);
    }
    return out;
  }

  private revokeAnchor(anchor: string, reason: RevocationReason): void {
    if (!this.revoked.has(anchor)) this.revoked.set(anchor, reason);
  }

  /** close(D, T, H). */
  private close(docId: string, t: Uint8Array, hits: readonly CascadeRecord[]): void {
    for (const h of hits) this.revokeAnchor(h.obs!.anchor, "withdrawn");
    let texts = this.withdrawn.get(docId);
    if (texts === undefined) this.withdrawn.set(docId, (texts = new Map()));
    const key = toHex(t);
    if (!texts.has(key)) texts.set(key, t);
  }

  private isWithdrawn(docId: string, t: Uint8Array): boolean {
    return this.withdrawn.get(docId)?.has(toHex(t)) === true;
  }

  private async revokeText(command: JsonObject): Promise<void> {
    const docId = command.get("doc_id");
    const quote = command.get("exact_quote");
    if (typeof docId !== "string" || typeof quote !== "string") return;
    const t = utf8(quote);
    this.close(docId, t, await this.hits(docId, t));
  }

  private async revoke(command: JsonObject): Promise<void> {
    const ref = command.get("record");
    if (typeof ref !== "string") return;
    // P6-3: revoke.record is a full 64-digit id (any case); the "@" form is for add_link and basis only.
    const r = HEX64.test(ref) ? this.byId.get(ref.toLowerCase()) : undefined;
    if (r === undefined || r.obs === null) return;
    const { docId, quoteBytes: t, anchor } = r.obs;
    const already = this.isWithdrawn(docId, t);
    // 1. hits before step 2
    const hits = already ? [] : await this.hits(docId, t);
    // 2.
    this.revokeAnchor(anchor, already ? "revoked" : "withdrawn");
    // 3.
    if (!already) this.close(docId, t, hits);
  }

  // -------------------------------------------------------------------------
  // P6-6: links
  // -------------------------------------------------------------------------

  /** P6-6: a 64-digit hex string names a record id; otherwise "@" and 16 to 64 hex digits of exactly one record. */
  private resolve(ref: string): string | null {
    if (HEX64.test(ref)) return ref.toLowerCase();
    if (!/^@[0-9a-fA-F]{16,64}$/.test(ref)) return null;
    const prefix = ref.slice(1).toLowerCase();
    let found: string | null = null;
    for (const r of this.records) {
      if (r.id.startsWith(prefix)) {
        if (found !== null) return null;
        found = r.id;
      }
    }
    return found;
  }

  private resolveList(v: JsonValue | undefined): (string | null)[] | null {
    if (!Array.isArray(v)) return null;
    return v.map((x) => (typeof x === "string" ? this.resolve(x) : null));
  }

  private async createLink(from: string, rel: string, to: string, basis: readonly (string | null)[]): Promise<void> {
    const key = tripleKey(from, rel, to);
    if (this.links.has(key)) return;
    const id = await linkId(this.adapter, from, rel, to);
    this.links.set(key, { id, from, rel, to, status: "proposed", basis: [...basis], acceptanceBasis: null });
    this.linkIds.set(id, key);
  }

  private async addLink(command: JsonObject): Promise<void> {
    const from = command.get("from");
    const rel = command.get("rel");
    const to = command.get("to");
    const basis = this.resolveList(command.get("basis"));
    if (typeof from !== "string" || typeof rel !== "string" || typeof to !== "string" || basis === null) return;
    const f = this.resolve(from);
    const t = this.resolve(to);
    if (f === null || t === null) return;
    await this.createLink(f, rel, t, basis);
  }

  private async setLinkStatus(command: JsonObject): Promise<void> {
    const link = command.get("link");
    const status = command.get("status");
    if (typeof link !== "string" || typeof status !== "string") return;
    const key = this.linkIds.get(link.toLowerCase());
    if (key === undefined) return;
    const l = this.links.get(key)!;
    l.status = status;
    if (status === "accepted") l.acceptanceBasis = this.resolveList(command.get("basis")) ?? [];
  }

  // -------------------------------------------------------------------------
  // P6-4, P6-7, P6-8: support and projections
  // -------------------------------------------------------------------------

  /** P6-4 for every observation; null for other records. */
  async observationsGrounded(): Promise<(boolean | null)[]> {
    const versions = new Map<string, string | undefined>();
    const out: (boolean | null)[] = [];
    for (const r of this.records) {
      if (r.obs === null) {
        out.push(null);
        continue;
      }
      if (this.revoked.has(r.obs.anchor)) {
        out.push(false);
        continue;
      }
      if (!versions.has(r.obs.docId)) versions.set(r.obs.docId, await this.docs.version(r.obs.docId));
      out.push(versions.get(r.obs.docId) === r.obs.version);
    }
    return out;
  }

  /** P6-7, P6-8: the support values and the two projections over the current state. */
  async status(): Promise<CascadeStatus> {
    const n = this.records.length;
    const og = await this.observationsGrounded();
    const at = (id: string | null): number => (id === null ? -1 : (this.byId.get(id)?.index ?? -1));

    // proof and structural, only when some link is accepted (P6-7).
    let proof: boolean[] | null = null;
    if (this.allLinks.some((l) => l.status === "accepted")) {
      const structural = new Array<boolean>(n);
      proof = new Array<boolean>(n);
      for (const r of this.records) {
        const k = r.index;
        if (r.kind === "observe") {
          structural[k] = og[k] === true;
          proof[k] = structural[k];
          continue;
        }
        const g = r.grounds.map(at);
        const ends = r.ends !== null ? [at(r.ends.from), at(r.ends.to)] : [];
        structural[k] = r.kind !== "done" && g.length > 0 && g.every((x) => x >= 0 && structural[x]!) && ends.every((x) => x >= 0 && structural[x]!);
        proof[k] =
          structural[k] && !["hypothesis", "question", "done"].includes(r.kind) && g.every((x) => proof![x]!) && ends.every((x) => proof![x]!);
      }
    }
    const effective = (from: string, rel: string, to: string): boolean => {
      const l = this.links.get(tripleKey(from, rel, to));
      return l !== undefined && this.effectiveWith(l, proof);
    };

    const grounded = new Array<boolean>(n);
    const established = new Array<boolean>(n);
    const isG = (x: number): boolean => x >= 0 && grounded[x]!;
    const isE = (x: number): boolean => x >= 0 && established[x]!;
    for (const r of this.records) {
      const k = r.index;
      const g = r.grounds.map(at);
      switch (r.kind) {
        case "observe":
          grounded[k] = og[k] === true;
          established[k] = grounded[k];
          break;
        case "claim":
          grounded[k] = g.length > 0 && g.every(isG);
          established[k] = grounded[k];
          break;
        case "hypothesis":
          grounded[k] = g.length > 0 && g.every(isG);
          established[k] = false;
          break;
        case "relation": {
          const f = at(r.ends!.from);
          const t = at(r.ends!.to);
          grounded[k] = g.length > 0 && g.every(isG) && isG(f) && isG(t);
          established[k] = grounded[k] && effective(r.ends!.from, r.ends!.rel, r.ends!.to) && isE(f) && isE(t);
          break;
        }
        case "done":
          grounded[k] = g.length > 0 && g.every((x) => isG(x) && isE(x));
          established[k] = false;
          break;
        default:
          // question
          grounded[k] = false;
          established[k] = false;
      }
    }

    const rows: StatusRow[] = [];
    const pairs: DependencyPair[] = [];
    for (const r of this.records) {
      const direct = this.directGrounds(r);
      const fallen = [...new Set(direct.filter((id) => !isG(at(id))))].sort();
      rows.push([r.id, r.kind, grounded[r.index]!, established[r.index]!, r.kind === "observe" || r.kind === "question" ? [] : fallen]);
      for (const d of direct) pairs.push([r.id, d]);
    }
    pairs.sort((a, b) => cmp(a[0] + a[1], b[0] + b[1]));
    const unique = pairs.filter((p, k) => k === 0 || p[0] !== pairs[k - 1]![0] || p[1] !== pairs[k - 1]![1]);
    const hashes = await projectionHashes(this.adapter, rows, unique);
    return { grounded, established, proof, rows, pairs: unique, ...hashes };
  }

  /** P6-7: a link is effective (the observation report calls it usable). */
  linkEffective(l: Link, st: CascadeStatus): boolean {
    return this.effectiveWith(l, st.proof);
  }

  private effectiveWith(l: Link, proof: readonly boolean[] | null): boolean {
    if (l.status !== "accepted" || proof === null) return false;
    const proofOf = (id: string | null): boolean => {
      const k = id === null ? -1 : (this.byId.get(id)?.index ?? -1);
      return k >= 0 && proof[k]!;
    };
    if (!proofOf(l.from) || !proofOf(l.to)) return false;
    if (l.basis.length === 0 || !l.basis.every(proofOf)) return false;
    return l.acceptanceBasis !== null && l.acceptanceBasis.length > 0 && l.acceptanceBasis.every(proofOf);
  }

  /** P6-8: a record's direct grounds are its based_on, then, for a relation, from and to. */
  directGrounds(r: CascadeRecord): string[] {
    return r.ends !== null ? [...r.grounds, r.ends.from, r.ends.to] : [...r.grounds];
  }
}

/** Comparison by UTF-16 code units (the order of JavaScript strings and of canonical JSON keys). */
export function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}
