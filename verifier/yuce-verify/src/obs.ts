// The observation report `yuce-observation-report/1` (SPEC_OBSERVATION_REPORT_v1):
// three axes per claim (support, dispute, time) and the map around them,
// computed from the state J4a replays; and the check of a given report.

import type { HashAdapter } from "./hash.ts";
import { toHex, utf8 } from "./hash.ts";
import type { Cascade, CascadeRecord, CascadeStatus, Link } from "./j4a.ts";
import { cmp } from "./j4a.ts";
import type { JsonObject, JsonValue } from "./json.ts";
import { fromPlain, isHashText, isObject, jcs, parseJson } from "./json.ts";
import type { Plain } from "./json.ts";
import { domainHash } from "./trees.ts";
import type { CutBundle } from "./cut.ts";
import { verifyCut } from "./cut.ts";
import { verifyJournalDetailed } from "./verify.ts";

export const OBS_REPORT_FORMAT = "yuce-observation-report/1";
export const OBS_REPORT_DOMAIN = "YUCE-OBS-REPORT/1";

/** One journal of the report: its name, the seal that ends its part, and the state J4a replayed there. */
export interface ObsJournal {
  name: string;
  seal_hash: string;
  log_size: number;
  cascade: Cascade;
  /** The status at that seal. */
  status: CascadeStatus;
}

/** A delivery of a cut (B3.1): the receiving journal, the document, its delivered version and the export's paragraphs in it. */
export interface ObsDelivery {
  journal: string;
  doc_id: string;
  version: string;
  /** The journal the export was made from. */
  source: string;
  paragraphs: readonly { record: string; start: number; end: number }[];
}

export interface ObsInput {
  cut_hash: string | null;
  journals: readonly ObsJournal[];
  /** Empty for a single journal. */
  deliveries: readonly ObsDelivery[];
}

interface LinkEntry {
  link: string;
  rel: string;
  from: string;
  to: string;
  status: string;
  other_grounded: boolean;
  usable: boolean;
}

interface ClaimEntry {
  journal: string;
  id: string;
  author: string;
  frame: number;
  quotes: { doc_id: string; version: string; start: number; end: number }[];
  rests_on: string[];
  rests_on_across: { journal: string; record: string }[];
  questions: string[];
  support: "grounded" | "affected";
  root_causes: { record: string; reason: string }[];
  dispute: "contested" | "uncontested" | "unknown";
  dispute_links: LinkEntry[];
  time: "current" | "stale" | "unknown";
  time_links: LinkEntry[];
}

type Debt = {
  affected: number;
  contested: number;
  resting_on_contested: number;
  stale: number;
  questions_about_claims: number;
  key_conflicts: number;
  rejected_submissions: number;
  late_submissions: number;
};

const zeroDebt = (): Debt => ({
  affected: 0,
  contested: 0,
  resting_on_contested: 0,
  stale: 0,
  questions_about_claims: 0,
  key_conflicts: 0,
  rejected_submissions: 0,
  late_submissions: 0,
});

const uniqueBy = <T>(items: readonly T[], key: (t: T) => string): T[] => {
  const seen = new Set<string>();
  return items.filter((t) => {
    const k = key(t);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
};

/** Computes the report: the JSON value with report_hash, and its canonical bytes as text. */
export async function observationReport(input: ObsInput, adapter: HashAdapter): Promise<{ value: JsonObject; text: string }> {
  const claims: ClaimEntry[] = [];
  const keyConflicts: { journal: string; subject: string; values: (string | null)[] }[] = [];
  const debtBy = new Map<string, Debt>();

  for (const j of input.journals) {
    const { cascade, status } = j;
    const records = cascade.accepted;
    const grounded = (id: string): boolean => {
      const r = cascade.record(id);
      return r !== undefined && status.grounded[r.index] === true;
    };
    const links = cascade.allLinks;
    const fallenBy = (r: CascadeRecord): string[] => status.rows[r.index]![4];
    const entryOf = (l: Link, other: string): LinkEntry => ({
      link: l.id,
      rel: l.rel,
      from: l.from,
      to: l.to,
      status: l.status,
      other_grounded: grounded(other),
      usable: cascade.linkEffective(l, status),
    });
    // Section 5: a triple some accepted relation record has, standing or not.
    const declared = new Set(records.filter((r) => r.kind === "relation" && r.ends !== null).map((r) => jcs([r.ends!.from, r.ends!.rel, r.ends!.to])));

    for (const c of records) {
      if (c.kind !== "claim") continue;
      const grounds = c.grounds.map((id) => cascade.record(id)).filter((g): g is CascadeRecord => g !== undefined);
      const obsGrounds = grounds.filter((g) => g.obs !== null);
      const quotes = uniqueBy(
        obsGrounds.map((g) => ({ doc_id: g.obs!.docId, version: g.obs!.version, start: g.obs!.start, end: g.obs!.end })),
        (q) => jcs(fromPlain(q)),
      );
      const restsOn = uniqueBy(
        grounds.filter((g) => g.kind === "claim").map((g) => g.id),
        (x) => x,
      );
      const across: { journal: string; record: string }[] = [];
      for (const g of obsGrounds) {
        for (const d of input.deliveries) {
          if (d.journal !== j.name || d.doc_id !== g.obs!.docId || d.version !== g.obs!.version) continue;
          for (const p of d.paragraphs) if (g.obs!.start < p.end && p.start < g.obs!.end) across.push({ journal: d.source, record: p.record });
        }
      }
      const restsOnAcross = uniqueBy(across, (a) => jcs([a.journal, a.record])).sort((a, b) => cmp(a.journal, b.journal) || cmp(a.record, b.record));
      const questions = [...new Set(records.filter((q) => q.kind === "question" && q.about === c.id).map((q) => q.id))].sort(cmp);

      // Section 3: support and root causes.
      const isGrounded = status.grounded[c.index] === true;
      const causes: CascadeRecord[] = [];
      if (!isGrounded) {
        const visited = new Set<string>();
        const stack = [...fallenBy(c)];
        while (stack.length > 0) {
          const id = stack.shift()!;
          if (visited.has(id)) continue;
          visited.add(id);
          const r = cascade.record(id);
          if (r === undefined) continue;
          if (r.kind === "observe") {
            if (status.grounded[r.index] !== true) causes.push(r);
          } else stack.push(...fallenBy(r));
        }
        causes.sort((a, b) => a.index - b.index);
      }
      const rootCauses = causes.map((r) => ({ record: r.id, reason: cascade.revoked.get(r.obs!.anchor) ?? "version_replaced" }));

      // Section 4: dispute.
      const K = links.filter((l) => l.rel === "contradicts" && (l.from === c.id || l.to === c.id));
      const other = (l: Link): string => (l.from === c.id ? l.to : l.from);
      let dispute: ClaimEntry["dispute"];
      if (K.some((l) => l.status === "accepted" && grounded(other(l)))) dispute = "contested";
      else if (K.some((l) => l.status === "proposed" || (l.status === "accepted" && !grounded(other(l))))) dispute = "unknown";
      else dispute = "uncontested";
      const disputeLinks = K.map((l) => entryOf(l, other(l))).sort((a, b) => cmp(a.link, b.link));

      // Section 5: time.
      const supersedes = links.filter((l) => l.rel === "supersedes" && l.to === c.id);
      const R = supersedes.filter((l) => l.status !== "rejected");
      let time: ClaimEntry["time"];
      if (R.some((l) => grounded(l.from) && (l.status === "accepted" || declared.has(jcs([l.from, l.rel, l.to]))))) time = "stale";
      else if (R.length > 0) time = "unknown";
      else time = "current";
      const timeLinks = supersedes.map((l) => entryOf(l, l.from)).sort((a, b) => cmp(a.link, b.link));

      claims.push({
        journal: j.name,
        id: c.id,
        author: c.actor,
        frame: c.frame,
        quotes,
        rests_on: restsOn,
        rests_on_across: restsOnAcross,
        questions,
        support: isGrounded ? "grounded" : "affected",
        root_causes: rootCauses,
        dispute,
        dispute_links: disputeLinks,
        time,
        time_links: timeLinks,
      });
    }

    // Section 6: exact-key conflicts, by the kernel's exact-key rule of an active claim.
    const supersededByKey = (c: CascadeRecord): boolean =>
      records.some((r) => {
        if (r.kind !== "relation" || r.ends === null || r.ends.rel !== "supersedes" || r.ends.to !== c.id || status.grounded[r.index] !== true) return false;
        const l = links.find((x) => x.from === r.ends!.from && x.rel === r.ends!.rel && x.to === r.ends!.to);
        return l !== undefined && l.status !== "rejected";
      });
    const byKey = new Map<string, Set<string>>();
    const valueOf = new Map<string, string | null>();
    for (const c of records) {
      if (c.kind !== "claim" || c.subject === null || status.grounded[c.index] !== true || supersededByKey(c)) continue;
      const v = jcs(c.object);
      valueOf.set(v, c.object);
      let set = byKey.get(c.subject);
      if (set === undefined) byKey.set(c.subject, (set = new Set()));
      set.add(v);
    }
    const conflicts = [...byKey.entries()].filter(([, vs]) => vs.size >= 2).sort((a, b) => cmp(a[0], b[0]));
    for (const [subject, vs] of conflicts) keyConflicts.push({ journal: j.name, subject, values: [...vs].sort(cmp).map((v) => valueOf.get(v)!) });

    const debt = zeroDebt();
    debt.key_conflicts = conflicts.length;
    debt.questions_about_claims = records.filter((q) => q.kind === "question" && q.about !== null && cascade.record(q.about)?.kind === "claim").length;
    // Section 6: the batch frames of the part that record a refused or a late answer.
    debt.rejected_submissions = cascade.rejectedSubmissions;
    debt.late_submissions = cascade.lateSubmissions;
    debtBy.set(j.name, debt);
  }

  // Debt counters that read the entries (resting_on_contested reads claims of other journals too).
  const disputeOf = new Map(claims.map((c) => [jcs([c.journal, c.id]), c.dispute]));
  for (const c of claims) {
    const debt = debtBy.get(c.journal)!;
    if (c.support === "affected") debt.affected++;
    if (c.dispute === "contested") debt.contested++;
    if (c.time === "stale") debt.stale++;
    const resting =
      c.rests_on.some((id) => disputeOf.get(jcs([c.journal, id])) === "contested") ||
      c.rests_on_across.some((a) => disputeOf.get(jcs([a.journal, a.record])) === "contested");
    if (resting) debt.resting_on_contested++;
  }
  const total = zeroDebt();
  for (const d of debtBy.values()) for (const k of Object.keys(total) as (keyof Debt)[]) total[k] += d[k];
  keyConflicts.sort((a, b) => cmp(a.journal, b.journal) || cmp(a.subject, b.subject));

  const body = fromPlain({
    format: OBS_REPORT_FORMAT,
    mode: "observe",
    cut_hash: input.cut_hash,
    journals: input.journals.map((j) => ({ name: j.name, seal_hash: j.seal_hash, log_size: j.log_size })),
    claims: claims as unknown as Plain,
    key_conflicts: keyConflicts as unknown as Plain,
    debt: { total, by_journal: Object.fromEntries([...debtBy.entries()]) } as unknown as Plain,
  }) as JsonObject;
  body.set("report_hash", await reportHash(adapter, body));
  return { value: body, text: jcs(body) };
}

/** report_hash = hex(H("YUCE-OBS-REPORT/1", JCS(report without "report_hash"))). */
export async function reportHash(adapter: HashAdapter, report: JsonObject): Promise<string> {
  const without: JsonObject = new Map([...report].filter(([k]) => k !== "report_hash"));
  return toHex(await domainHash(adapter, OBS_REPORT_DOMAIN, utf8(jcs(without))));
}

export type ReportCheck = { verdict: "PASS"; code: null; path: null } | { verdict: "FAIL"; code: "REPORT_FORM" | "REPORT_HASH_MISMATCH" | "REPORT_MISMATCH"; path: string | null };

/** Section 7: the three checks of a given report, in order. `computed` is the report recomputed from the same input. */
export async function checkReport(given: Uint8Array, computed: JsonObject, adapter: HashAdapter): Promise<ReportCheck> {
  // 1. The bytes as they are are the UTF-8 of a canonical JSON object whose report_hash is 64 lowercase hex
  // digits. A byte-order mark is kept by the decoder, so it is no JSON; the canonical form is compared as bytes.
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(given);
  } catch {
    return { verdict: "FAIL", code: "REPORT_FORM", path: null };
  }
  const parsed = parseJson(text);
  if (!parsed.ok || parsed.badNumber || !isObject(parsed.value) || !sameBytes(utf8(jcs(parsed.value)), given) || !isHashText(parsed.value.get("report_hash"))) {
    return { verdict: "FAIL", code: "REPORT_FORM", path: null };
  }
  // 2. Its own hash.
  if (parsed.value.get("report_hash") !== (await reportHash(adapter, parsed.value))) return { verdict: "FAIL", code: "REPORT_HASH_MISMATCH", path: null };
  // 3. Recomputed, byte for byte.
  if (sameBytes(utf8(jcs(computed)), given)) return { verdict: "PASS", code: null, path: null };
  return { verdict: "FAIL", code: "REPORT_MISMATCH", path: firstDifference(parsed.value, computed, "") };
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, k) => x === b[k]);
}

/** The first differing path: depth first, object keys in canonical order, array positions ascending. */
export function firstDifference(a: JsonValue | undefined, b: JsonValue | undefined, path: string): string | null {
  if (a === undefined || b === undefined) return path;
  if (isObject(a) && isObject(b)) {
    const keys = [...new Set([...a.keys(), ...b.keys()])].sort(cmp);
    for (const k of keys) {
      const d = firstDifference(a.get(k), b.get(k), path === "" ? k : `${path}.${k}`);
      if (d !== null) return d;
    }
    return null;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      const d = firstDifference(a[i], b[i], `${path}[${i}]`);
      if (d !== null) return d;
    }
    return null;
  }
  return jcs(a) === jcs(b) ? null : path;
}

// ---------------------------------------------------------------------------
// The two inputs (section 1)
// ---------------------------------------------------------------------------

export type ObsOutcome = { ok: true; value: JsonObject; text: string } | { ok: false; reason: string };

/** The part of a journal that ends with the seal at position n: its first n + 1 frames. */
export function partThroughSeal(journal: Uint8Array, n: number): Uint8Array | null {
  let at = 0;
  for (let k = 0; k <= n; k++) {
    const lf = journal.indexOf(0x0a, at);
    if (lf < 0) return null;
    at = lf + 1;
  }
  return journal.subarray(0, at);
}

/** The report over one journal, its documents and the seal frame that ends its part. */
export async function observationReportForJournal(journal: Uint8Array, documents: readonly Uint8Array[], sealFrame: number, adapter: HashAdapter): Promise<ObsOutcome> {
  const part = partThroughSeal(journal, sealFrame);
  if (part === null) return { ok: false, reason: `the journal has no frame ${sealFrame}` };
  const { report, cascade } = await verifyJournalDetailed([part], { documents }, adapter);
  if (report.verdict !== "PASS" || report.levels.J4a.result !== "PASS" || cascade === null) {
    const f = report.first_failure;
    return { ok: false, reason: f !== null ? `the part fails at ${f.level}${f.frame === null ? "" : `, frame ${f.frame}`}: ${f.code}` : `the part is not verified through J4a (${report.verdict})` };
  }
  const seal = report.levels.J1.result === "PASS" ? report.levels.J1.seals.find((s) => s.n === sealFrame) : undefined;
  if (seal === undefined) return { ok: false, reason: `frame ${sealFrame} is not a seal` };
  const firstLf = part.indexOf(0x0a);
  const genesis = parseJson(new TextDecoder().decode(part.subarray(0, firstLf)));
  const body = genesis.ok && isObject(genesis.value) ? genesis.value.get("body") : undefined;
  const runId = isObject(body) ? body.get("run_id") : undefined;
  const status = await cascade.status();
  const r = await observationReport(
    { cut_hash: null, journals: [{ name: typeof runId === "string" ? runId : "", seal_hash: seal.seal_hash, log_size: sealFrame, cascade, status }], deliveries: [] },
    adapter,
  );
  return { ok: true, ...r };
}

/** The report over a cut and its bundle; the cut must pass B0-B4. */
export async function observationReportForCut(bundle: CutBundle, adapter: HashAdapter): Promise<ObsOutcome> {
  const cut = await verifyCut(bundle, adapter);
  if (cut.report.verdict !== "PASS" || cut.manifest === null) {
    const f = cut.report.failures[0];
    return { ok: false, reason: `the cut fails${f === undefined ? "" : `: ${f.code}`}` };
  }
  const journals: ObsJournal[] = cut.manifest.journals.map((j) => {
    const s = cut.states.get(j.name)!;
    return { name: j.name, seal_hash: j.seal_hash, log_size: j.log_size, cascade: s.cascade, status: s.status };
  });
  const sourceOf = new Map(cut.manifest.exports.map((e) => [e.name, e.journal]));
  const deliveries: ObsDelivery[] = cut.delivered.map((d) => ({
    journal: d.delivery.journal,
    doc_id: d.delivery.doc_id,
    version: d.version,
    source: sourceOf.get(d.delivery.export)!,
    paragraphs: d.paragraphs,
  }));
  return { ok: true, ...(await observationReport({ cut_hash: cut.report.cut_hash, journals, deliveries }, adapter)) };
}
