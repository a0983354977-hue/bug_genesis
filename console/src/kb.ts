import initSqlJs, { type Database } from "sql.js";

/**
 * Read-only view over the engine's SQLite knowledge base.
 *
 * The schema is owned by src/storage/db.nim. This module deliberately knows
 * nothing about how the data got there — it reads what is on disk, including
 * whatever a campaign that was killed halfway left behind.
 */

export interface Family {
  id: string;
  signature: string;
  kindLabel: string;
  code: string;
  hitCount: number;
  repro: Uint8Array | null;
  reproLen: number;
  firstSeen: string;
  lastSeen: string;
  firstSeenMs: number;
  caseCount: number;
  topStrategy: string;
  /** UTF-8 best-effort rendering of the reproducer, for the panel. */
  reproText: string;
  classKey: string;
}

export interface CaseRow {
  id: string;
  familyId: string | null;
  contentLen: number;
  kindLabel: string;
  elapsedMs: number;
  strategy: string;
  isRepro: number;
  createdAt: string;
}

export interface RunRow {
  id: string;
  startedAt: string;
  target: string;
  workers: number;
  timeoutMs: number;
  seedHex: string;
  execs: number;
  families: number;
}

export interface StrategyStat {
  strategy: string;
  tries: number;
  failures: number;
  newFamilies: number;
}

export interface Kb {
  families: Family[];
  cases: CaseRow[];
  runs: RunRow[];
  stats: StrategyStat[];
  label: string;
  bytes: number;
  /** Distinct defect classes, ordered by family count. */
  classes: string[];
  strategies: string[];
  kinds: string[];
}

export const KIND_COLORS: Record<string, number> = {
  ok: 0x4ade80,
  logic_error: 0xfacc15,
  crash_access_violation: 0xf87171,
  crash_stack_overflow: 0xfb923c,
  crash_int_div_by_zero: 0xe879f9,
  crash_other: 0xef4444,
  hang: 0x60a5fa,
};

function query(db: Database, sql: string): Record<string, any>[] {
  const res = db.exec(sql);
  if (!res.length) return [];
  const { columns, values } = res[0];
  return values.map((row) => {
    const out: Record<string, any> = {};
    columns.forEach((c, i) => (out[c] = row[i]));
    return out;
  });
}

export function asBytes(v: unknown): Uint8Array | null {
  if (v instanceof Uint8Array) return v;
  if (v && typeof v === "object" && (v as any).buffer instanceof ArrayBuffer) {
    return new Uint8Array((v as any).buffer, (v as any).byteOffset ?? 0, (v as any).length);
  }
  if (typeof v === "string") return new TextEncoder().encode(v);
  return null;
}

/** Best-effort text for arbitrary bytes: the engine stores NULs and lone
 *  surrogates here, so this never throws — it degrades and says so. */
export function bytesToText(data: Uint8Array | null): string {
  if (!data || data.length === 0) return "";
  try {
    return new TextDecoder("utf-8", { fatal: false }).decode(data);
  } catch {
    return "";
  }
}

export function hexdump(data: Uint8Array, limit = 1024): string {
  const lines: string[] = [];
  const n = Math.min(data.length, limit);
  for (let i = 0; i < n; i += 16) {
    const slice = data.subarray(i, i + 16);
    const hex = Array.from(slice)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ")
      .padEnd(47, " ");
    const text = Array.from(slice)
      .map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : "."))
      .join("");
    lines.push(`${i.toString(16).padStart(6, "0")}  ${hex}  |${text}|`);
  }
  if (data.length > limit) lines.push(`… ${data.length - limit} more bytes`);
  return lines.join("\n");
}

export async function loadFromBytes(bytes: Uint8Array, label: string): Promise<Kb> {
  const SQL = await initSqlJs({
    // The wasm is copied to public/ by hand rather than resolved through the
    // bundler: sql.js loads it with a plain <script>-style fetch at runtime, so
    // a hashed asset name would break it silently.
    locateFile: (_file: string) => `/sql-wasm.wasm`,
  });
  const db = new SQL.Database(bytes);

  // Tables the engine may or may not have written, depending on how the
  // campaign ended. Absence is reported by the caller, never guessed here.
  const have = new Set(
    query(db, "SELECT name FROM sqlite_master WHERE type='table'").map((r) => r.name as string),
  );

  const families: Family[] = have.has("bug_families")
    ? query(
        db,
        `SELECT f.id, f.signature, f.kind_label, f.code, f.hit_count,
                f.repro, f.repro_len, f.first_seen, f.last_seen,
                COUNT(c.id) AS case_count,
                COALESCE((SELECT c2.strategy FROM test_cases c2
                          WHERE c2.family_id = f.id
                          GROUP BY c2.strategy
                          ORDER BY COUNT(*) DESC LIMIT 1), '') AS top_strategy
         FROM bug_families f
         LEFT JOIN test_cases c ON c.family_id = f.id
         GROUP BY f.id
         ORDER BY f.first_seen ASC`,
      ).map((r) => {
        const repro = asBytes(r.repro);
        return {
          id: r.id as string,
          signature: String(r.signature ?? ""),
          kindLabel: String(r.kind_label ?? ""),
          code: String(r.code ?? ""),
          hitCount: Number(r.hit_count ?? 0),
          repro,
          reproLen: Number(r.repro_len ?? 0),
          firstSeen: String(r.first_seen ?? ""),
          lastSeen: String(r.last_seen ?? ""),
          firstSeenMs: Date.parse(String(r.first_seen ?? "")) || 0,
          caseCount: Number(r.case_count ?? 0),
          topStrategy: String(r.top_strategy ?? ""),
          reproText: bytesToText(repro),
          classKey: `${r.kind_label}|${r.code}`,
        } as Family;
      })
    : [];

  const cases: CaseRow[] = have.has("test_cases")
    ? query(
        db,
        `SELECT id, family_id, content_len, kind_label, elapsed_ms, strategy,
                is_repro, created_at
         FROM test_cases ORDER BY created_at ASC LIMIT 200000`,
      ).map((r) => ({
        id: r.id as string,
        familyId: (r.family_id as string) ?? null,
        contentLen: Number(r.content_len ?? 0),
        kindLabel: String(r.kind_label ?? ""),
        elapsedMs: Number(r.elapsed_ms ?? 0),
        strategy: String(r.strategy ?? ""),
        isRepro: Number(r.is_repro ?? 0),
        createdAt: String(r.created_at ?? ""),
      }))
    : [];

  const runs: RunRow[] = have.has("run_log")
    ? query(
        db,
        `SELECT id, started_at, target, workers, timeout_ms, seed_hex, execs, families
         FROM run_log ORDER BY started_at ASC LIMIT 500`,
      ).map((r) => ({
        id: r.id as string,
        startedAt: String(r.started_at ?? ""),
        target: String(r.target ?? ""),
        workers: Number(r.workers ?? 0),
        timeoutMs: Number(r.timeout_ms ?? 0),
        seedHex: String(r.seed_hex ?? ""),
        execs: Number(r.execs ?? 0),
        families: Number(r.families ?? 0),
      }))
    : [];

  const stats: StrategyStat[] = have.has("strategy_stats")
    ? query(db, `SELECT strategy, tries, failures, new_families FROM strategy_stats`)
        .map((r) => ({
          strategy: String(r.strategy ?? ""),
          tries: Number(r.tries ?? 0),
          failures: Number(r.failures ?? 0),
          newFamilies: Number(r.new_families ?? 0),
        }))
    : [];

  db.close();

  const classCounts = new Map<string, number>();
  for (const f of families) classCounts.set(f.classKey, (classCounts.get(f.classKey) ?? 0) + 1);
  const classes = [...classCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([k]) => k);

  return {
    families,
    cases,
    runs,
    stats,
    label,
    bytes: bytes.length,
    classes,
    strategies: [...new Set(stats.map((s) => s.strategy))].sort(),
    kinds: [...new Set(families.map((f) => f.kindLabel))].sort(),
  };
}

export async function loadFromFile(file: File): Promise<Kb> {
  return loadFromBytes(new Uint8Array(await file.arrayBuffer()), file.name);
}

export async function loadFromUrl(url: string): Promise<Kb | null> {
  try {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) return null;
    const buf = await res.arrayBuffer();
    if (buf.byteLength === 0) return null;
    return loadFromBytes(new Uint8Array(buf), url.split("/").pop() ?? url);
  } catch {
    return null;
  }
}
