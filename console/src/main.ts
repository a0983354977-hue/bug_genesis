import "./style.css";
import { createGraph } from "./graph";
import {
  hexdump,
  KIND_COLORS,
  loadFromFile,
  loadFromUrl,
  type Family,
  type Kb,
} from "./kb";

// selector helpers — note the '#': querySelector("status") would match a
// <status> element (there is none), return null, and blow up on first write
// with no other symptom than a panel that never updates.
const $ = <T extends HTMLElement>(sel: string) => document.querySelector(sel) as T;

const statusEl = $("#status");
const statsEl = $("#stats");
const summaryEl = $("#summary");
const detailEl = $("#detail");
const timeEl = $<HTMLInputElement>("#time");
const fileEl = $<HTMLInputElement>("#file");
const replayEl = $<HTMLButtonElement>("#replay");
const tlCanvas = $<HTMLCanvasElement>("#tl");

let kb: Kb | null = null;

function status(text: string, tone?: "good" | "bad") {
  statusEl.textContent = text;
  statusEl.className = tone ?? "";
}

const graph = createGraph($<HTMLCanvasElement>("#scene"), onSelect, status);

function colorOf(kind: string): string {
  return "#" + (KIND_COLORS[kind] ?? 0x9ca3af).toString(16).padStart(6, "0");
}

function esc(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
}

/* ------------------------------------------------------------------ stats */

function renderStats() {
  if (!kb) return;
  const avgRate = kb.runs.length
    ? kb.runs.reduce((a, r) => a + r.execs, 0) /
      Math.max(
        1,
        kb.runs.reduce((a, r) => {
          const t = Date.parse(r.startedAt);
          return a + (Number.isFinite(t) ? 1 : 0);
        }, 0),
      )
    : 0;
  statsEl.innerHTML =
    `族群 <b>${kb.families.length}</b>` +
    ` 類別 <b>${kb.classes.length}</b>` +
    ` 案例 <b>${kb.cases.length.toLocaleString()}</b>` +
    ` 輪次 <b>${kb.runs.length}</b>` +
    (avgRate ? ` 平均 <b>${Math.round(avgRate)}</b> exec/run` : "");
}

function renderSummary() {
  if (!kb) return;

  const runs = kb.runs
    .map(
      (r) => `<tr><td>${esc(r.startedAt.slice(11, 19) || r.startedAt)}</td>
              <td>${esc(r.target.split(/[\\/]/).pop() ?? "")}</td>
              <td class="n">${r.workers}</td>
              <td class="n">${r.execs.toLocaleString()}</td>
              <td class="n">${r.families}</td>
              <td class="n">${r.timeoutMs}</td></tr>`,
    )
    .join("");

  const stats = kb.stats
    .slice()
    .sort((a, b) => b.tries - a.tries)
    .map((s) => {
      const yieldRate = s.tries ? (100 * s.newFamilies) / s.tries : 0;
      return `<tr><td>${esc(s.strategy)}</td>
                <td class="n">${s.tries.toLocaleString()}</td>
                <td class="n">${s.failures.toLocaleString()}</td>
                <td class="n">${s.newFamilies}</td>
                <td class="n">${yieldRate.toFixed(2)}%</td></tr>`;
    })
    .join("");

  summaryEl.innerHTML = `
    <h2>輪次</h2>
    ${runs ? `<table><thead><tr><th>時間</th><th>目標</th><th>worker</th><th>exec</th><th>族群</th><th>逾時</th></tr></thead><tbody>${runs}</tbody></table>`
           : `<p class="hint">run_log 是空的 —— campaign 可能被中斷，來不及寫入總結。</p>`}

    <h2>策略成效</h2>
    ${stats ? `<table><thead><tr><th>策略</th><th>嘗試</th><th>失敗</th><th>新族群</th><th>產出率</th></tr></thead><tbody>${stats}</tbody></table>`
            : `<p class="hint">strategy_stats 是空的。它只在 campaign 正常結束時寫入 —— 被 <code>timeout</code> 砍掉的輪次不會有。</p>`}

    <h2>型別</h2>
    <div>${kb.kinds
      .map((k) => {
        const n = kb!.families.filter((f) => f.kindLabel === k).length;
        return `<div><span class="swatch" style="background:${colorOf(k)}"></span>${esc(k)} <b>${n}</b></div>`;
      })
      .join("")}</div>`;
}

/* --------------------------------------------------------------- timeline */

function renderTimeline() {
  if (!kb) return;
  const dpr = window.devicePixelRatio || 1;
  const w = tlCanvas.clientWidth || 340;
  const h = 120;
  tlCanvas.width = w * dpr;
  tlCanvas.height = h * dpr;
  const ctx = tlCanvas.getContext("2d")!;
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);

  const withTime = kb.families.filter((f) => f.firstSeenMs > 0);
  if (withTime.length < 2) {
    ctx.fillStyle = "#8b93a5";
    ctx.font = '12px "Segoe UI", system-ui, sans-serif';
    ctx.fillText("資料不足，無法畫出發現軌跡。", 8, h / 2);
    return;
  }

  const t0 = Math.min(...withTime.map((f) => f.firstSeenMs));
  const t1 = Math.max(...withTime.map((f) => f.firstSeenMs));
  const span = Math.max(1, t1 - t0);
  const kinds = [...new Set(withTime.map((f) => f.kindLabel))].sort();
  const totals = new Map<string, number>();
  const maxTotal = withTime.length;

  const x = (t: number) => 6 + ((t - t0) / span) * (w - 12);
  const y = (n: number) => h - 16 - (n / maxTotal) * (h - 26);

  // Axis
  ctx.strokeStyle = "#232936";
  ctx.beginPath();
  ctx.moveTo(6, h - 16);
  ctx.lineTo(w - 6, h - 16);
  ctx.stroke();
  ctx.fillStyle = "#5b6478";
  ctx.font = '10px "Segoe UI", system-ui, sans-serif';
  ctx.fillText(new Date(t0).toISOString().slice(11, 19), 6, h - 4);
  const end = new Date(t1).toISOString().slice(11, 19);
  ctx.fillText(end, w - 6 - ctx.measureText(end).width, h - 4);

  // Cumulative step line per kind, drawn as a running total.
  let running = 0;
  ctx.lineWidth = 1.6;
  for (let i = 0; i < withTime.length; i++) {
    const f = withTime[i];
    totals.set(f.kindLabel, (totals.get(f.kindLabel) ?? 0) + 1);
    running++;
    if (i === 0) continue;
    ctx.strokeStyle = colorOf(f.kindLabel);
    ctx.beginPath();
    ctx.moveTo(x(withTime[i - 1].firstSeenMs), y(running - 1));
    ctx.lineTo(x(f.firstSeenMs), y(running - 1));
    ctx.lineTo(x(f.firstSeenMs), y(running));
    ctx.stroke();
  }
  void kinds;
}

/* ----------------------------------------------------------------- detail */

function replayCommand(target: string): string {
  const leaf = target.split(/[\\/]/).pop() ?? target;
  if (leaf.toLowerCase().endsWith(".py")) {
    return `python ${target} repro.bin`;
  }
  return `"${target}" repro.bin`;
}

function onSelect(family: Family) {
  const cases = (kb?.cases ?? []).filter((c) => c.familyId === family.id);
  const bytes = family.repro;

  detailEl.innerHTML = `
    <h2>族群</h2>
    <div class="sig">${esc(family.signature)}</div>

    <dl class="kv">
      <dt>ID</dt><dd>${esc(family.id)}</dd>
      <dt>型別</dt><dd><span class="swatch" style="background:${colorOf(family.kindLabel)}"></span>${esc(family.kindLabel)} · ${esc(family.code)}</dd>
      <dt>命中</dt><dd>${family.hitCount.toLocaleString()}</dd>
      <dt>案例</dt><dd>${family.caseCount.toLocaleString()}</dd>
      <dt>首見</dt><dd>${esc(family.firstSeen)}</dd>
      <dt>末見</dt><dd>${esc(family.lastSeen)}</dd>
      <dt>主要策略</dt><dd>${esc(family.topStrategy || "—")}</dd>
      <dt>repro</dt><dd>${family.reproLen} bytes</dd>
    </dl>

    ${
      bytes && bytes.length
        ? `<h2>反例內容</h2>
           <div class="row">
             <button data-act="download" type="button">下載 repro.bin</button>
           </div>
           <div class="hex">${esc(hexdump(bytes))}</div>
           <h2>文字檢視</h2>
           <div class="sig">${esc(family.reproText.slice(0, 4000))}</div>
           <h2>重放</h2>
           <p class="hint">控制台是唯讀的，不能在瀏覽器裡執行目標。把反例存下來，用引擎同一條路徑重跑：</p>
           <div class="cmd">${esc(replayCommand(kb?.runs[0]?.target ?? ""))}</div>`
        : `<h2>反例內容</h2>
           <p class="hint">這個族群沒有 <code>repro</code>（campaign 用 <code>--no-reduce</code> 跑的，或縮減被預算切斷）。存檔的案例仍可逐筆檢視。</p>`
    }

    <h2>案例 (${cases.length})</h2>
    ${
      cases.length
        ? `<table><thead><tr><th>大小</th><th>耗時</th><th>策略</th><th>repro</th></tr></thead><tbody>
           ${cases
             .slice(0, 60)
             .map(
               (c) => `<tr><td class="n">${c.contentLen}</td><td class="n">${c.elapsedMs}</td>
                        <td>${esc(c.strategy)}</td><td>${c.isRepro ? "✓" : ""}</td></tr>`,
             )
             .join("")}
           </tbody></table>${cases.length > 60 ? `<p class="hint">… 另有 ${cases.length - 60} 筆</p>` : ""}`
        : `<p class="hint">沒有。</p>`
    }`;

  const dl = detailEl.querySelector<HTMLButtonElement>('[data-act="download"]');
  dl?.addEventListener("click", () => {
    if (!bytes) return;
    const blob = new Blob([bytes as unknown as BlobPart], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${family.id}.bin`;
    a.click();
    URL.revokeObjectURL(url);
  });
}

/* ------------------------------------------------------------------- boot */

async function adopt(next: Kb) {
  kb = next;
  renderStats();
  renderSummary();
  renderTimeline();
  graph.setData(next);
  const first = next.families[0];
  if (first) onSelect(first);
}

fileEl.addEventListener("change", async () => {
  const file = fileEl.files?.[0];
  if (!file) return;
  status(`載入 ${file.name} …`);
  try {
    await adopt(await loadFromFile(file));
  } catch (err) {
    status(`無法讀取：${(err as Error).message}`, "bad");
  }
});

timeEl.addEventListener("input", () => {
  graph.setProgress(Number(timeEl.value) / 1000);
});

replayEl.addEventListener("click", () => {
  if (!kb?.families.length) return;
  const total = kb.families.length;
  let i = 0;
  timeEl.value = "0";
  const step = () => {
    i++;
    const frac = i / total;
    timeEl.value = String(Math.round(frac * 1000));
    graph.setProgress(frac);
    const current = kb!.families[Math.min(i - 1, total - 1)];
    if (current) onSelect(current);
    if (frac < 1) window.setTimeout(step, 260);
    else status(`重播完成：${total} 個族群。`, "good");
  };
  graph.setProgress(0);
  window.setTimeout(step, 200);
});

window.addEventListener("resize", renderTimeline);

// Default: the knowledge base served next to the app, if one is there.
// A campaign that was killed mid-run can leave a WAL behind, and SQLite
// only exposes committed state — so a stale-looking .db is worth reloading
// from disk after the campaign closes cleanly.
status("載入中…");
const loaded = await loadFromUrl("/kb.db");
if (loaded) {
  await adopt(loaded);
} else {
  status("未找到 /kb.db —— 點左上角「開啟 .db」選擇一個知識庫。");
}
