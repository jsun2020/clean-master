/* Clean Master frontend. Talks to the Rust side via Tauri commands only;
   every destructive action is confirmed here and re-validated in Rust. */
"use strict";

const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

const $ = (id) => document.getElementById(id);

// ------------------------------------------------------------- helpers --

function fmtBytes(n) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v.toFixed(0) : v.toFixed(1)) + " " + units[i];
}

function fmtCount(n) { return Number(n).toLocaleString("en-US"); }

function filesLabel(n) { return fmtCount(n) + (Number(n) === 1 ? " file" : " files"); }

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function timeAgo(unix) {
  if (!unix) return "";
  const s = Math.max(0, Math.floor(Date.now() / 1000) - unix);
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + " min ago";
  if (s < 86400) return Math.floor(s / 3600) + " h ago";
  return Math.floor(s / 86400) + " d ago";
}

function toast(msg, isErr) {
  const el = document.createElement("div");
  el.className = "toast" + (isErr ? " err" : "");
  el.textContent = msg;
  $("toasts").appendChild(el);
  setTimeout(() => { el.classList.add("gone"); setTimeout(() => el.remove(), 350); }, 5200);
}

function confirmModal(title, body, okLabel, okOnly) {
  return new Promise((resolve) => {
    $("modal-title").textContent = title;
    $("modal-body").textContent = body;
    $("modal-ok").textContent = okLabel || "Move to Recycle Bin";
    $("modal-cancel").hidden = Boolean(okOnly);
    $("overlay").hidden = false;
    const done = (v) => {
      $("overlay").hidden = true;
      $("modal-cancel").hidden = false;
      $("modal-ok").onclick = $("modal-cancel").onclick = null;
      resolve(v);
    };
    $("modal-ok").onclick = () => done(true);
    $("modal-cancel").onclick = () => done(false);
  });
}

/* Honest apply outcome: success -> toast; failures -> explain who holds the
   files (Restart Manager result from the Rust side) in an OK-only dialog. */
function showApplyResult(res, noun) {
  if (!res.failed) {
    toast("Recycled " + fmtCount(res.deleted) + " " + noun + ", freed " + fmtBytes(res.bytes) + ".");
    return { blockedMsg: null };
  }
  const who = res.holders && res.holders.length
    ? "They are in use by: " + res.holders.join(", ") + "."
    : "They are in use by running programs or protected by permissions.";
  const body =
    "Recycled " + fmtCount(res.deleted) + " " + noun + " (" + fmtBytes(res.bytes) + " freed). " +
    fmtCount(res.failed) + " could not be moved to the Recycle Bin. " + who +
    " Close those programs and rescan - until then, these files stay in the list and keep counting as reclaimable.";
  confirmModal("Some files are still in use", body, "OK", true);
  const blockedMsg = res.holders && res.holders.length
    ? "<b>" + fmtCount(res.failed) + " files</b> could not be cleaned - still held open by <b>" +
      esc(res.holders.join(", ")) + "</b>. Close those programs, then rescan."
    : "<b>" + fmtCount(res.failed) + " files</b> could not be cleaned - in use by running programs. Close them, then rescan.";
  return { blockedMsg };
}

function busyShow(title) {
  $("busy-title").textContent = title;
  $("busy-bar").style.width = "0%";
  $("busy-label").textContent = "";
  $("busy").hidden = false;
}
function busyHide() { $("busy").hidden = true; }

// ------------------------------------------------------------ nav ------

document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    ["junk", "dupes", "analyze", "dev"].forEach((v) => { $("view-" + v).hidden = v !== btn.dataset.view; });
  });
});

// --------------------------------------------------------- progress ----

listen("progress", (e) => {
  const { stage, label, seen } = e.payload;
  const text = fmtCount(seen) + " entries";
  if (stage === "junk-scan") $("junk-progress-label").textContent = label + " - " + text;
  else if (stage === "dupe-scan") $("dupes-progress-label").textContent = "scanning - " + text;
  else if (stage === "dupe-hash") $("dupes-progress-label").textContent = "verifying content (BLAKE3)...";
  else if (stage === "analyze-scan") $("an-progress-label").textContent = "scanning - " + text;
  else if (stage === "dev-scan") $("dev-progress-label").textContent = "scanning projects - " + fmtCount(seen) + " folders (sizing artifacts...)";
});

listen("apply-progress", (e) => {
  const { done, total } = e.payload;
  const pct = total ? Math.min(100, Math.round((done / total) * 100)) : 0;
  $("busy-bar").style.width = pct + "%";
  $("busy-label").textContent = fmtCount(done) + " / " + fmtCount(total);
});

// -------------------------------------------------------------- junk ---

const RULE_NAMES = {
  "win.user_temp": "User temp folder",
  "win.windows_temp": "Windows temp",
  "browser.chrome_cache": "Chrome cache",
  "browser.edge_cache": "Edge cache",
  "browser.firefox_cache": "Firefox cache",
  "win.thumbnail_cache": "Thumbnail cache",
  "win.update_download_cache": "Windows Update downloads",
  "win.user_crash_dumps": "Crash dumps",
  "win.error_reports": "Windows error reports",
};

let junkReport = null;
const junkSelected = new Set();
/* Set after an apply that had failures; shown as a banner on the rescan so
   the recurring "reclaimable" number is explained instead of looking stuck. */
let junkBlockedMsg = null;
/* Rule ids whose files could not be recycled (held open by a running app).
   These are greyed on the next scan and dropped from the reclaimable-now
   headline, until the user closes the app and hits Rescan. */
let junkBlockedRules = new Set();
let junkHolders = [];

async function junkScan() {
  $("junk-hero").innerHTML = 'Scanning<span class="dots"></span>';
  $("junk-sub").textContent = "Looking through known-safe junk locations. Nothing is deleted during a scan.";
  $("junk-progress").classList.add("on");
  $("junk-cards").innerHTML = "";
  $("junk-applybar").hidden = true;
  $("btn-junk-rescan").disabled = true;
  try {
    junkReport = await invoke("junk_scan");
    junkSelected.clear();
    // Auto-select everything with content EXCEPT rules known to be blocked
    // by a running app (they cannot be recycled until it closes).
    junkReport.rules.forEach((r) => {
      if (r.files > 0 && !junkBlockedRules.has(r.id)) junkSelected.add(r.id);
    });
    renderJunk();
  } catch (err) {
    toast(String(err), true);
    $("junk-hero").textContent = "Scan failed";
  } finally {
    $("junk-progress").classList.remove("on");
    $("btn-junk-rescan").disabled = false;
  }
}

function renderJunk() {
  const rep = junkReport;
  if (junkBlockedMsg) {
    $("junk-banner").innerHTML = junkBlockedMsg;
    $("junk-banner").hidden = false;
  } else {
    $("junk-banner").hidden = true;
  }
  const isBlocked = (r) => junkBlockedRules.has(r.id);
  const blockedBytes = rep.rules.filter(isBlocked).reduce((a, r) => a + r.bytes, 0);
  const blockedFiles = rep.rules.filter(isBlocked).reduce((a, r) => a + r.files, 0);
  const readyBytes = rep.total_bytes - blockedBytes;
  const readyFiles = rep.total_files - blockedFiles;

  $("junk-hero").innerHTML =
    "<strong>" + esc(fmtBytes(readyBytes)) + "</strong> reclaimable" + (blockedBytes > 0 ? " now" : "");
  if (blockedBytes > 0) {
    // The amber banner already names the holding apps; keep this line short.
    $("junk-sub").textContent =
      filesLabel(readyFiles) + " ready to clean now. " + fmtBytes(blockedBytes) +
      " is held open by running apps (see above).";
  } else {
    $("junk-sub").textContent =
      fmtCount(rep.total_files) + " junk files across " + rep.rules.length +
      " locations. This scan was a dry run - review, then clean what you select.";
  }

  const byCat = new Map();
  rep.rules.forEach((r) => {
    if (!byCat.has(r.category_label)) byCat.set(r.category_label, []);
    byCat.get(r.category_label).push(r);
  });
  const maxBytes = Math.max(1, ...rep.rules.map((r) => r.bytes));

  let html = "";
  for (const [cat, rules] of byCat) {
    // Category totals and the master checkbox reflect only what is actually
    // cleanable now (non-empty, non-blocked). Blocked rows show their own
    // size in grey so it is clear the space is real but currently stuck.
    const selectable = rules.filter((r) => r.files > 0 && !isBlocked(r));
    const catBytes = selectable.reduce((a, r) => a + r.bytes, 0);
    const anySelectable = selectable.length > 0;
    html += '<div class="card"><div class="cat-head">' +
      '<label class="chk"><input type="checkbox" data-cat="' + esc(cat) + '"' +
      (anySelectable ? " checked" : " disabled") + '><span class="box"></span></label>' +
      '<div class="cat-title">' + esc(cat) + '</div>' +
      '<div class="cat-bytes">' + esc(fmtBytes(catBytes)) + '</div></div>';
    for (const r of rules) {
      const name = RULE_NAMES[r.id] || r.id;
      const blocked = isBlocked(r);
      const empty = r.files === 0;
      const disabled = empty || blocked;
      const cls = "rule-row" + (blocked ? " blocked" : empty ? " empty" : "");
      html += '<div class="' + cls + '" title="' + esc(r.rationale) + '">' +
        '<label class="chk"><input type="checkbox" data-rule="' + esc(r.id) + '" data-cat-of="' + esc(cat) + '"' +
        (disabled ? " disabled" : " checked") + '><span class="box"></span></label>' +
        '<div class="rule-detail"><div class="rule-name">' + esc(name) +
        (blocked ? ' <span class="tag-inuse">in use</span>' : "") +
        (r.min_age_days > 0 ? ' <span class="rule-count">(older than ' + r.min_age_days + ' days only)</span>' : "") +
        '</div><div class="rule-base">' + esc(r.base) + '</div>' +
        '<div class="meter"><i style="width:' + Math.max(1, Math.round((r.bytes / maxBytes) * 100)) + '%"></i></div></div>' +
        '<div class="rule-count">' + filesLabel(r.files) + '</div>' +
        '<div class="rule-bytes">' + esc(fmtBytes(r.bytes)) + '</div></div>';
    }
    html += "</div>";
  }
  if (!rep.rules.length) html = '<div class="hint">No junk locations found on this system.</div>';
  $("junk-cards").innerHTML = html;

  document.querySelectorAll('#junk-cards input[data-rule]').forEach((cb) => {
    cb.addEventListener("change", () => {
      if (cb.checked) junkSelected.add(cb.dataset.rule); else junkSelected.delete(cb.dataset.rule);
      syncCatBoxes(); junkSelectionChanged();
    });
  });
  document.querySelectorAll('#junk-cards input[data-cat]').forEach((cb) => {
    cb.addEventListener("change", () => {
      document.querySelectorAll('#junk-cards input[data-cat-of="' + CSS.escape(cb.dataset.cat) + '"]').forEach((r) => {
        if (r.disabled) return;
        r.checked = cb.checked;
        if (cb.checked) junkSelected.add(r.dataset.rule); else junkSelected.delete(r.dataset.rule);
      });
      junkSelectionChanged();
    });
  });
  junkSelectionChanged();
}

function syncCatBoxes() {
  document.querySelectorAll('#junk-cards input[data-cat]').forEach((cb) => {
    const kids = [...document.querySelectorAll('#junk-cards input[data-cat-of="' + CSS.escape(cb.dataset.cat) + '"]')]
      .filter((k) => !k.disabled);
    cb.checked = kids.length > 0 && kids.every((k) => k.checked);
  });
}

function junkSelectionChanged() {
  if (!junkReport) return;
  let files = 0, bytes = 0;
  junkReport.rules.forEach((r) => {
    if (junkSelected.has(r.id)) { files += r.files; bytes += r.bytes; }
  });
  $("junk-sel-size").textContent = fmtBytes(bytes);
  $("junk-sel-files").textContent = filesLabel(files) + " in " + junkSelected.size + (junkSelected.size === 1 ? " rule" : " rules");
  $("junk-applybar").hidden = files === 0;
}

$("btn-junk-rescan").addEventListener("click", () => {
  // User is re-checking after acting on the notice: forget the blocked state
  // so files that are now free are re-offered; still-open ones will only be
  // re-flagged if a fresh clean attempt fails again.
  junkBlockedMsg = null;
  junkBlockedRules = new Set();
  junkHolders = [];
  junkScan();
});

$("btn-junk-clean").addEventListener("click", async () => {
  let files = 0, bytes = 0;
  junkReport.rules.forEach((r) => { if (junkSelected.has(r.id)) { files += r.files; bytes += r.bytes; } });
  const ok = await confirmModal(
    "Clean junk files?",
    "Move " + fmtCount(files) + " files (" + fmtBytes(bytes) + ") to the Recycle Bin? " +
    "Nothing is permanently deleted, and you can undo this from the sidebar.");
  if (!ok) return;
  busyShow("Moving to Recycle Bin");
  try {
    const res = await invoke("junk_apply", { ruleIds: [...junkSelected] });
    junkBlockedRules = new Set(res.blocked_rules || []);
    junkHolders = res.holders || [];
    junkBlockedMsg = showApplyResult(res, "files").blockedMsg;
    refreshUndo();
    junkScan();
  } catch (err) {
    toast(String(err), true);
  } finally { busyHide(); }
});

// -------------------------------------------------------------- dupes --

let dupesPath = null;
let dupesReport = null;
const dupesChecked = new Set();

$("btn-dupes-browse").addEventListener("click", async () => {
  const p = await invoke("pick_folder");
  if (!p) return;
  dupesPath = p;
  const el = $("dupes-path");
  el.textContent = p; el.classList.add("set");
  $("btn-dupes-scan").disabled = false;
});

$("btn-dupes-scan").addEventListener("click", async () => {
  if (!dupesPath) return;
  $("dupes-progress").classList.add("on");
  $("dupes-progress").hidden = false;
  $("dupes-groups").innerHTML = "";
  $("dupes-summary").hidden = true;
  $("dupes-applybar").hidden = true;
  $("btn-dupes-scan").disabled = true;
  try {
    dupesReport = await invoke("dupes_scan", {
      path: dupesPath,
      minSize: Number($("dupes-minsize").value),
    });
    dupesChecked.clear();
    dupesReport.groups.forEach((g) => dupesChecked.add(g.index));
    renderDupes();
  } catch (err) {
    toast(String(err), true);
  } finally {
    $("dupes-progress").classList.remove("on");
    $("btn-dupes-scan").disabled = false;
  }
});

function renderDupes() {
  const rep = dupesReport;
  if (!rep.group_count) {
    $("dupes-summary").hidden = true;
    $("dupes-groups").innerHTML = '<div class="hint">No duplicates found under<br><b>' + esc(rep.root) + '</b></div>';
    $("dupes-applybar").hidden = true;
    return;
  }
  $("dupes-summary").hidden = false;
  $("dupes-summary").innerHTML =
    '<div class="sum-item"><div class="k">Groups</div><div class="v">' + fmtCount(rep.group_count) + '</div></div>' +
    '<div class="sum-item"><div class="k">Redundant copies</div><div class="v">' + fmtCount(rep.redundant_files) + '</div></div>' +
    '<div class="sum-item"><div class="k">Reclaimable</div><div class="v"><em>' + esc(fmtBytes(rep.total_wasted)) + '</em></div></div>' +
    (rep.truncated ? '<div class="sum-item"><div class="k">Showing</div><div class="v">top ' + rep.groups.length + '</div></div>' : "");

  let html = "";
  for (const g of rep.groups) {
    html += '<div class="card"><div class="grp-head">' +
      '<label class="chk"><input type="checkbox" data-group="' + g.index + '" checked><span class="box"></span></label>' +
      '<div class="grp-title">' + g.members.length + ' identical copies - ' + esc(fmtBytes(g.size)) + ' each</div>' +
      '<span class="grp-hash">' + esc(g.hash12) + '</span>' +
      '<div class="grp-wasted">' + esc(fmtBytes(g.wasted)) + ' wasted</div></div>';
    for (const m of g.members) {
      html += '<div class="mem-row">' +
        (m.keep ? '<span class="badge-keep">KEEP</span>' : '<span class="badge-del">recycle</span>') +
        '<div class="mem-path">' + esc(m.path) + '</div></div>';
    }
    html += "</div>";
  }
  $("dupes-groups").innerHTML = html;

  document.querySelectorAll('#dupes-groups input[data-group]').forEach((cb) => {
    cb.addEventListener("change", () => {
      const idx = Number(cb.dataset.group);
      if (cb.checked) dupesChecked.add(idx); else dupesChecked.delete(idx);
      dupesSelectionChanged();
    });
  });
  dupesSelectionChanged();
}

function dupesSelectionChanged() {
  let bytes = 0, files = 0;
  dupesReport.groups.forEach((g) => {
    if (dupesChecked.has(g.index)) { bytes += g.wasted; files += g.members.length - 1; }
  });
  $("dupes-sel-size").textContent = fmtBytes(bytes);
  $("dupes-sel-files").textContent = fmtCount(files) + " redundant copies in " + dupesChecked.size + " groups";
  $("dupes-applybar").hidden = files === 0;
}

$("btn-dupes-clean").addEventListener("click", async () => {
  let bytes = 0, files = 0;
  dupesReport.groups.forEach((g) => {
    if (dupesChecked.has(g.index)) { bytes += g.wasted; files += g.members.length - 1; }
  });
  const ok = await confirmModal(
    "Recycle duplicate copies?",
    "Move " + fmtCount(files) + " redundant copies (" + fmtBytes(bytes) + ") to the Recycle Bin? " +
    "The copy marked KEEP always survives in every group.");
  if (!ok) return;
  busyShow("Moving to Recycle Bin");
  try {
    const res = await invoke("dupes_apply", { groupIndexes: [...dupesChecked] });
    showApplyResult(res, "copies");
    refreshUndo();
    $("dupes-groups").innerHTML = '<div class="hint">Done. Rescan to verify - the folder should now be duplicate-free.</div>';
    $("dupes-summary").hidden = true;
    $("dupes-applybar").hidden = true;
  } catch (err) {
    toast(String(err), true);
  } finally { busyHide(); }
});

// ------------------------------------------------------------ analyze --

let anPath = null;

$("btn-an-browse").addEventListener("click", async () => {
  const p = await invoke("pick_folder");
  if (!p) return;
  anPath = p;
  const el = $("an-path");
  el.textContent = p; el.classList.add("set");
  $("btn-an-scan").disabled = false;
});

$("btn-an-scan").addEventListener("click", async () => {
  if (!anPath) return;
  $("an-progress").classList.add("on");
  $("an-progress").hidden = false;
  $("an-panels").hidden = true;
  $("an-summary").hidden = true;
  $("btn-an-scan").disabled = true;
  try {
    const rep = await invoke("analyze_path", { path: anPath });
    renderAnalyze(rep);
  } catch (err) {
    toast(String(err), true);
  } finally {
    $("an-progress").classList.remove("on");
    $("btn-an-scan").disabled = false;
  }
});

function meterRow(name, bytes, maxBytes, extra) {
  return '<div class="row-wrap"><div class="row-line">' +
    '<div class="row-name" title="' + esc(name) + '">' + esc(name) + '</div>' +
    (extra ? '<div class="row-val" style="color:var(--ink-3);font-weight:400">' + esc(extra) + '</div>' : "") +
    '<div class="row-val">' + esc(fmtBytes(bytes)) + '</div></div>' +
    '<div class="meter"><i style="width:' + Math.max(1, Math.round((bytes / Math.max(1, maxBytes)) * 100)) + '%"></i></div></div>';
}

function renderAnalyze(rep) {
  $("an-hero").innerHTML = "<strong>" + esc(fmtBytes(rep.total_bytes)) + "</strong> in " + esc(shortRoot(rep.root));
  $("an-summary").hidden = false;
  $("an-summary").innerHTML =
    '<div class="sum-item"><div class="k">Total</div><div class="v"><em>' + esc(fmtBytes(rep.total_bytes)) + '</em></div></div>' +
    '<div class="sum-item"><div class="k">Files</div><div class="v">' + fmtCount(rep.files) + '</div></div>' +
    '<div class="sum-item"><div class="k">Folders</div><div class="v">' + fmtCount(rep.dirs) + '</div></div>' +
    (rep.skipped ? '<div class="sum-item"><div class="k">Unreadable</div><div class="v">' + fmtCount(rep.skipped) + '</div></div>' : "");

  const maxF = Math.max(1, ...rep.top_files.map((f) => f.bytes));
  $("an-files").innerHTML = rep.top_files.map((f) => meterRow(f.path, f.bytes, maxF)).join("") || '<div class="hint">Empty</div>';
  const maxD = Math.max(1, ...rep.top_dirs.map((d) => d.bytes));
  $("an-dirs").innerHTML = rep.top_dirs.map((d) => meterRow(d.path, d.bytes, maxD, fmtCount(d.files) + " files")).join("") || '<div class="hint">Empty</div>';
  const maxE = Math.max(1, ...rep.exts.map((x) => x.bytes));
  $("an-exts").innerHTML = rep.exts.map((x) => meterRow("." + x.ext, x.bytes, maxE, fmtCount(x.count) + " files")).join("") || '<div class="hint">Empty</div>';
  const maxA = Math.max(1, ...rep.ages.map((a) => a.bytes));
  $("an-ages").innerHTML = rep.ages.map((a) => meterRow(a.label, a.bytes, maxA, fmtCount(a.count) + " files")).join("");
  $("an-panels").hidden = false;
}

function shortRoot(p) {
  return p.length > 40 ? p.slice(0, 18) + "..." + p.slice(-18) : p;
}

// ---------------------------------------------------------- developer --

const DEV_KIND_ICON = {
  node_modules: "js", rust_target: "rs", maven_target: "mvn", gradle_build: "gr",
  gradle_cache: "gr", python_venv: "py", dotnet_obj: "net", dotnet_bin: "net",
};

let devPath = null;
let devReport = null;
const devChecked = new Set(); // artifact indexes; empty by default (opt-in)

$("btn-dev-browse").addEventListener("click", async () => {
  const p = await invoke("pick_folder");
  if (!p) return;
  devPath = p;
  const el = $("dev-path");
  el.textContent = p; el.classList.add("set");
  $("btn-dev-scan").disabled = false;
});

$("btn-dev-scan").addEventListener("click", async () => {
  if (!devPath) return;
  $("dev-progress").classList.add("on");
  $("dev-progress").hidden = false;
  $("dev-projects").innerHTML = "";
  $("dev-summary").hidden = true;
  $("dev-applybar").hidden = true;
  $("btn-dev-scan").disabled = true;
  try {
    devReport = await invoke("dev_scan", { path: devPath });
    devChecked.clear(); // nothing pre-selected: dev cleanup is always opt-in
    renderDev();
  } catch (err) {
    toast(String(err), true);
  } finally {
    $("dev-progress").classList.remove("on");
    $("btn-dev-scan").disabled = false;
  }
});

function renderDev() {
  const rep = devReport;
  if (!rep.project_count) {
    $("dev-summary").hidden = true;
    $("dev-projects").innerHTML =
      '<div class="hint">No developer projects with reclaimable folders found under<br><b>' +
      esc(rep.root) + '</b><br><br>Clean Master looks for node_modules, target, build, venvs and bin/obj that sit next to a project manifest.</div>';
    $("dev-applybar").hidden = true;
    return;
  }
  $("dev-hero").innerHTML = "<strong>" + esc(fmtBytes(rep.total_bytes)) + "</strong> in build &amp; dependency folders";
  $("dev-summary").hidden = false;
  $("dev-summary").innerHTML =
    '<div class="sum-item"><div class="k">Projects</div><div class="v">' + fmtCount(rep.project_count) + '</div></div>' +
    '<div class="sum-item"><div class="k">Artifact folders</div><div class="v">' + fmtCount(rep.artifact_count) + '</div></div>' +
    '<div class="sum-item"><div class="k">Reclaimable</div><div class="v"><em>' + esc(fmtBytes(rep.total_bytes)) + '</em></div></div>' +
    (rep.truncated ? '<div class="sum-item"><div class="k">Showing</div><div class="v">top ' + rep.projects.length + '</div></div>' : "");

  let html = "";
  for (const p of rep.projects) {
    html += '<div class="card"><div class="cat-head">' +
      '<label class="chk"><input type="checkbox" data-proj="' + esc(p.root) + '"><span class="box"></span></label>' +
      '<div class="cat-title">' + esc(p.name) + ' <span class="proj-path">' + esc(p.root) + '</span></div>' +
      '<div class="cat-bytes">' + esc(fmtBytes(p.total_bytes)) + '</div></div>';
    for (const a of p.artifacts) {
      const badge = (DEV_KIND_ICON[a.kind_id] || "dev").toUpperCase();
      html += '<div class="rule-row" title="' + esc(a.path) + '">' +
        '<label class="chk"><input type="checkbox" data-art="' + a.index + '" data-proj-of="' + esc(p.root) + '"><span class="box"></span></label>' +
        '<span class="kind-badge">' + esc(badge) + '</span>' +
        '<div class="rule-detail"><div class="rule-name">' + esc(a.dir_name) +
        ' <span class="rule-count">' + esc(a.kind_label) + '</span></div>' +
        '<div class="rule-base">restored by ' + esc(a.restore_hint) + '</div></div>' +
        '<div class="rule-count">' + filesLabel(a.files) + '</div>' +
        '<div class="rule-bytes">' + esc(fmtBytes(a.bytes)) + '</div></div>';
    }
    html += "</div>";
  }
  $("dev-projects").innerHTML = html;

  document.querySelectorAll('#dev-projects input[data-art]').forEach((cb) => {
    cb.addEventListener("change", () => {
      const idx = Number(cb.dataset.art);
      if (cb.checked) devChecked.add(idx); else devChecked.delete(idx);
      syncProjBoxes(); devSelectionChanged();
    });
  });
  document.querySelectorAll('#dev-projects input[data-proj]').forEach((cb) => {
    cb.addEventListener("change", () => {
      document.querySelectorAll('#dev-projects input[data-proj-of="' + CSS.escape(cb.dataset.proj) + '"]').forEach((a) => {
        a.checked = cb.checked;
        if (cb.checked) devChecked.add(Number(a.dataset.art)); else devChecked.delete(Number(a.dataset.art));
      });
      devSelectionChanged();
    });
  });
  devSelectionChanged();
}

function syncProjBoxes() {
  document.querySelectorAll('#dev-projects input[data-proj]').forEach((cb) => {
    const kids = [...document.querySelectorAll('#dev-projects input[data-proj-of="' + CSS.escape(cb.dataset.proj) + '"]')];
    cb.checked = kids.length > 0 && kids.every((k) => k.checked);
  });
}

function devSelectionChanged() {
  let bytes = 0;
  const byIndex = new Map();
  devReport.projects.forEach((p) => p.artifacts.forEach((a) => byIndex.set(a.index, a)));
  devChecked.forEach((i) => { const a = byIndex.get(i); if (a) bytes += a.bytes; });
  $("dev-sel-size").textContent = fmtBytes(bytes);
  $("dev-sel-files").textContent = devChecked.size
    ? filesLabel(devChecked.size).replace(/files?$/, devChecked.size === 1 ? "folder" : "folders") + " selected"
    : "nothing selected";
  $("dev-applybar").hidden = devChecked.size === 0;
}

$("btn-dev-clean").addEventListener("click", async () => {
  let bytes = 0;
  const byIndex = new Map();
  devReport.projects.forEach((p) => p.artifacts.forEach((a) => byIndex.set(a.index, a)));
  devChecked.forEach((i) => { const a = byIndex.get(i); if (a) bytes += a.bytes; });
  const n = devChecked.size;
  const ok = await confirmModal(
    "Recycle developer folders?",
    "Move " + n + " build/dependency folder" + (n === 1 ? "" : "s") + " (" + fmtBytes(bytes) + ") to the Recycle Bin? " +
    "These are regenerable (npm install, cargo build, etc.) and your source code is not affected.");
  if (!ok) return;
  busyShow("Moving folders to Recycle Bin");
  try {
    const res = await invoke("dev_apply", { artifactIndexes: [...devChecked] });
    showApplyResult(res, "folders");
    refreshUndo();
    $("dev-projects").innerHTML = '<div class="hint">Done. Rescan to see the current state.</div>';
    $("dev-summary").hidden = true;
    $("dev-applybar").hidden = true;
  } catch (err) {
    toast(String(err), true);
  } finally { busyHide(); }
});

// --------------------------------------------------------------- undo --

async function refreshUndo() {
  try {
    const st = await invoke("undo_status");
    if (st && st.files > 0) {
      $("undo-card").hidden = false;
      $("undo-meta").textContent =
        fmtCount(st.files) + " files - " + fmtBytes(st.bytes) + "\n" + timeAgo(st.at_unix);
    } else {
      $("undo-card").hidden = true;
    }
  } catch (_) { /* no manifest dir yet */ }
}

$("btn-undo").addEventListener("click", async () => {
  const ok = await confirmModal(
    "Undo last clean?",
    "Restore the files from the last clean out of the Recycle Bin, back to their original locations.",
    "Restore files");
  if (!ok) return;
  busyShow("Restoring from Recycle Bin");
  try {
    const res = await invoke("undo_last");
    toast("Restored " + fmtCount(res.restored) + " files." +
      (res.missing ? " " + fmtCount(res.missing) + " were no longer in the Recycle Bin." : ""));
    refreshUndo();
  } catch (err) {
    toast(String(err), true);
  } finally { busyHide(); }
});

// --------------------------------------------------------------- init --

refreshUndo();
junkScan();
