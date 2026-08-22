/* Clean Master frontend. Talks to the Rust side via Tauri commands only;
   every destructive action is confirmed here and re-validated in Rust.
   All user-visible text goes through t()/tf() (see i18n.js); the backend
   keeps sending stable ids plus English labels as the fallback. */
"use strict";

const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

const $ = (id) => document.getElementById(id);

// -------------------------------------------------------------- i18n ----

let lang = (() => {
  const saved = localStorage.getItem("cm.lang");
  if (saved === "en" || saved === "zh") return saved;
  return (navigator.language || "").toLowerCase().startsWith("zh") ? "zh" : "en";
})();

const dict = () => window.CM_I18N[lang];

function t(key) {
  return dict().ui[key] ?? window.CM_I18N.en.ui[key] ?? key;
}
function tf(key, vars) {
  let s = t(key);
  for (const [k, v] of Object.entries(vars)) s = s.split("{" + k + "}").join(String(v));
  return s;
}
/* Backend-label translators: keyed by id where one exists, otherwise by the
   exact English string the backend emits. Unknown -> backend text. */
const trRule = (id) => dict().rules[id] || window.CM_I18N.en.rules[id] || id;
const trRationale = (id, fallback) => dict().rationales[id] || fallback;
const trCat = (label) => dict().cats[label] || label;
const trKind = (kindId, fallback) => dict().kinds[kindId] || fallback;
const trHint = (hint) => dict().hints[hint] || hint;
const trAge = (label) => dict().ages[label] || label;

function applyStatic() {
  document.documentElement.lang = lang === "zh" ? "zh-CN" : "en";
  document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll("[data-i18n-html]").forEach((el) => { el.innerHTML = t(el.dataset.i18nHtml); });
  // Path placeholders keep the chosen path once one is set.
  [["dupes-path", "choose_folder_scan"], ["an-path", "choose_folder_drive"], ["dev-path", "choose_folder_projects"]]
    .forEach(([id, key]) => { const el = $(id); if (!el.classList.contains("set")) el.textContent = t(key); });
  document.querySelectorAll(".lang-btn").forEach((b) => b.classList.toggle("active", b.dataset.lang === lang));
}

function setLang(next) {
  if (next === lang) return;
  lang = next;
  localStorage.setItem("cm.lang", lang);
  applyStatic();
  // Re-render whatever data is on screen in the new language.
  if (junkReport) renderJunk();
  else if (junkScanning) { $("junk-hero").innerHTML = t("scanning") + '<span class="dots"></span>'; $("junk-sub").textContent = t("junk_scan_sub"); }
  else junkIdle();
  if (dupesReport) renderDupes();
  if (lastAnalyze) renderAnalyze(lastAnalyze);
  if (devReport) renderDev();
  if (appsReport) renderApps();
  if (tbReport) renderToolbox();
  refreshUndo();
}

document.querySelectorAll(".lang-btn").forEach((b) => {
  b.addEventListener("click", () => setLang(b.dataset.lang));
});

// ------------------------------------------------------------- helpers --

function fmtBytes(n) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v.toFixed(0) : v.toFixed(1)) + " " + units[i];
}

function fmtCount(n) { return Number(n).toLocaleString(lang === "zh" ? "zh-CN" : "en-US"); }

function filesLabel(n) {
  return tf(Number(n) === 1 ? "file_one" : "file_many", { n: fmtCount(n) });
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function timeAgo(unix) {
  if (!unix) return "";
  const s = Math.max(0, Math.floor(Date.now() / 1000) - unix);
  if (s < 60) return t("just_now");
  if (s < 3600) return tf("min_ago", { n: Math.floor(s / 60) });
  if (s < 86400) return tf("h_ago", { n: Math.floor(s / 3600) });
  if (s < 86400 * 30) return tf("d_ago", { n: Math.floor(s / 86400) });
  if (s < 86400 * 365) return tf("mo_ago", { n: Math.floor(s / (86400 * 30)) });
  return tf("y_ago", { n: Math.floor(s / (86400 * 365)) });
}

function toast(msg, isErr) {
  const el = document.createElement("div");
  el.className = "toast" + (isErr ? " err" : "");
  el.textContent = msg;
  $("toasts").appendChild(el);
  setTimeout(() => { el.classList.add("gone"); setTimeout(() => el.remove(), 350); }, 5200);
}

/* optLabel (optional): shows a checkbox under the body, unchecked by
   default; read its state via $("modal-opt-check").checked after OK. */
function confirmModal(title, body, okLabel, okOnly, optLabel) {
  return new Promise((resolve) => {
    $("modal-title").textContent = title;
    $("modal-body").textContent = body;
    $("modal-ok").textContent = okLabel || t("move_to_bin");
    $("modal-cancel").hidden = Boolean(okOnly);
    $("modal-opt").hidden = !optLabel;
    $("modal-opt-check").checked = false;
    if (optLabel) $("modal-opt-label").textContent = optLabel;
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
function showApplyResult(res, nounKey, permanent) {
  const noun = t(nounKey);
  if (!res.failed) {
    toast(tf(permanent ? "toast_deleted" : "toast_recycled",
      { n: fmtCount(res.deleted), noun, bytes: fmtBytes(res.bytes) }));
    return { blockedMsg: null };
  }
  const who = res.holders && res.holders.length
    ? tf("inuse_by", { who: res.holders.join(", ") })
    : t("inuse_generic");
  const body = tf("inuse_body", {
    n: fmtCount(res.deleted), noun, bytes: fmtBytes(res.bytes),
    failed: fmtCount(res.failed), who,
  });
  confirmModal(t("inuse_title"), body, t("ok"), true);
  const blockedMsg = res.holders && res.holders.length
    ? tf("banner_holders", { failed: fmtCount(res.failed), who: esc(res.holders.join(", ")) })
    : tf("banner_generic", { failed: fmtCount(res.failed) });
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
/* "Disk Files" is one nav entry holding two sub-tabs (Junk Clean and
   Duplicates); the underlying sections keep their ids and state. */

let filesTab = "junk";

function showView(v) {
  $("files-tabs").hidden = v !== "files";
  ["junk", "dupes", "analyze", "dev", "apps", "toolbox", "startup", "optimize"].forEach((s) => {
    $("view-" + s).hidden = v === "files" ? s !== filesTab : s !== v;
  });
  // The app list is cheap to build (registry / bundle listing): scan lazily
  // the first time the screen is opened.
  if (v === "apps" && !appsReport && !appsScanning) appsScan();
  // Toolbox: catalog + size probes, first time only (Rescan re-probes).
  if (v === "toolbox" && !tbReport && !tbLoading) toolboxLoad();
  // Startup: enumerate autostart entries the first time the screen opens.
  if (v === "startup" && !startupReport && !startupScanning) startupScan();
  // Optimize: read the current memory status the first time the screen opens.
  if (v === "optimize" && !memStatus) memRefresh();
}

document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    showView(btn.dataset.view);
  });
});

document.querySelectorAll("#files-tabs .subtab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#files-tabs .subtab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    filesTab = btn.dataset.tab;
    showView("files");
  });
});

// --------------------------------------------------------- progress ----

listen("progress", (e) => {
  const { stage, label, seen } = e.payload;
  if (stage === "junk-scan") $("junk-progress-label").textContent = label + " - " + tf("entries", { n: fmtCount(seen) });
  else if (stage === "dupe-scan") $("dupes-progress-label").textContent = tf("prog_scanning", { n: fmtCount(seen) });
  else if (stage === "dupe-hash") $("dupes-progress-label").textContent = t("prog_hashing");
  else if (stage === "analyze-scan") $("an-progress-label").textContent = tf("prog_scanning", { n: fmtCount(seen) });
  else if (stage === "dev-scan") $("dev-progress-label").textContent = tf("prog_dev", { n: fmtCount(seen) });
  else if (stage === "apps-scan") $("apps-progress-label").textContent = tf("prog_apps", { n: fmtCount(seen) });
});

listen("apply-progress", (e) => {
  const { done, total } = e.payload;
  const pct = total ? Math.min(100, Math.round((done / total) * 100)) : 0;
  $("busy-bar").style.width = pct + "%";
  $("busy-label").textContent = fmtCount(done) + " / " + fmtCount(total);
});

// -------------------------------------------------------------- junk ---

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
let junkScanning = false;

/* No scan runs until the user asks for one: scanning at startup costs a full
   disk walk on every launch (expensive under EDR) for a screen the user may
   not even be here for. Same lazy pattern as every other view. */
function junkIdle() {
  $("junk-hero").textContent = t("junk_hero_idle");
  $("junk-sub").textContent = t("junk_idle_sub");
}

async function junkScan() {
  junkScanning = true;
  const btn = $("btn-junk-rescan");
  btn.dataset.i18n = "rescan";
  btn.textContent = t("rescan");
  btn.classList.remove("primary");
  btn.classList.add("ghost");
  $("junk-hero").innerHTML = t("scanning") + '<span class="dots"></span>';
  $("junk-sub").textContent = t("junk_scan_sub");
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
      // Opt-in rules (privacy traces: recent files, browser history/cookies)
      // are left unchecked - the user must tick them deliberately.
      if (r.files > 0 && r.default_apply !== false && !junkBlockedRules.has(r.id))
        junkSelected.add(r.id);
    });
    renderJunk();
  } catch (err) {
    toast(String(err), true);
    $("junk-hero").textContent = t("scan_failed");
  } finally {
    junkScanning = false;
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

  $("junk-hero").innerHTML = tf(blockedBytes > 0 ? "junk_hero_ready_now" : "junk_hero_ready",
    { b: "<strong>" + esc(fmtBytes(readyBytes)) + "</strong>" });
  if (blockedBytes > 0) {
    // The amber banner already names the holding apps; keep this line short.
    $("junk-sub").textContent = tf("junk_sub_blocked",
      { files: filesLabel(readyFiles), blocked: fmtBytes(blockedBytes) });
  } else {
    $("junk-sub").textContent = tf("junk_sub_done",
      { count: fmtCount(rep.total_files), n: rep.rules.length });
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
    const allSelected = selectable.length > 0 && selectable.every((r) => junkSelected.has(r.id));
    html += '<div class="card"><div class="cat-head">' +
      '<label class="chk"><input type="checkbox" data-cat="' + esc(cat) + '"' +
      (selectable.length ? (allSelected ? " checked" : "") : " disabled") + '><span class="box"></span></label>' +
      '<div class="cat-title">' + esc(trCat(cat)) + '</div>' +
      '<div class="cat-bytes">' + esc(fmtBytes(catBytes)) + '</div></div>';
    for (const r of rules) {
      const blocked = isBlocked(r);
      const empty = r.files === 0;
      const disabled = empty || blocked;
      const cls = "rule-row" + (blocked ? " blocked" : empty ? " empty" : "");
      html += '<div class="' + cls + '" title="' + esc(trRationale(r.id, r.rationale)) + '">' +
        '<label class="chk"><input type="checkbox" data-rule="' + esc(r.id) + '" data-cat-of="' + esc(cat) + '"' +
        (disabled ? " disabled" : junkSelected.has(r.id) ? " checked" : "") + '><span class="box"></span></label>' +
        '<div class="rule-detail"><div class="rule-name">' + esc(trRule(r.id)) +
        (blocked ? ' <span class="tag-inuse">' + t("in_use") + '</span>' : "") +
        (r.default_apply === false ? ' <span class="tag-optin">' + t("opt_in") + '</span>' : "") +
        (r.min_age_days > 0 ? ' <span class="rule-count">' + esc(tf("older_than", { n: r.min_age_days })) + '</span>' : "") +
        '</div><div class="rule-base">' + esc(r.base) + '</div>' +
        '<div class="meter"><i style="width:' + Math.max(1, Math.round((r.bytes / maxBytes) * 100)) + '%"></i></div></div>' +
        '<div class="rule-count">' + filesLabel(r.files) + '</div>' +
        '<div class="rule-bytes">' + esc(fmtBytes(r.bytes)) + '</div></div>';
    }
    html += "</div>";
  }
  if (!rep.rules.length) html = '<div class="hint">' + t("junk_none") + '</div>';
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
  $("junk-sel-files").textContent = tf("junk_sel", {
    files: filesLabel(files), n: junkSelected.size,
    rules: t(junkSelected.size === 1 ? "word_rule" : "word_rules"),
  });
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
    t("confirm_junk_title"),
    tf("confirm_junk_body", { files: fmtCount(files), bytes: fmtBytes(bytes) }),
    null, false, t("opt_permanent"));
  if (!ok) return;
  const permanent = $("modal-opt-check").checked;
  busyShow(permanent ? t("busy_delete") : t("busy_recycle"));
  try {
    const res = await invoke("junk_apply", { ruleIds: [...junkSelected], permanent });
    junkBlockedRules = new Set(res.blocked_rules || []);
    junkHolders = res.holders || [];
    junkBlockedMsg = showApplyResult(res, "noun_files", permanent).blockedMsg;
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
    $("dupes-groups").innerHTML = '<div class="hint">' + t("dupes_none") + '<br><b>' + esc(rep.root) + '</b></div>';
    $("dupes-applybar").hidden = true;
    return;
  }
  $("dupes-summary").hidden = false;
  $("dupes-summary").innerHTML =
    '<div class="sum-item"><div class="k">' + t("sum_groups") + '</div><div class="v">' + fmtCount(rep.group_count) + '</div></div>' +
    '<div class="sum-item"><div class="k">' + t("sum_redundant") + '</div><div class="v">' + fmtCount(rep.redundant_files) + '</div></div>' +
    '<div class="sum-item"><div class="k">' + t("sum_reclaimable") + '</div><div class="v"><em>' + esc(fmtBytes(rep.total_wasted)) + '</em></div></div>' +
    (rep.truncated ? '<div class="sum-item"><div class="k">' + t("sum_showing") + '</div><div class="v">' + tf("top_n", { n: rep.groups.length }) + '</div></div>' : "");

  let html = "";
  for (const g of rep.groups) {
    html += '<div class="card"><div class="grp-head">' +
      '<label class="chk"><input type="checkbox" data-group="' + g.index + '"' +
      (dupesChecked.has(g.index) ? " checked" : "") + '><span class="box"></span></label>' +
      '<div class="grp-title">' + esc(tf("grp_title", { n: g.members.length, size: fmtBytes(g.size) })) + '</div>' +
      '<span class="grp-hash">' + esc(g.hash12) + '</span>' +
      '<div class="grp-wasted">' + esc(tf("grp_wasted", { bytes: fmtBytes(g.wasted) })) + '</div></div>';
    for (const m of g.members) {
      html += '<div class="mem-row">' +
        (m.keep ? '<span class="badge-keep">' + t("keep") + '</span>' : '<span class="badge-del">' + t("recycle_badge") + '</span>') +
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
  $("dupes-sel-files").textContent = tf("dupes_sel", { n: fmtCount(files), g: dupesChecked.size });
  $("dupes-applybar").hidden = files === 0;
}

$("btn-dupes-clean").addEventListener("click", async () => {
  let bytes = 0, files = 0;
  dupesReport.groups.forEach((g) => {
    if (dupesChecked.has(g.index)) { bytes += g.wasted; files += g.members.length - 1; }
  });
  const ok = await confirmModal(
    t("confirm_dupes_title"),
    tf("confirm_dupes_body", { n: fmtCount(files), bytes: fmtBytes(bytes) }));
  if (!ok) return;
  busyShow(t("busy_recycle"));
  try {
    const res = await invoke("dupes_apply", { groupIndexes: [...dupesChecked] });
    showApplyResult(res, "noun_copies");
    refreshUndo();
    $("dupes-groups").innerHTML = '<div class="hint">' + t("dupes_done") + '</div>';
    $("dupes-summary").hidden = true;
    $("dupes-applybar").hidden = true;
  } catch (err) {
    toast(String(err), true);
  } finally { busyHide(); }
});

// ------------------------------------------------------------ analyze --

let anPath = null;
let lastAnalyze = null;
let anOpenExt = null; // extension whose drill-down is expanded

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
  $("btn-an-scan").disabled = true;
  // Instant view: last saved snapshot of this root, if one exists. The
  // fresh scan then runs behind it (usually a quick USN-journal diff).
  let cachedShown = false;
  try {
    const cached = await invoke("analyze_cached", { path: anPath });
    if (cached) {
      lastAnalyze = cached;
      anOpenExt = null;
      renderAnalyze(cached);
      cachedShown = true;
    }
  } catch (_) { /* cache is best-effort; fall through to the scan */ }
  $("an-progress").classList.add("on");
  $("an-progress").hidden = false;
  if (!cachedShown) {
    $("an-panels").hidden = true;
    $("an-summary").hidden = true;
    $("an-fresh").hidden = true;
  }
  try {
    const rep = await invoke("analyze_path", { path: anPath });
    lastAnalyze = rep;
    anOpenExt = null;
    renderAnalyze(rep);
  } catch (err) {
    toast(String(err), true);
  } finally {
    $("an-progress").classList.remove("on");
    $("btn-an-scan").disabled = false;
  }
});

function fmtAge(secs) {
  if (secs < 90) return t("age_just_now");
  const m = Math.round(secs / 60);
  if (m < 90) return tf("age_minutes", { n: m });
  const h = Math.round(secs / 3600);
  if (h < 36) return tf("age_hours", { n: h });
  return tf("age_days", { n: Math.round(secs / 86400) });
}

function showFreshness(rep) {
  const el = $("an-fresh");
  el.hidden = false;
  el.classList.toggle("stale", !!rep.cached);
  if (rep.cached) el.textContent = tf("an_cached", { age: fmtAge(rep.age_secs) });
  else if (rep.method === "delta") el.textContent = tf("an_fresh_delta", { n: fmtCount(rep.delta_dirs) });
  else el.textContent = t("an_fresh_full");
}

/* Rows with a concrete path (full) are reveal targets: clicking opens the
   file manager with the item selected so the user can view or manually
   delete it - the second layer of Analyze, which itself stays read-only. */
function meterRow(name, bytes, maxBytes, extra, full) {
  const attrs = full
    ? ' reveal-row" data-path="' + esc(full)
    : "";
  const title = full ? full + "\n" + t("reveal_hint") : name;
  return '<div class="row-wrap' + attrs + '"><div class="row-line">' +
    '<div class="row-name" title="' + esc(title) + '">' + esc(name) + '</div>' +
    (extra ? '<div class="row-val" style="color:var(--ink-3);font-weight:400">' + esc(extra) + '</div>' : "") +
    '<div class="row-val">' + esc(fmtBytes(bytes)) + '</div></div>' +
    '<div class="meter"><i style="width:' + Math.max(1, Math.round((bytes / Math.max(1, maxBytes)) * 100)) + '%"></i></div></div>';
}

// Overview shows paths relative to the analyzed root (the absolute prefix is
// the same on every row); the full path lives in the hover tooltip.
function relToRoot(p, root) {
  if (root && p.length > root.length && p.toLowerCase().startsWith(root.toLowerCase())) {
    const rest = p.slice(root.length).replace(/^[\\/]+/, "");
    if (rest) return rest;
  }
  return p;
}

function renderAnalyze(rep) {
  $("an-hero").innerHTML = tf("an_hero", {
    b: "<strong>" + esc(fmtBytes(rep.total_bytes)) + "</strong>",
    root: esc(shortRoot(rep.root)),
  });
  $("an-summary").hidden = false;
  $("an-summary").innerHTML =
    '<div class="sum-item"><div class="k">' + t("sum_total") + '</div><div class="v"><em>' + esc(fmtBytes(rep.total_bytes)) + '</em></div></div>' +
    '<div class="sum-item"><div class="k">' + t("sum_files") + '</div><div class="v">' + fmtCount(rep.files) + '</div></div>' +
    '<div class="sum-item"><div class="k">' + t("sum_folders") + '</div><div class="v">' + fmtCount(rep.dirs) + '</div></div>' +
    (rep.skipped ? '<div class="sum-item"><div class="k">' + t("sum_unreadable") + '</div><div class="v">' + fmtCount(rep.skipped) + '</div></div>' : "");

  const maxF = Math.max(1, ...rep.top_files.map((f) => f.bytes));
  $("an-files").innerHTML = rep.top_files.map((f) => meterRow(relToRoot(f.path, rep.root), f.bytes, maxF, null, f.path)).join("") || '<div class="hint">' + t("empty") + '</div>';
  const maxD = Math.max(1, ...rep.top_dirs.map((d) => d.bytes));
  $("an-dirs").innerHTML = rep.top_dirs.map((d) => meterRow(relToRoot(d.path, rep.root), d.bytes, maxD, filesLabel(d.files), d.path)).join("") || '<div class="hint">' + t("empty") + '</div>';
  const maxE = Math.max(1, ...rep.exts.map((x) => x.bytes));
  $("an-exts").innerHTML = rep.exts.map((x, i) => {
    const open = anOpenExt === x.ext;
    const subMax = open && x.top.length ? Math.max(1, x.top[0].bytes) : 1;
    return '<div class="ext-group' + (open ? " open" : "") + '">' +
      '<div class="row-wrap ext-row" data-ext-i="' + i + '" title="' + esc(t("ext_click_hint")) + '"><div class="row-line">' +
      '<span class="caret"></span>' +
      '<div class="row-name">.' + esc(x.ext) + '</div>' +
      '<div class="row-val" style="color:var(--ink-3);font-weight:400">' + esc(filesLabel(x.count)) + '</div>' +
      '<div class="row-val">' + esc(fmtBytes(x.bytes)) + '</div></div>' +
      '<div class="meter"><i style="width:' + Math.max(1, Math.round((x.bytes / maxE) * 100)) + '%"></i></div></div>' +
      (open
        ? '<div class="sub-rows">' +
          (x.top.map((f) => meterRow(relToRoot(f.path, rep.root), f.bytes, subMax, null, f.path)).join("") ||
            '<div class="hint">' + t("empty") + '</div>') +
          '</div>'
        : "") +
      '</div>';
  }).join("") || '<div class="hint">' + t("empty") + '</div>';
  document.querySelectorAll("#an-exts .ext-row").forEach((el) => {
    el.addEventListener("click", () => {
      const ext = rep.exts[Number(el.dataset.extI)].ext;
      anOpenExt = anOpenExt === ext ? null : ext;
      renderAnalyze(rep);
    });
  });
  document.querySelectorAll("#an-panels .reveal-row").forEach((el) => {
    el.addEventListener("click", async () => {
      try { await invoke("reveal_path", { path: el.dataset.path }); }
      catch (err) { toast(String(err), true); }
    });
  });
  const maxA = Math.max(1, ...rep.ages.map((a) => a.bytes));
  $("an-ages").innerHTML = rep.ages.map((a) => meterRow(trAge(a.label), a.bytes, maxA, filesLabel(a.count))).join("");
  $("an-panels").hidden = false;
  showFreshness(rep);
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
  $("dev-toolbar").hidden = true;
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

/* All artifacts recommended for cleanup (stale > 30 days). */
function devRecommended() {
  const out = [];
  devReport.projects.forEach((p) => p.artifacts.forEach((a) => { if (a.recommended) out.push(a); }));
  return out;
}

function renderDev() {
  const rep = devReport;
  if (!rep.project_count) {
    $("dev-summary").hidden = true;
    $("dev-toolbar").hidden = true;
    $("dev-projects").innerHTML =
      '<div class="hint">' + t("dev_none") + '<br><b>' +
      esc(rep.root) + '</b><br><br>' + t("dev_none_hint") + '</div>';
    $("dev-applybar").hidden = true;
    return;
  }
  $("dev-hero").innerHTML = tf("dev_hero", { b: "<strong>" + esc(fmtBytes(rep.total_bytes)) + "</strong>" });
  $("dev-summary").hidden = false;
  $("dev-summary").innerHTML =
    '<div class="sum-item"><div class="k">' + t("sum_projects") + '</div><div class="v">' + fmtCount(rep.project_count) + '</div></div>' +
    '<div class="sum-item"><div class="k">' + t("sum_artifacts") + '</div><div class="v">' + fmtCount(rep.artifact_count) + '</div></div>' +
    '<div class="sum-item"><div class="k">' + t("sum_reclaimable") + '</div><div class="v"><em>' + esc(fmtBytes(rep.total_bytes)) + '</em></div></div>' +
    (rep.truncated ? '<div class="sum-item"><div class="k">' + t("sum_showing") + '</div><div class="v">' + tf("top_n", { n: rep.projects.length }) + '</div></div>' : "");

  // Toolbar: the recommend button carries its own count + size so the user
  // sees what one click will select before clicking it.
  const rec = devRecommended();
  const recBytes = rec.reduce((s, a) => s + a.bytes, 0);
  $("dev-toolbar").hidden = false;
  $("btn-dev-recommend").textContent = rec.length
    ? tf("select_recommended", { n: rec.length, bytes: fmtBytes(recBytes) })
    : t("select_recommended_none");
  $("btn-dev-recommend").disabled = rec.length === 0;

  let html = "";
  for (const p of rep.projects) {
    const allChecked = p.artifacts.length > 0 && p.artifacts.every((a) => devChecked.has(a.index));
    html += '<div class="card"><div class="cat-head">' +
      '<label class="chk"><input type="checkbox" data-proj="' + esc(p.root) + '"' +
      (allChecked ? " checked" : "") + '><span class="box"></span></label>' +
      '<div class="cat-title">' + esc(p.name) + ' <span class="proj-path">' + esc(p.root) + '</span></div>' +
      '<div class="cat-bytes">' + esc(fmtBytes(p.total_bytes)) + '</div></div>';
    for (const a of p.artifacts) {
      const badge = (DEV_KIND_ICON[a.kind_id] || "dev").toUpperCase();
      // Activity tag: stale = green "recommended", recent = amber heads-up
      // that the next build will re-download/re-compile. Unknown = no tag.
      let tag = "";
      if (a.recommended) {
        tag = ' <span class="tag-rec">' + esc(tf("dev_tag_stale", { ago: timeAgo(a.last_used_unix) })) + '</span>';
      } else if (a.last_used_unix > 0) {
        tag = ' <span class="tag-active">' + esc(tf("dev_tag_active", { ago: timeAgo(a.last_used_unix) })) + '</span>';
      }
      html += '<div class="rule-row" title="' + esc(a.path) + '">' +
        '<label class="chk"><input type="checkbox" data-art="' + a.index + '" data-proj-of="' + esc(p.root) + '"' +
        (devChecked.has(a.index) ? " checked" : "") + '><span class="box"></span></label>' +
        '<span class="kind-badge">' + esc(badge) + '</span>' +
        '<div class="rule-detail"><div class="rule-name">' + esc(a.dir_name) +
        ' <span class="rule-count">' + esc(trKind(a.kind_id, a.kind_label)) + '</span>' + tag + '</div>' +
        '<div class="rule-base">' + esc(tf("restored_by", { hint: trHint(a.restore_hint) })) + '</div></div>' +
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

/* Replace the selection wholesale (toolbar buttons), then re-render so row
   and project checkboxes reflect it. */
function devSetSelection(indexes) {
  devChecked.clear();
  indexes.forEach((i) => devChecked.add(i));
  renderDev();
}

$("btn-dev-recommend").addEventListener("click", () => {
  if (!devReport) return;
  devSetSelection(devRecommended().map((a) => a.index));
});
$("btn-dev-all").addEventListener("click", () => {
  if (!devReport) return;
  const all = [];
  devReport.projects.forEach((p) => p.artifacts.forEach((a) => all.push(a.index)));
  devSetSelection(all);
});
$("btn-dev-none").addEventListener("click", () => {
  if (!devReport) return;
  devSetSelection([]);
});

function devSelectionChanged() {
  let bytes = 0;
  const byIndex = new Map();
  devReport.projects.forEach((p) => p.artifacts.forEach((a) => byIndex.set(a.index, a)));
  devChecked.forEach((i) => { const a = byIndex.get(i); if (a) bytes += a.bytes; });
  $("dev-sel-size").textContent = fmtBytes(bytes);
  $("dev-sel-files").textContent = devChecked.size === 0
    ? t("nothing_selected")
    : devChecked.size === 1 ? t("folder_selected") : tf("folders_selected", { n: devChecked.size });
  $("dev-applybar").hidden = devChecked.size === 0;
}

$("btn-dev-clean").addEventListener("click", async () => {
  let bytes = 0;
  const byIndex = new Map();
  devReport.projects.forEach((p) => p.artifacts.forEach((a) => byIndex.set(a.index, a)));
  devChecked.forEach((i) => { const a = byIndex.get(i); if (a) bytes += a.bytes; });
  const n = devChecked.size;
  const ok = await confirmModal(
    t("confirm_dev_title"),
    tf("confirm_dev_body", {
      n, bytes: fmtBytes(bytes),
      folders: t(n === 1 ? "word_folder" : "word_folders"),
    }),
    null, false, t("opt_permanent_dev"));
  if (!ok) return;
  const permanent = $("modal-opt-check").checked;
  busyShow(permanent ? t("busy_delete_folders") : t("busy_recycle_folders"));
  try {
    const res = await invoke("dev_apply", { artifactIndexes: [...devChecked], permanent });
    showApplyResult(res, "noun_folders", permanent);
    refreshUndo();
    $("dev-projects").innerHTML = '<div class="hint">' + t("dev_done") + '</div>';
    $("dev-summary").hidden = true;
    $("dev-toolbar").hidden = true;
    $("dev-applybar").hidden = true;
  } catch (err) {
    toast(String(err), true);
  } finally { busyHide(); }
});

// --------------------------------------------------------------- apps --

const APP_FLAG_KEYS = { unused: "flag_unused", old: "flag_old", bundleware: "flag_bundleware" };

let appsReport = null;
let appsScanning = false;
let appsFilter = "all";

async function appsScan() {
  appsScanning = true;
  $("apps-progress").hidden = false;
  $("apps-progress").classList.add("on");
  $("apps-list").innerHTML = "";
  $("apps-summary").hidden = true;
  $("apps-chips").hidden = true;
  $("btn-apps-rescan").disabled = true;
  try {
    appsReport = await invoke("apps_scan");
    renderApps();
  } catch (err) {
    toast(String(err), true);
  } finally {
    appsScanning = false;
    $("apps-progress").classList.remove("on");
    $("apps-progress").hidden = true;
    $("btn-apps-rescan").disabled = false;
  }
}

function appMatchesFilter(a) {
  if (appsFilter === "all") return true;
  if (appsFilter === "flagged") return a.flags.length > 0;
  return a.flags.includes(appsFilter);
}

function renderApps() {
  const rep = appsReport;
  $("apps-hero").innerHTML = tf("apps_hero", {
    n: fmtCount(rep.app_count),
    b: "<strong>" + esc(fmtBytes(rep.total_bytes)) + "</strong>",
  });
  $("apps-summary").hidden = false;
  $("apps-summary").innerHTML =
    '<div class="sum-item"><div class="k">' + t("sum_apps") + '</div><div class="v">' + fmtCount(rep.app_count) + '</div></div>' +
    '<div class="sum-item"><div class="k">' + t("sum_total") + '</div><div class="v"><em>' + esc(fmtBytes(rep.total_bytes)) + '</em></div></div>' +
    '<div class="sum-item"><div class="k">' + t("sum_flagged") + '</div><div class="v">' + fmtCount(rep.flagged_count) + '</div></div>';
  // A filter chip with nothing behind it is a dead control - hide it. If the
  // active filter just became empty (e.g. after a rescan), fall back to All.
  const flagCounts = {};
  for (const a of rep.apps) {
    for (const f of a.flags) flagCounts[f] = (flagCounts[f] || 0) + 1;
  }
  const chipEmpty = (f) =>
    f === "flagged" ? rep.flagged_count === 0 : f !== "all" && !flagCounts[f];
  if (chipEmpty(appsFilter)) appsFilter = "all";
  $("apps-chips").hidden = false;
  document.querySelectorAll("#apps-chips .chip").forEach((c) => {
    c.hidden = chipEmpty(c.dataset.filter);
    c.classList.toggle("active", c.dataset.filter === appsFilter);
  });

  if (!rep.apps.length) {
    $("apps-list").innerHTML = '<div class="hint">' + t("apps_none") + '</div>';
    return;
  }
  const shown = rep.apps.filter(appMatchesFilter);
  if (!shown.length) {
    $("apps-list").innerHTML = '<div class="hint">' + t("apps_filter_empty") + '</div>';
    return;
  }

  let html = '<div class="card">';
  for (const a of shown) {
    const meta = [];
    if (a.version) meta.push(esc(a.version));
    if (a.publisher) meta.push(esc(a.publisher));
    if (a.install_date) meta.push(esc(tf("installed_on", { d: a.install_date })));
    meta.push(a.last_used_unix
      ? esc(tf("last_used_est", { ago: timeAgo(a.last_used_unix) }))
      : t("usage_unknown"));
    const tags = a.flags.map((f) =>
      '<span class="tag-flag' + (f === "bundleware" ? " warn" : "") + '">' +
      t(APP_FLAG_KEYS[f] || f) + '</span>').join("");
    html += '<div class="app-row" title="' + esc(a.location || a.name) + '">' +
      '<div class="rule-detail"><div class="rule-name">' + esc(a.name) + tags + '</div>' +
      '<div class="rule-base">' + meta.join(" &middot; ") + '</div></div>' +
      '<div class="rule-bytes">' + (a.bytes ? esc(fmtBytes(a.bytes)) : "-") + '</div>' +
      '<button class="btn ghost small" data-uninstall="' + a.index + '">' + t("uninstall") + '</button></div>';
  }
  html += "</div>";
  $("apps-list").innerHTML = html;

  document.querySelectorAll("#apps-list [data-uninstall]").forEach((btn) => {
    btn.addEventListener("click", () => uninstallApp(Number(btn.dataset.uninstall)));
  });
}

document.querySelectorAll("#apps-chips .chip").forEach((c) => {
  c.addEventListener("click", () => {
    appsFilter = c.dataset.filter;
    if (appsReport) renderApps();
  });
});

$("btn-apps-rescan").addEventListener("click", appsScan);

async function uninstallApp(index) {
  const a = appsReport.apps.find((x) => x.index === index);
  if (!a) return;
  const isTrash = a.removal === "trash";
  const ok = await confirmModal(
    tf("confirm_uninstall_title", { name: a.name }),
    isTrash ? tf("confirm_trash_body", { name: a.name }) : t("confirm_uninstall_body"),
    isTrash ? t("move_to_bin") : t("launch_uninstaller"));
  if (!ok) return;
  try {
    const res = await invoke("app_uninstall", { index });
    if (res.launched) {
      // Windows: the vendor uninstaller now owns the flow; the list refreshes
      // when the user hits Rescan after finishing it.
      toast(tf("toast_uninstaller", { name: a.name }));
    } else if (res.recycled > 0) {
      toast(tf("toast_app_trashed", { name: a.name, bytes: fmtBytes(res.bytes) }));
      refreshUndo();
      appsScan();
    } else {
      toast(tf("toast_app_trash_failed", { name: a.name }), true);
    }
  } catch (err) {
    toast(String(err), true);
  }
}

// ------------------------------------------------------------ toolbox --
/* Curated maintenance tools. The webview only ever sends a tool id + a mode
   ("check" | "action" | "open") and, for the winget search card, the typed
   term; the Rust side re-derives every command line from its catalog. */

let tbReport = null;
let tbLoading = false;
let tbCat = "storage";
let tbRunningId = null;
const tbInputs = {};   // tool id -> last typed term (survives re-render)
const TB_MAX_LINES = 2000;

/* Tool text: translated by tool id when the dictionary has it, else the
   backend's English. */
function trTool(id, field, fallback) {
  const d = dict().tools && dict().tools[id];
  return (d && d[field]) || fallback;
}
function trReason(id) {
  return (dict().tb_reasons && dict().tb_reasons[id]) || (window.CM_I18N.en.tb_reasons[id]) || id;
}

async function toolboxLoad() {
  tbLoading = true;
  $("btn-tb-refresh").disabled = true;
  try {
    tbReport = await invoke("toolbox_list");
    renderToolbox();
  } catch (err) {
    toast(String(err), true);
  } finally {
    tbLoading = false;
    $("btn-tb-refresh").disabled = false;
  }
}

function renderToolbox() {
  const rep = tbReport;
  if (!rep.supported) {
    $("tb-admin").hidden = true;
    $("tb-chips").hidden = true;
    $("tb-list").innerHTML = '<div class="hint">' + t("tb_windows_only") + '</div>';
    return;
  }
  $("tb-admin").hidden = rep.elevated;
  $("tb-chips").hidden = false;
  document.querySelectorAll("#tb-chips .chip").forEach((c) => {
    c.classList.toggle("active", c.dataset.cat === tbCat);
  });

  const shown = rep.tools.filter((x) => x.category === tbCat);
  if (!shown.length) {
    $("tb-list").innerHTML = '<div class="hint">' + t("tb_cat_empty") + '</div>';
    return;
  }
  let html = '<div class="card">';
  for (const x of shown) {
    const admin = x.needs_admin && !rep.elevated;
    const busy = tbRunningId !== null;
    const off = admin || Boolean(x.unavailable);
    const tags = [];
    if (x.needs_admin) tags.push('<span class="tag-flag' + (admin ? " warn" : "") + '">' + t("tb_tag_admin") + "</span>");
    if (x.reboot) tags.push('<span class="tag-flag warn">' + t("tb_tag_reboot") + "</span>");
    if (x.long_running) tags.push('<span class="tag-flag">' + t("tb_tag_long") + "</span>");
    const size = x.probe_bytes !== null && x.probe_bytes !== undefined
      ? '<div class="rule-bytes">' + esc(fmtBytes(x.probe_bytes)) + "</div>"
      : '<div class="rule-bytes tb-nosize">-</div>';
    const note = x.unavailable
      ? '<div class="rule-note tb-unavail">' + esc(trReason(x.unavailable)) + "</div>"
      : "";
    const cmdLine = x.check_cmd || x.action_cmd
      ? '<div class="rule-base" title="' + esc(x.action_cmd || x.check_cmd) + '">' +
        esc((x.check_cmd || x.action_cmd).split("\n")[0]) + "</div>"
      : "";
    const input = x.takes_input
      ? '<div class="tb-input-row"><input class="tb-input" data-tb-input="' + x.id +
        '" placeholder="' + esc(t("tb_winget_ph")) + '" value="' + esc(tbInputs[x.id] || "") +
        '" ' + (off ? "disabled" : "") + "></div>"
      : "";
    const btns = [];
    if (x.has_check) btns.push('<button class="btn ghost small" data-tb-run="' + x.id + '" data-tb-mode="check"' +
      (off || busy ? " disabled" : "") + ">" + esc(trTool(x.id, "check", x.check_label)) + "</button>");
    if (x.has_action) btns.push('<button class="btn primary small" data-tb-run="' + x.id + '" data-tb-mode="action"' +
      (off || busy ? " disabled" : "") + ">" + esc(trTool(x.id, "action", x.action_label)) + "</button>");
    if (x.has_open) btns.push('<button class="btn ghost small" data-tb-run="' + x.id + '" data-tb-mode="open"' +
      (off ? " disabled" : "") + ">" + t("tb_open") + "</button>");
    html += '<div class="app-row tb-row' + (off ? " tb-off" : "") + '">' +
      '<div class="rule-detail"><div class="rule-name">' + esc(trTool(x.id, "name", x.name)) + tags.join("") + "</div>" +
      '<div class="tb-blurb">' + esc(trTool(x.id, "blurb", x.blurb)) + "</div>" + cmdLine + note + input + "</div>" +
      size + '<div class="tb-btns">' + btns.join("") + "</div></div>";
  }
  html += "</div>";
  $("tb-list").innerHTML = html;

  document.querySelectorAll("#tb-list [data-tb-run]").forEach((btn) => {
    btn.addEventListener("click", () => toolboxRun(btn.dataset.tbRun, btn.dataset.tbMode));
  });
  document.querySelectorAll("#tb-list [data-tb-input]").forEach((inp) => {
    inp.addEventListener("input", () => { tbInputs[inp.dataset.tbInput] = inp.value; });
    inp.addEventListener("keydown", (e) => {
      if (e.key === "Enter") toolboxRun(inp.dataset.tbInput, "check");
    });
  });
}

document.querySelectorAll("#tb-chips .chip").forEach((c) => {
  c.addEventListener("click", () => {
    tbCat = c.dataset.cat;
    if (tbReport) renderToolbox();
  });
});

$("btn-tb-refresh").addEventListener("click", toolboxLoad);

$("btn-tb-elevate").addEventListener("click", async () => {
  const ok = await confirmModal(t("tb_elevate_title"), t("tb_elevate_body"), t("tb_restart_admin"));
  if (!ok) return;
  try {
    await invoke("toolbox_elevate");
    // On success the app exits; nothing more to do here.
  } catch (err) {
    toast(String(err), true);
  }
});

/* Console: DISM redraws a progress bar with \r - collapse consecutive
   progress lines into one so the log stays readable. Strip VT escapes that
   winget emits even when piped. */
const TB_ANSI = /\x1b\[[0-9;?]*[ -\/]*[@-~]/g;
/* DISM "[=====  42.0%  =====]", winget spinner frames "- \ | /" and block
   bars "████░░ 1.2 MB / 3.4 MB": only bar/spinner glyphs plus numbers. */
const TB_PROGRESS = /^(?:[\s\-\\|\/=\[\]\u2588\u2593\u2592\u2591]|\d[\d.,]*\s*(?:%|[KMGT]?i?B)?)+$/;
let tbLastWasProgress = false;

function tbConsoleLine(line) {
  const out = $("tb-console-out");
  const clean = line.replace(TB_ANSI, "");
  const trimmed = clean.trim();
  const isProg = trimmed.length > 0 && TB_PROGRESS.test(trimmed);
  if (isProg && tbLastWasProgress && out.lastChild) {
    out.lastChild.textContent = clean + "\n";
  } else {
    const span = document.createElement("span");
    span.textContent = clean + "\n";
    if (clean.startsWith("> ")) span.className = "tb-cmd";
    out.appendChild(span);
    while (out.childNodes.length > TB_MAX_LINES) out.removeChild(out.firstChild);
  }
  tbLastWasProgress = isProg;
  out.scrollTop = out.scrollHeight;
}

listen("tool-line", (e) => {
  if (e.payload && typeof e.payload.line === "string") tbConsoleLine(e.payload.line);
});

$("btn-tb-clear").addEventListener("click", () => {
  $("tb-console-out").textContent = "";
  tbLastWasProgress = false;
  if (tbRunningId === null) {
    $("tb-console").hidden = true;
    $("tb-console-status").textContent = "";
  }
});

$("btn-tb-cancel").addEventListener("click", async () => {
  try { await invoke("toolbox_cancel"); } catch (err) { toast(String(err), true); }
});

async function toolboxRun(id, mode) {
  if (!tbReport) return;
  const x = tbReport.tools.find((tt) => tt.id === id);
  if (!x) return;
  if (tbRunningId !== null && mode !== "open") { toast(t("tb_busy"), true); return; }
  const name = trTool(id, "name", x.name);
  let input = null;
  if (x.takes_input) {
    input = (tbInputs[id] || "").trim();
    if (!input) { toast(t("tb_need_term"), true); return; }
  }
  if (mode === "action") {
    let cmd = x.action_cmd;
    if (x.takes_input) cmd = cmd.replace("<term>", input);
    let body = tf("tb_confirm_body", { name, cmd });
    if (x.reboot) body += "\n\n" + t("tb_confirm_reboot");
    if (x.long_running) body += "\n\n" + t("tb_confirm_long");
    const ok = await confirmModal(tf("tb_confirm_title", { name }), body,
      trTool(id, "action", x.action_label));
    if (!ok) return;
  }
  if (mode === "open") {
    try { await invoke("toolbox_run", { id, mode, input: null }); }
    catch (err) { toast(String(err), true); }
    return;
  }

  tbRunningId = id;
  renderToolbox();
  $("tb-console").hidden = false;
  $("tb-console").scrollIntoView({ behavior: "smooth", block: "nearest" });
  $("tb-console-title").textContent = name;
  $("tb-console-status").textContent = t("tb_running");
  $("tb-console-status").className = "tb-console-status run";
  $("btn-tb-cancel").hidden = false;
  tbLastWasProgress = false;
  try {
    const res = await invoke("toolbox_run", { id, mode, input });
    const st = $("tb-console-status");
    if (res.cancelled) { st.textContent = t("tb_cancelled"); st.className = "tb-console-status warn"; }
    else if (res.success) { st.textContent = t("tb_done"); st.className = "tb-console-status ok"; }
    else { st.textContent = tf("tb_failed", { code: res.exit_code === null ? "?" : res.exit_code }); st.className = "tb-console-status err"; }
    if (res.success && mode === "action") toast(tf("tb_toast_done", { name }));
  } catch (err) {
    $("tb-console-status").textContent = t("tb_error");
    $("tb-console-status").className = "tb-console-status err";
    tbConsoleLine(String(err));
    toast(String(err), true);
  } finally {
    tbRunningId = null;
    $("btn-tb-cancel").hidden = true;
    // Actions change what the probes measure (hiberfil gone, cache empty):
    // reload the catalog so the sizes and availability are honest.
    if (mode === "action") toolboxLoad(); else renderToolbox();
  }
}

// --------------------------------------------------------------- undo --

async function refreshUndo() {
  try {
    const st = await invoke("undo_status");
    if (st && st.files > 0) {
      $("undo-card").hidden = false;
      $("undo-meta").textContent =
        filesLabel(st.files) + " - " + fmtBytes(st.bytes) + "\n" + timeAgo(st.at_unix);
    } else {
      $("undo-card").hidden = true;
    }
  } catch (_) { /* no manifest dir yet */ }
}

$("btn-undo").addEventListener("click", async () => {
  const ok = await confirmModal(
    t("undo_confirm_title"),
    t("undo_confirm_body"),
    t("restore_files"));
  if (!ok) return;
  busyShow(t("busy_restore"));
  try {
    const res = await invoke("undo_last");
    toast(tf("toast_restored", { n: fmtCount(res.restored) }) +
      (res.missing ? " " + tf("toast_missing", { n: fmtCount(res.missing) }) : ""));
    refreshUndo();
  } catch (err) {
    toast(String(err), true);
  } finally { busyHide(); }
});

// --------------------------------------------------------------- startup

let startupReport = null;
let startupScanning = false;

async function startupScan() {
  startupScanning = true;
  $("startup-progress").hidden = false;
  $("startup-progress-label").textContent = t("startup_scanning");
  $("btn-startup-rescan").disabled = true;
  try {
    startupReport = await invoke("startup_scan");
    renderStartup();
  } catch (err) {
    toast(String(err), true);
  } finally {
    startupScanning = false;
    $("startup-progress").hidden = true;
    $("btn-startup-rescan").disabled = false;
  }
}

function renderStartup() {
  const rep = startupReport;
  if (!rep) return;
  $("startup-summary").hidden = false;
  const highN = rep.entries.filter((e) => e.impact === "high").length;
  $("startup-summary").textContent =
    tf("startup_summary", { on: fmtCount(rep.enabled), n: fmtCount(rep.total) }) +
    (highN ? "  •  " + tf("startup_high", { n: fmtCount(highN) }) : "");
  const anyAdmin = rep.entries.some((e) => e.requires_admin);
  $("startup-admin").hidden = rep.elevated || !anyAdmin;
  if (!rep.entries.length) {
    $("startup-list").innerHTML = '<div class="hint">' + t("startup_none") + "</div>";
    return;
  }
  let html = "";
  for (const e of rep.entries) {
    const blocked = e.requires_admin && !rep.elevated;
    const admin = e.requires_admin
      ? ' <span class="tag-optin' + (blocked ? " warn" : "") + '">' + t("st_admin") + "</span>"
      : "";
    const impact =
      ' <span class="tag-impact impact-' + e.impact + '" title="' + esc(t("st_impact_hint")) +
      '">' + t("impact_" + e.impact) + "</span>";
    const label = e.enabled ? t("st_disable") : t("st_enable");
    const btn = blocked
      ? '<button class="btn small ghost" disabled title="' + esc(t("st_needs_admin")) + '">' + label + "</button>"
      : e.enabled
      ? '<button class="btn small ghost" data-toggle="' + e.index + '" data-enable="0">' + t("st_disable") + "</button>"
      : '<button class="btn small primary" data-toggle="' + e.index + '" data-enable="1">' + t("st_enable") + "</button>";
    html +=
      '<div class="card startup-row' + (e.enabled ? "" : " off") + '">' +
      '<div class="rule-detail"><div class="rule-name">' + esc(e.name) + impact + admin +
      (e.enabled ? "" : ' <span class="tag-inuse">' + t("st_off") + "</span>") +
      '</div><div class="rule-base">' + esc(e.location) + "  •  " + esc(e.command) + "</div></div>" +
      btn +
      "</div>";
  }
  $("startup-list").innerHTML = html;
  document.querySelectorAll("#startup-list [data-toggle]").forEach((b) => {
    b.addEventListener("click", () =>
      startupToggle(Number(b.dataset.toggle), b.dataset.enable === "1"));
  });
}

async function startupToggle(index, enable) {
  try {
    startupReport = await invoke("startup_toggle", { index, enable });
    renderStartup();
    toast(enable ? t("toast_startup_enabled") : t("toast_startup_disabled"));
  } catch (err) {
    toast(String(err), true);
  }
}

$("btn-startup-rescan").addEventListener("click", () => startupScan());

$("btn-startup-elevate").addEventListener("click", async () => {
  const ok = await confirmModal(t("tb_elevate_title"), t("tb_elevate_body"), t("tb_restart_admin"));
  if (!ok) return;
  try {
    await invoke("toolbox_elevate");
    // On success the app exits and relaunches elevated; nothing more to do here.
  } catch (err) {
    toast(String(err), true);
  }
});

// -------------------------------------------------------------- optimize

let memStatus = null;
let memBusy = false;

function memRenderMeter(s) {
  const pct = Math.max(0, Math.min(100, Number(s.percent_used)));
  const fill = $("mem-fill");
  fill.style.width = pct + "%";
  fill.className = "mem-fill" + (pct >= 85 ? " hot" : pct >= 60 ? " warm" : "");
  $("mem-legend").textContent = tf("mem_legend", {
    used: fmtBytes(s.used_bytes),
    total: fmtBytes(s.total_bytes),
    pct: pct,
    avail: fmtBytes(s.avail_bytes),
  });
}

async function memRefresh() {
  try {
    memStatus = await invoke("memory_status");
    if (!memStatus || Number(memStatus.total_bytes) === 0) {
      $("mem-legend").textContent = t("mem_unavailable");
      return;
    }
    memRenderMeter(memStatus);
  } catch (err) {
    toast(String(err), true);
  }
}

async function memFree() {
  if (memBusy) return;
  memBusy = true;
  const btn = $("btn-mem-free");
  btn.disabled = true;
  btn.textContent = t("mem_freeing");
  try {
    const out = await invoke("memory_optimize");
    memStatus = out.after;
    memRenderMeter(out.after);
    const freed = Number(out.freed_bytes);
    const freedTxt = freed >= 0 ? fmtBytes(freed) : "-" + fmtBytes(-freed);
    const standby = out.standby_purged
      ? t("mem_standby_purged")
      : out.elevated
      ? t("mem_standby_none")
      : t("mem_standby_admin");
    const r = $("mem-result");
    r.hidden = false;
    r.innerHTML =
      '<div class="mem-freed">' + tf("mem_freed", { n: freedTxt }) + "</div>" +
      '<div class="mem-detail">' +
      tf("mem_ba", { before: fmtBytes(out.before.avail_bytes), after: fmtBytes(out.after.avail_bytes) }) +
      "  •  " + tf("mem_trimmed", { a: out.processes_trimmed, b: out.processes_total }) +
      "  •  " + standby +
      "</div>";
    toast(tf("toast_mem_freed", { n: freedTxt }));
  } catch (err) {
    toast(String(err), true);
  } finally {
    memBusy = false;
    btn.disabled = false;
    btn.textContent = t("mem_free");
  }
}

$("btn-mem-refresh").addEventListener("click", () => memRefresh());
$("btn-mem-free").addEventListener("click", () => memFree());

// --------------------------------------------------------------- init --

applyStatic();
junkIdle();
refreshUndo();
