import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getVersion } from "@tauri-apps/api/app";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

// ---- Types mirroring the Rust payloads ----
type Method = "inject" | "electron-patch" | "hide-during-capture";
type CaptureStatus = "not-running" | "protected" | "partial" | "unprotected";

interface Target {
  id: string;
  name: string;
  method: Method;
  process: string;
  class: string;
  title: string;
  all_windows: boolean;
  enabled: boolean;
  builtin: boolean;
  show_icon: boolean;
}

interface Config {
  master_enabled: boolean;
  interval_secs: number;
  start_on_login: boolean;
  start_minimized: boolean;
  protect_self: boolean;
  privacy_veil: boolean;
  elevated_mode: boolean;
  activity: ActivityConfig;
  targets: Target[];
}

type WaBlurState = "off" | "waiting-for-whats-app" | "active" | "elevation-needed";

interface WaBlurStatus {
  enabled: boolean;
  state: WaBlurState;
}

interface SafeKey {
  label: string;
  vks: number[];
}

interface ActivityConfig {
  enabled: boolean;
  idle_threshold_secs: number;
  keys_per_burst: number;
  press_gap_min_ms: number;
  press_gap_max_ms: number;
  hold_min_ms: number;
  hold_max_ms: number;
  safe_keys: SafeKey[];
}

interface ActivityStatus {
  enabled: boolean;
  idle_secs: number;
  threshold_secs: number;
}

interface SyncConfig {
  enabled: boolean;
  spike_threshold_kb: number;
  poll_interval_secs: number;
  known_trackers: string[];
  custom_trackers: string[];
  cooldown_secs: number;
  paused: boolean;
  paused_until_ms: number | null;
  quiet_from: string;
  quiet_to: string;
  log_max_mb: number;
  log_retention_days: number | null;
}

interface SyncStatus {
  enabled: boolean;
  running: boolean;
  paused: boolean;
  paused_until_ms: number;
  tracker_name: string;
  tracker_pid: number;
  last_poll_ms: number;
  last_event_ms: number;
  today_count: number;
}

interface SyncEvent {
  datetime: string;
  date: string;
  time: string;
  spike_kb: number;
  source: string;
  pid: number;
}

interface ScreenshotInfo {
  filename: string;
  taken_at_ms: number;
  data_uri: string;
}

interface TargetStatus {
  id: string;
  status: CaptureStatus;
  windows_total: number;
  windows_protected: number;
}

interface LogEntry {
  ts_ms: number;
  level: string;
  message: string;
}

interface FullState {
  config: Config;
  statuses: TargetStatus[];
  autostart_enabled: boolean;
  is_elevated: boolean;
  elevated_task_installed: boolean;
  fullscreen_active: boolean;
  log: LogEntry[];
}

function setFullscreenBanner(on: boolean) {
  $("#fullscreen-banner").classList.toggle("hidden", !on);
}

interface AppTypeInfo {
  kind: string;
  recommended_method: Method;
  exe_path: string | null;
  note: string;
  running: boolean;
}

// ---- App state ----
let config: Config;
let activityConfig: ActivityConfig | null = null;
let syncConfig: SyncConfig | null = null;
const statusById = new Map<string, TargetStatus>();
const iconMap = new Map<string, string>(); // lowercase process -> icon data URI
let pendingIcon: string | null = null; // icon of the app being added via the picker

const $ = <T extends HTMLElement = HTMLElement>(sel: string) =>
  document.querySelector(sel) as T;

const METHOD_LABELS: Record<Method, string> = {
  inject: "Injection show-through",
  "electron-patch": "Electron self-patch",
  "hide-during-capture": "Hide during capture",
};

const STATUS_LABELS: Record<CaptureStatus, string> = {
  protected: "Protected",
  unprotected: "Capturable",
  partial: "Partly protected",
  "not-running": "Not running",
};

const BADGE_COLORS = [
  "#3ddc97", "#5b9dff", "#f5b544", "#c98bff", "#ff8a65", "#4dd0e1", "#ff6b9d",
];

function badgeColor(id: string): string {
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  return BADGE_COLORS[h % BADGE_COLORS.length];
}

function fmtTime(ms: number): string {
  const d = new Date(ms);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string)
  );
}

// ---- Rendering ----
function renderCards() {
  const wrap = $("#cards");
  if (!config.targets.length) {
    wrap.innerHTML = `<div class="empty-state">No apps yet. Click "+ Add app" to protect one.</div>`;
    return;
  }
  wrap.innerHTML = "";
  for (const t of config.targets) {
    const st = statusById.get(t.id);
    const status: CaptureStatus = st ? st.status : "not-running";
    const showCounts =
      !!st && (status === "protected" || status === "partial") && st.windows_total > 0;

    const icon = iconMap.get(t.process.toLowerCase());
    const badge = icon
      ? `<div class="badge badge-icon"><img src="${icon}" alt="" /></div>`
      : `<div class="badge" style="background:${badgeColor(t.id)}">${escapeHtml(
          (t.name[0] ?? "?").toUpperCase()
        )}</div>`;

    const card = document.createElement("div");
    card.className = "card" + (t.enabled ? "" : " disabled");
    card.innerHTML = `
      <div class="card-top">
        ${badge}
        <div class="card-info">
          <div class="card-name">${escapeHtml(t.name)}</div>
          <span class="method-badge">${METHOD_LABELS[t.method]}</span>
          <div class="card-proc">${escapeHtml(t.process)}.exe</div>
        </div>
        <div class="card-actions">
          ${t.builtin ? "" : `<button class="remove-btn" title="Remove" data-remove="${t.id}">\u{1F5D1}</button>`}
          <label class="switch"><input type="checkbox" data-toggle="${t.id}" ${t.enabled ? "checked" : ""}/><span class="slider"></span></label>
        </div>
      </div>
      <div class="card-foot">
        <span class="status ${status}"><span class="dot"></span>${STATUS_LABELS[status]}${
          showCounts ? ` · ${st!.windows_protected}/${st!.windows_total} window${st!.windows_total === 1 ? "" : "s"}` : ""
        }</span>
        <button type="button" class="icon-toggle-btn${t.show_icon ? " on" : ""}" data-icon-toggle="${t.id}" title="${
          t.show_icon ? "Defender icon shown on this app — click to hide" : "Show a defender status icon on this app"
        }">🛡</button>
      </div>`;
    wrap.appendChild(card);
  }

  wrap.querySelectorAll<HTMLInputElement>("[data-toggle]").forEach((el) => {
    el.addEventListener("change", () => onToggleTarget(el.dataset.toggle as string, el.checked));
  });
  wrap.querySelectorAll<HTMLButtonElement>("[data-remove]").forEach((el) => {
    el.addEventListener("click", () => onRemoveTarget(el.dataset.remove as string));
  });
  wrap.querySelectorAll<HTMLButtonElement>("[data-icon-toggle]").forEach((el) => {
    el.addEventListener("click", () => onToggleShowIcon(el.dataset.iconToggle as string));
  });
}

function renderMaster() {
  const on = config.master_enabled;
  ($("#master-toggle") as HTMLInputElement).checked = on;
  $("#master-label").textContent = on ? "Protection ON" : "Protection paused";
  const enabledCount = config.targets.filter((t) => t.enabled).length;
  const protectedCount = config.targets.filter(
    (t) => t.enabled && statusById.get(t.id)?.status === "protected"
  ).length;
  $("#master-sub").textContent = on
    ? `${protectedCount}/${enabledCount} active apps protected`
    : "All protection is paused";
}

function renderSettings(autostartEnabled: boolean, isElevated: boolean) {
  ($("#autostart-toggle") as HTMLInputElement).checked = autostartEnabled;
  ($("#startmin-toggle") as HTMLInputElement).checked = config.start_minimized;
  ($("#self-toggle") as HTMLInputElement).checked = config.protect_self;
  ($("#veil-toggle") as HTMLInputElement).checked = config.privacy_veil;
  ($("#activity-toggle") as HTMLInputElement).checked = config.activity.enabled;
  ($("#elev-toggle") as HTMLInputElement).checked = config.elevated_mode;
  const range = $("#interval-range") as HTMLInputElement;
  range.value = String(config.interval_secs);
  updateIntervalUi(config.interval_secs);

  const status = $("#elev-status");
  const restartBtn = $("#elev-restart");
  if (isElevated) {
    status.textContent = "elevated";
  } else if (config.elevated_mode) {
    status.textContent = "at next logon";
  } else {
    status.textContent = "off";
  }
  // Offer an immediate elevated restart when enabled but not yet elevated.
  restartBtn.classList.toggle("hidden", !(config.elevated_mode && !isElevated));
}

function applyWablurStatus(s: WaBlurStatus) {
  const pill = $("#wablur-status");
  pill.classList.remove("pill-waiting", "pill-danger");
  switch (s.state) {
    case "active":
      pill.textContent = "active";
      break;
    case "waiting-for-whats-app":
      pill.textContent = "waiting for whatsapp";
      pill.classList.add("pill-waiting");
      break;
    case "elevation-needed":
      pill.textContent = "needs elevation";
      pill.classList.add("pill-danger");
      break;
    default:
      pill.textContent = "off";
  }
}

// ---- Activity simulator ----

// Physical-key identity (KeyboardEvent.code) -> Win32 virtual-key code + label.
// Deliberately an ALLOWLIST: only modifiers, lock keys, Pause, and F13-F24 are
// recordable — none of these type a character or run a bound OS shortcut, so
// there's no way to accidentally record something unsafe (e.g. Win+D, Alt+F4).
const ACTIVITY_KEY_MAP: Record<string, { vk: number; label: string }> = {
  ShiftLeft: { vk: 0xa0, label: "Shift" },
  ShiftRight: { vk: 0xa1, label: "Shift (R)" },
  ControlLeft: { vk: 0xa2, label: "Ctrl" },
  ControlRight: { vk: 0xa3, label: "Ctrl (R)" },
  AltLeft: { vk: 0xa4, label: "Alt" },
  AltRight: { vk: 0xa5, label: "Alt (R)" },
  MetaLeft: { vk: 0x5b, label: "Win" },
  MetaRight: { vk: 0x5c, label: "Win (R)" },
  ScrollLock: { vk: 0x91, label: "Scroll Lock" },
  CapsLock: { vk: 0x14, label: "Caps Lock" },
  NumLock: { vk: 0x90, label: "Num Lock" },
  Pause: { vk: 0x13, label: "Pause" },
  F13: { vk: 0x7c, label: "F13" },
  F14: { vk: 0x7d, label: "F14" },
  F15: { vk: 0x7e, label: "F15" },
  F16: { vk: 0x7f, label: "F16" },
  F17: { vk: 0x80, label: "F17" },
  F18: { vk: 0x81, label: "F18" },
  F19: { vk: 0x82, label: "F19" },
  F20: { vk: 0x83, label: "F20" },
  F21: { vk: 0x84, label: "F21" },
  F22: { vk: 0x85, label: "F22" },
  F23: { vk: 0x86, label: "F23" },
  F24: { vk: 0x87, label: "F24" },
};

let recording = false;
let heldKeys = new Map<string, { vk: number; label: string }>();

function applyActivityStatus(s: ActivityStatus) {
  const pill = $("#activity-status");
  pill.classList.remove("pill-waiting");
  if (!s.enabled) {
    pill.textContent = "off";
    return;
  }
  const remaining = Math.max(0, s.threshold_secs - s.idle_secs);
  if (remaining === 0) {
    pill.textContent = "active";
  } else {
    pill.textContent = `next in ${remaining}s`;
    pill.classList.add("pill-waiting");
  }
}

function renderSafeKeys() {
  const list = $("#safe-keys-list");
  if (!activityConfig || activityConfig.safe_keys.length === 0) {
    list.innerHTML = `<div class="key-chip-empty">No safe keys configured — add one below.</div>`;
    return;
  }
  list.innerHTML = activityConfig.safe_keys
    .map(
      (k) =>
        `<span class="key-chip">${k.label}<button type="button" data-remove="${encodeURIComponent(k.label)}" aria-label="Remove">&times;</button></span>`
    )
    .join("");
  list.querySelectorAll("[data-remove]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const label = decodeURIComponent((btn as HTMLElement).getAttribute("data-remove")!);
      activityConfig = await invoke<ActivityConfig>("remove_safe_key", { label });
      renderSafeKeys();
    });
  });
}

function populateActivityModal() {
  if (!activityConfig) return;
  const c = activityConfig;
  ($("#act-idle") as HTMLInputElement).value = String(c.idle_threshold_secs);
  ($("#act-keys") as HTMLInputElement).value = String(c.keys_per_burst);
  ($("#act-gap-min") as HTMLInputElement).value = String(c.press_gap_min_ms);
  ($("#act-gap-max") as HTMLInputElement).value = String(c.press_gap_max_ms);
  ($("#act-hold-min") as HTMLInputElement).value = String(c.hold_min_ms);
  ($("#act-hold-max") as HTMLInputElement).value = String(c.hold_max_ms);
  renderSafeKeys();
  stopRecording();
  $("#act-error").classList.add("hidden");
}

async function openActivityModal() {
  activityConfig = await invoke<ActivityConfig>("get_activity_config");
  populateActivityModal();
  $("#activity-modal").classList.remove("hidden");
}

function closeActivityModal() {
  stopRecording();
  $("#activity-modal").classList.add("hidden");
}

async function saveActivityModal() {
  const num = (id: string) => Number(($(id) as HTMLInputElement).value);
  activityConfig = await invoke<ActivityConfig>("set_activity_config", {
    settings: {
      idle_threshold_secs: num("#act-idle"),
      keys_per_burst: num("#act-keys"),
      press_gap_min_ms: num("#act-gap-min"),
      press_gap_max_ms: num("#act-gap-max"),
      hold_min_ms: num("#act-hold-min"),
      hold_max_ms: num("#act-hold-max"),
    },
  });
  closeActivityModal();
}

function onRecorderKeyDown(e: KeyboardEvent) {
  e.preventDefault();
  const match = ACTIVITY_KEY_MAP[e.code];
  const err = $("#act-error");
  if (!match) {
    err.textContent =
      "Only Shift, Ctrl, Alt, Win, Scroll Lock, Caps Lock, Num Lock, Pause, or F13–F24 can be used — these never type anything or run a shortcut.";
    err.classList.remove("hidden");
    return;
  }
  err.classList.add("hidden");
  heldKeys.set(e.code, match);
  const label = [...heldKeys.values()].map((k) => k.label).join(" + ");
  $("#act-recorder span").textContent = `Recording: ${label} — release all keys to save`;
}

async function onRecorderKeyUp(e: KeyboardEvent) {
  e.preventDefault();
  if (!ACTIVITY_KEY_MAP[e.code] || !heldKeys.has(e.code)) return;

  // Snapshot the combo BEFORE removing the released key, so releasing the
  // last key still finalizes with the full combo that was held.
  const isLastKey = heldKeys.size === 1;
  const combo = [...heldKeys.values()];
  heldKeys.delete(e.code);
  if (!isLastKey) return; // other keys still held — keep recording

  stopRecording();
  const vks = combo.map((k) => k.vk);
  const label = combo.map((k) => k.label).join(" + ");
  try {
    activityConfig = await invoke<ActivityConfig>("add_safe_key", { label, vks });
    renderSafeKeys();
  } catch (err) {
    const el = $("#act-error");
    el.textContent = String(err);
    el.classList.remove("hidden");
  }
}

function stopRecording() {
  recording = false;
  heldKeys = new Map();
  document.removeEventListener("keydown", onRecorderKeyDown, true);
  document.removeEventListener("keyup", onRecorderKeyUp, true);
  $("#act-recorder").classList.add("hidden");
}

function startRecording() {
  if (recording) return;
  recording = true;
  heldKeys = new Map();
  $("#act-error").classList.add("hidden");
  const recorderEl = $("#act-recorder");
  recorderEl.classList.remove("hidden");
  recorderEl.querySelector("span")!.textContent =
    "Press a key or combo now… (Shift, Ctrl, Alt, Win, Scroll Lock, Caps Lock, Num Lock, Pause, F13–F24)";

  document.addEventListener("keydown", onRecorderKeyDown, true);
  document.addEventListener("keyup", onRecorderKeyUp, true);
}

async function refreshSettings() {
  const state = await invoke<FullState>("get_state");
  config = state.config;
  renderSettings(state.autostart_enabled, state.is_elevated);
}

function updateIntervalUi(v: number) {
  $("#interval-val").textContent = `${v}s`;
  const range = $("#interval-range") as HTMLInputElement;
  const pct = ((v - 3) / (60 - 3)) * 100;
  range.style.setProperty("--pct", `${pct}%`);
}

function addLogRow(entry: LogEntry, prepend = true) {
  const log = $("#log");
  const empty = log.querySelector(".log-empty");
  if (empty) empty.remove();
  const row = document.createElement("div");
  row.className = `log-row ${entry.level}`;
  row.innerHTML = `<span class="log-time">${fmtTime(entry.ts_ms)}</span><span class="log-msg">${escapeHtml(entry.message)}</span>`;
  if (prepend) log.prepend(row);
  else log.appendChild(row);
  while (log.children.length > 200) log.lastChild?.remove();
}

function renderLog(entriesNewestFirst: LogEntry[]) {
  const log = $("#log");
  log.innerHTML = "";
  if (!entriesNewestFirst.length) {
    log.innerHTML = `<div class="log-empty">No activity yet.</div>`;
    return;
  }
  for (const e of entriesNewestFirst) addLogRow(e, false);
  log.scrollTop = 0;
}

// ---- Auto-update ----
let pendingUpdate: Update | null = null;
const UPDATE_CHECK_INTERVAL_MS = 4 * 60 * 60 * 1000; // 4 hours

async function initUpdater() {
  try {
    $("#app-version").textContent = `v${await getVersion()}`;
  } catch (e) {
    console.error(e);
  }
  checkForUpdates(false);
  setInterval(() => checkForUpdates(false), UPDATE_CHECK_INTERVAL_MS);
}

async function checkForUpdates(manual: boolean) {
  const title = $("#update-title");
  const btn = $("#check-update-btn") as HTMLButtonElement;
  if (manual) {
    title.textContent = "Checking for updates…";
    btn.disabled = true;
  }
  try {
    const update = await check();
    if (update) {
      pendingUpdate = update;
      title.textContent = `Update available: v${update.version}`;
      await downloadUpdateInBackground(update);
    } else if (manual || !pendingUpdate) {
      title.textContent = "Up to date";
    }
  } catch (e) {
    if (manual) title.textContent = "Couldn't check for updates";
    console.error(e);
  } finally {
    btn.disabled = false;
  }
}

async function downloadUpdateInBackground(update: Update) {
  const title = $("#update-title");
  const wrap = $("#update-progress-wrap");
  const bar = $("#update-progress-bar") as HTMLElement;
  wrap.classList.remove("hidden");
  bar.style.width = "0%";
  let total = 0;
  let downloaded = 0;

  try {
    await update.download((event) => {
      if (event.event === "Started") {
        total = event.data.contentLength ?? 0;
      } else if (event.event === "Progress") {
        downloaded += event.data.chunkLength;
        const pct = total ? Math.min(100, Math.round((downloaded / total) * 100)) : 0;
        bar.style.width = `${pct}%`;
        title.textContent = `Downloading update v${update.version}… ${pct}%`;
      } else if (event.event === "Finished") {
        bar.style.width = "100%";
      }
    });
    title.textContent = `Update v${update.version} ready`;
    wrap.classList.add("hidden");
    $("#restart-update-btn").classList.remove("hidden");
    $("#check-update-btn").classList.add("hidden");
  } catch (e) {
    title.textContent = "Update download failed";
    wrap.classList.add("hidden");
    console.error(e);
  }
}

async function onRestartToUpdate() {
  if (!pendingUpdate) return;
  const btn = $("#restart-update-btn") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = "Installing…";
  try {
    await pendingUpdate.install();
    await relaunch();
  } catch (e) {
    alert(`Update install failed: ${e}`);
    btn.disabled = false;
    btn.textContent = "Restart to update";
  }
}

// ---- Tabs (thin icon sidebar) ----
function switchTab(tab: string) {
  document.querySelectorAll<HTMLButtonElement>("#tabs .side-tab").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tab);
  });
  document.querySelectorAll<HTMLElement>(".tab-panel").forEach((panel) => {
    panel.classList.toggle("active", panel.id === `tab-${tab}`);
  });
  if (tab === "sync") $("#sync-tab-dot").classList.remove("show");
}

function wireTabs() {
  document.querySelectorAll<HTMLButtonElement>("#tabs .side-tab").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab as string));
  });
}

// ---- Sync Monitor ----
function fmtAgo(ms: number): string {
  if (!ms) return "—";
  const secs = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (secs < 5) return "just now";
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  return `${Math.floor(mins / 60)}h ago`;
}

function fmtRemaining(untilMs: number): string {
  const secs = Math.max(0, Math.round((untilMs - Date.now()) / 1000));
  if (secs < 60) return `${secs}s`;
  return `${Math.round(secs / 60)}m`;
}

function updateRangePct(el: HTMLInputElement, min: number, max: number) {
  const pct = ((Number(el.value) - min) / (max - min)) * 100;
  el.style.setProperty("--pct", `${pct}%`);
}

function renderSyncStatus(s: SyncStatus) {
  const dot = $("#sync-status-dot");
  const title = $("#sync-status-title");
  const sub = $("#sync-status-sub");
  dot.className = "sync-status-dot";
  if (!s.enabled) {
    title.textContent = "Sync Monitor is off";
    sub.textContent = "Turn it on to watch for monitoring/tracker software";
  } else if (s.paused) {
    dot.classList.add("paused");
    title.textContent = s.paused_until_ms
      ? `Meeting mode — resumes in ${fmtRemaining(s.paused_until_ms)}`
      : "Paused";
    sub.textContent = "Not watching for tracker activity right now";
  } else if (s.tracker_name) {
    dot.classList.add("on");
    title.textContent = `Watching ${s.tracker_name}`;
    sub.textContent = `pid ${s.tracker_pid} · last checked ${fmtAgo(s.last_poll_ms)}`;
  } else {
    dot.classList.add("watching");
    title.textContent = "Watching — no tracker running";
    sub.textContent = `Last checked ${fmtAgo(s.last_poll_ms)}`;
  }
  $("#sync-today-count").textContent = String(s.today_count);
  $("#sync-last-event").textContent = s.last_event_ms ? fmtAgo(s.last_event_ms) : "—";

  ($("#sync-toggle") as HTMLInputElement).checked = s.enabled;
  ($("#sync-pause-toggle") as HTMLInputElement).checked = s.paused;
}

function renderTrackerChips(c: SyncConfig) {
  const known = $("#known-trackers-list");
  known.innerHTML = c.known_trackers.map((n) => `<span class="key-chip">${escapeHtml(n)}</span>`).join("");

  const custom = $("#custom-trackers-list");
  if (!c.custom_trackers.length) {
    custom.innerHTML = `<div class="key-chip-empty">No custom trackers added.</div>`;
    return;
  }
  custom.innerHTML = c.custom_trackers
    .map(
      (n) =>
        `<span class="key-chip">${escapeHtml(n)}<button type="button" data-remove-tracker="${encodeURIComponent(n)}" aria-label="Remove">&times;</button></span>`
    )
    .join("");
  custom.querySelectorAll("[data-remove-tracker]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const name = decodeURIComponent((btn as HTMLElement).getAttribute("data-remove-tracker")!);
      syncConfig = await invoke<SyncConfig>("remove_sync_tracker", { name });
      renderTrackerChips(syncConfig);
    });
  });
}

function renderSyncConfig(c: SyncConfig) {
  const th = $("#sync-threshold-range") as HTMLInputElement;
  th.value = String(c.spike_threshold_kb);
  $("#sync-threshold-val").textContent = `${c.spike_threshold_kb} KB`;
  updateRangePct(th, 50, 5000);

  const iv = $("#sync-interval-range") as HTMLInputElement;
  iv.value = String(c.poll_interval_secs);
  $("#sync-interval-val").textContent = `${c.poll_interval_secs}s`;
  updateRangePct(iv, 1, 60);

  const cd = $("#sync-cooldown-range") as HTMLInputElement;
  cd.value = String(c.cooldown_secs);
  $("#sync-cooldown-val").textContent = `${c.cooldown_secs}s`;
  updateRangePct(cd, 0, 60);

  ($("#sync-quiet-from") as HTMLInputElement).value = c.quiet_from;
  ($("#sync-quiet-to") as HTMLInputElement).value = c.quiet_to;

  renderTrackerChips(c);
}

function syncEventDetail(evt: SyncEvent): string {
  return evt.spike_kb > 0
    ? `${evt.source} — RAM spike ${evt.spike_kb} KB (pid ${evt.pid})`
    : `${evt.source} — screenshot captured`;
}

function renderSyncEvents(events: SyncEvent[]) {
  const log = $("#sync-events");
  if (!events.length) {
    log.innerHTML = `<div class="log-empty">No events yet.</div>`;
    return;
  }
  log.innerHTML = "";
  for (const evt of events) {
    const row = document.createElement("div");
    row.className = "log-row warn";
    row.innerHTML = `<span class="log-time">${escapeHtml(evt.date)} ${escapeHtml(evt.time)}</span><span class="log-msg">${escapeHtml(syncEventDetail(evt))}</span>`;
    log.appendChild(row);
  }
}

function addSyncEventRow(evt: SyncEvent) {
  const log = $("#sync-events");
  const empty = log.querySelector(".log-empty");
  if (empty) empty.remove();
  const row = document.createElement("div");
  row.className = "log-row warn";
  row.innerHTML = `<span class="log-time">${escapeHtml(evt.date)} ${escapeHtml(evt.time)}</span><span class="log-msg">${escapeHtml(syncEventDetail(evt))}</span>`;
  log.prepend(row);
  while (log.children.length > 200) log.lastChild?.remove();
  if (!$("#tab-sync").classList.contains("active")) $("#sync-tab-dot").classList.add("show");
  if ($("#event-subtabs .mini-tab.active")?.getAttribute("data-subtab") === "screenshots") {
    loadWebworkScreenshots();
  }
}

function renderScreenshotGrid(shots: ScreenshotInfo[]) {
  const grid = $("#sync-screenshots");
  if (!shots.length) {
    grid.innerHTML = `<div class="empty-state">No screenshots recovered yet — only WebWorkTracker captures are shown here (other trackers are detected but their images aren't accessible to us).</div>`;
    return;
  }
  grid.innerHTML = "";
  for (const shot of shots) {
    const tile = document.createElement("div");
    tile.className = "screenshot-tile";
    tile.innerHTML = `<img src="${shot.data_uri}" alt="" loading="lazy" /><div class="shot-time">${fmtTime(shot.taken_at_ms)}</div>`;
    tile.addEventListener("click", () => window.open(shot.data_uri, "_blank"));
    grid.appendChild(tile);
  }
}

async function loadWebworkScreenshots() {
  const grid = $("#sync-screenshots");
  grid.innerHTML = `<div class="empty-state">Loading…</div>`;
  try {
    const shots = await invoke<ScreenshotInfo[]>("list_webwork_screenshots", { limit: 24 });
    renderScreenshotGrid(shots);
  } catch (e) {
    grid.innerHTML = `<div class="empty-state">Couldn't load screenshots: ${escapeHtml(String(e))}</div>`;
  }
}

function wireEventSubtabs() {
  $("#event-subtabs").querySelectorAll<HTMLButtonElement>(".mini-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      $("#event-subtabs").querySelectorAll(".mini-tab").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const sub = btn.dataset.subtab;
      $("#sync-events").classList.toggle("hidden", sub !== "events");
      $("#sync-screenshots").classList.toggle("hidden", sub !== "screenshots");
      if (sub === "screenshots") loadWebworkScreenshots();
    });
  });
  $("#open-screenshots-folder").addEventListener("click", () => invoke("open_webwork_screenshots_folder"));
}

// ---- Actions ----
async function onToggleTarget(id: string, enabled: boolean) {
  try {
    const statuses = await invoke<TargetStatus[]>("set_target_enabled", { id, enabled });
    const t = config.targets.find((x) => x.id === id);
    if (t) t.enabled = enabled;
    applyStatuses(statuses);
    renderCards();
    renderMaster();
  } catch (e) {
    console.error(e);
  }
}

async function onToggleShowIcon(id: string) {
  const t = config.targets.find((x) => x.id === id);
  if (!t) return;
  try {
    config = await invoke<Config>("set_target_show_icon", { id, showIcon: !t.show_icon });
    renderCards();
  } catch (e) {
    console.error(e);
  }
}

async function onRemoveTarget(id: string) {
  const t = config.targets.find((x) => x.id === id);
  if (!t) return;
  if (!confirm(`Remove ${t.name} from Windows Guard? Its protection will be turned off.`)) return;
  try {
    config = await invoke<Config>("remove_target", { id });
    statusById.delete(id);
    renderCards();
    renderMaster();
  } catch (e) {
    alert(String(e));
  }
}

async function onMasterToggle(on: boolean) {
  const statuses = await invoke<TargetStatus[]>("set_master", { enabled: on });
  config.master_enabled = on;
  applyStatuses(statuses);
  renderMaster();
  renderCards();
}

function applyStatuses(statuses: TargetStatus[]) {
  for (const s of statuses) statusById.set(s.id, s);
}

async function loadTargetIcons() {
  const procs = config.targets.map((t) => t.process);
  if (!procs.length) return;
  try {
    const map = await invoke<Record<string, string>>("get_app_icons", { processes: procs });
    for (const [k, v] of Object.entries(map || {})) iconMap.set(k.toLowerCase(), v);
    renderCards();
  } catch (e) {
    console.error(e);
  }
}

// ---- Modal: installed-app picker ----
interface InstalledApp {
  name: string;
  exe: string;
  process: string;
  method: Method;
  icon: string | null;
}
let installedApps: InstalledApp[] = [];
let appsLoaded = false;

function openModal() {
  $("#modal").classList.remove("hidden");
  showBrowseStep();
  loadApps(false);
}

function showBrowseStep() {
  $("#modal-title").textContent = "Add an app to protect";
  $("#step-browse").classList.remove("hidden");
  $("#step-config").classList.add("hidden");
  $("#modal-save").classList.add("hidden");
  $("#back-btn").classList.add("hidden");
  ($("#app-search") as HTMLInputElement).value = "";
  renderAppGrid("");
  setTimeout(() => ($("#app-search") as HTMLInputElement).focus(), 30);
}

async function loadApps(refresh: boolean) {
  const grid = $("#app-grid");
  if (!appsLoaded || refresh) {
    grid.innerHTML = `<div class="grid-loading">Scanning installed apps…</div>`;
    try {
      const list = await invoke<InstalledApp[]>("list_installed_apps", { refresh });
      installedApps = list || [];
      appsLoaded = true;
    } catch (e) {
      grid.innerHTML = `<div class="grid-empty">Couldn't load apps: ${escapeHtml(String(e))}</div>`;
      return;
    }
  }
  renderAppGrid(($("#app-search") as HTMLInputElement).value);
}

function renderAppGrid(filter: string) {
  const grid = $("#app-grid");
  const f = filter.trim().toLowerCase();
  const items = f
    ? installedApps.filter(
        (a) => a.name.toLowerCase().includes(f) || a.process.toLowerCase().includes(f)
      )
    : installedApps;
  $("#app-count").textContent = `${items.length} app${items.length === 1 ? "" : "s"}`;
  if (!items.length) {
    grid.innerHTML = `<div class="grid-empty">No matching apps. Try “Add manually”.</div>`;
    return;
  }
  grid.innerHTML = "";
  for (const a of items) {
    const tile = document.createElement("button");
    tile.className = "app-tile";
    const icon = a.icon
      ? `<img src="${a.icon}" alt="" />`
      : `<div class="tile-fallback" style="background:${badgeColor(a.process)}">${escapeHtml(
          (a.name[0] ?? "?").toUpperCase()
        )}</div>`;
    tile.innerHTML = `${icon}<div class="tile-meta"><div class="tile-name">${escapeHtml(
      a.name
    )}</div><div class="tile-badge">${a.method === "electron-patch" ? "Electron" : "app"}</div></div>`;
    tile.addEventListener("click", () => goToConfig(a));
    grid.appendChild(tile);
  }
}

function goToConfig(a: InstalledApp | null) {
  $("#step-browse").classList.add("hidden");
  $("#step-config").classList.remove("hidden");
  $("#modal-save").classList.remove("hidden");
  $("#back-btn").classList.remove("hidden");
  $("#modal-error").classList.add("hidden");
  $("#detect-hint").classList.add("hidden");
  $("#adv").classList.add("hidden");
  $("#adv-toggle").textContent = "Advanced options ▾";
  ($("#f-class") as HTMLInputElement).value = "";
  ($("#f-title") as HTMLInputElement).value = "";
  ($("#f-all") as HTMLInputElement).checked = false;

  pendingIcon = a ? a.icon : null;
  if (a) {
    $("#modal-title").textContent = "Configure protection";
    $("#sel-app").classList.remove("hidden");
    const img = $("#sel-icon") as HTMLImageElement;
    if (a.icon) {
      img.src = a.icon;
      img.style.display = "";
    } else {
      img.style.display = "none";
    }
    $("#sel-name-lbl").textContent = a.name;
    $("#sel-proc-lbl").textContent = `${a.process}.exe`;
    ($("#f-name") as HTMLInputElement).value = a.name;
    ($("#f-process") as HTMLInputElement).value = a.process;
    ($("#f-method") as HTMLSelectElement).value = a.method;
  } else {
    $("#modal-title").textContent = "Add manually";
    $("#sel-app").classList.add("hidden");
    ($("#f-name") as HTMLInputElement).value = "";
    ($("#f-process") as HTMLInputElement).value = "";
    ($("#f-method") as HTMLSelectElement).value = "inject";
    setTimeout(() => ($("#f-name") as HTMLInputElement).focus(), 30);
  }
}

async function runDetect() {
  const process = ($("#f-process") as HTMLInputElement).value.trim();
  const hint = $("#detect-hint");
  if (!process) {
    hint.classList.add("hidden");
    return;
  }
  try {
    const info = await invoke<AppTypeInfo>("detect_app_type", { process });
    ($("#f-method") as HTMLSelectElement).value = info.recommended_method;
    hint.textContent = info.note;
    const cls =
      info.kind === "native"
        ? " native"
        : info.kind === "electron-packed" || info.kind === "not-running"
        ? " warn"
        : "";
    hint.className = "detect-hint" + cls;
    hint.classList.remove("hidden");
  } catch (e) {
    hint.textContent = String(e);
    hint.className = "detect-hint warn";
    hint.classList.remove("hidden");
  }
}
function closeModal() {
  $("#modal").classList.add("hidden");
}

async function saveModal() {
  const name = ($("#f-name") as HTMLInputElement).value.trim();
  const process = ($("#f-process") as HTMLInputElement).value.trim();
  const err = $("#modal-error");
  if (!name || !process) {
    err.textContent = "Please fill in a display name and a process name.";
    err.classList.remove("hidden");
    return;
  }
  const target = {
    name,
    process,
    class: ($("#f-class") as HTMLInputElement).value.trim(),
    title: ($("#f-title") as HTMLInputElement).value.trim(),
    all_windows: ($("#f-all") as HTMLInputElement).checked,
    method: ($("#f-method") as HTMLSelectElement).value,
  };
  try {
    config = await invoke<Config>("add_target", { target });
    if (pendingIcon) iconMap.set(process.toLowerCase(), pendingIcon);
    closeModal();
    const statuses = await invoke<TargetStatus[]>("refresh_now");
    applyStatuses(statuses);
    renderCards();
    renderMaster();
    loadTargetIcons(); // fetch an icon for it if it wasn't picked from the list
  } catch (e) {
    err.textContent = String(e);
    err.classList.remove("hidden");
  }
}

// ---- Wiring ----
function wireSyncEvents() {
  wireEventSubtabs();
  $("#sync-toggle").addEventListener("change", async (e) => {
    const el = e.target as HTMLInputElement;
    const on = el.checked;
    try {
      syncConfig = await invoke<SyncConfig>("set_sync_config", { settings: { enabled: on } });
    } catch (err) {
      alert(String(err));
      el.checked = !on;
    }
  });
  $("#sync-pause-toggle").addEventListener("change", async (e) => {
    const status = await invoke<SyncStatus>("set_sync_paused", {
      paused: (e.target as HTMLInputElement).checked,
    });
    renderSyncStatus(status);
  });
  $("#sync-meeting-btn").addEventListener("click", async () => {
    const mins = Number(($("#sync-meeting-mins") as HTMLInputElement).value) || 30;
    const status = await invoke<SyncStatus>("set_sync_meeting_mode", { minutes: mins });
    renderSyncStatus(status);
  });

  const th = $("#sync-threshold-range") as HTMLInputElement;
  th.addEventListener("input", () => {
    updateRangePct(th, 50, 5000);
    $("#sync-threshold-val").textContent = `${th.value} KB`;
  });
  th.addEventListener("change", async () => {
    syncConfig = await invoke<SyncConfig>("set_sync_config", {
      settings: { spike_threshold_kb: Number(th.value) },
    });
  });

  const iv = $("#sync-interval-range") as HTMLInputElement;
  iv.addEventListener("input", () => {
    updateRangePct(iv, 1, 60);
    $("#sync-interval-val").textContent = `${iv.value}s`;
  });
  iv.addEventListener("change", async () => {
    syncConfig = await invoke<SyncConfig>("set_sync_config", {
      settings: { poll_interval_secs: Number(iv.value) },
    });
  });

  const cd = $("#sync-cooldown-range") as HTMLInputElement;
  cd.addEventListener("input", () => {
    updateRangePct(cd, 0, 60);
    $("#sync-cooldown-val").textContent = `${cd.value}s`;
  });
  cd.addEventListener("change", async () => {
    syncConfig = await invoke<SyncConfig>("set_sync_config", {
      settings: { cooldown_secs: Number(cd.value) },
    });
  });

  $("#sync-quiet-from").addEventListener("change", async (e) => {
    syncConfig = await invoke<SyncConfig>("set_sync_config", {
      settings: { quiet_from: (e.target as HTMLInputElement).value },
    });
  });
  $("#sync-quiet-to").addEventListener("change", async (e) => {
    syncConfig = await invoke<SyncConfig>("set_sync_config", {
      settings: { quiet_to: (e.target as HTMLInputElement).value },
    });
  });

  $("#tracker-add-btn").addEventListener("click", async () => {
    const input = $("#tracker-add-input") as HTMLInputElement;
    const err = $("#tracker-error");
    const name = input.value.trim();
    if (!name) return;
    try {
      syncConfig = await invoke<SyncConfig>("add_sync_tracker", { name });
      renderTrackerChips(syncConfig);
      input.value = "";
      err.classList.add("hidden");
    } catch (e2) {
      err.textContent = String(e2);
      err.classList.remove("hidden");
    }
  });
  $("#tracker-add-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") $("#tracker-add-btn").dispatchEvent(new MouseEvent("click"));
  });
  $("#sync-clear-events").addEventListener("click", async () => {
    if (!confirm("Wipe the entire Sync Monitor event history from disk? This can't be undone.")) return;
    await invoke("wipe_sync_events");
    $("#sync-events").innerHTML = `<div class="log-empty">No events yet.</div>`;
  });
}

function wireEvents() {
  wireTabs();
  wireSyncEvents();
  $("#master-toggle").addEventListener("change", (e) =>
    onMasterToggle((e.target as HTMLInputElement).checked)
  );
  $("#refresh-btn").addEventListener("click", async () => {
    const statuses = await invoke<TargetStatus[]>("refresh_now");
    applyStatuses(statuses);
    renderCards();
    renderMaster();
  });
  $("#add-btn").addEventListener("click", openModal);
  $("#app-search").addEventListener("input", (e) =>
    renderAppGrid((e.target as HTMLInputElement).value)
  );
  $("#app-refresh").addEventListener("click", () => loadApps(true));
  $("#manual-link").addEventListener("click", () => goToConfig(null));
  $("#back-btn").addEventListener("click", showBrowseStep);
  $("#f-detect").addEventListener("click", runDetect);
  $("#f-process").addEventListener("blur", () => {
    if (($("#f-process") as HTMLInputElement).value.trim()) runDetect();
  });
  $("#modal-close").addEventListener("click", closeModal);
  $("#modal-cancel").addEventListener("click", closeModal);
  $("#modal-save").addEventListener("click", saveModal);
  $("#modal").addEventListener("click", (e) => {
    if (e.target === $("#modal")) closeModal();
  });
  $("#adv-toggle").addEventListener("click", () => {
    const adv = $("#adv");
    adv.classList.toggle("hidden");
    $("#adv-toggle").textContent = adv.classList.contains("hidden")
      ? "Advanced options ▾"
      : "Advanced options ▴";
  });

  $("#autostart-toggle").addEventListener("change", async (e) => {
    const el = e.target as HTMLInputElement;
    const on = el.checked;
    try {
      const result = await invoke<boolean>("set_autostart", { enabled: on });
      el.checked = result;
    } catch (err) {
      alert(String(err));
      el.checked = !on;
    }
  });
  $("#startmin-toggle").addEventListener("change", async (e) => {
    const on = (e.target as HTMLInputElement).checked;
    config = await invoke<Config>("update_settings", { settings: { start_minimized: on } });
  });
  $("#self-toggle").addEventListener("change", async (e) => {
    const el = e.target as HTMLInputElement;
    const on = el.checked;
    try {
      await invoke<boolean>("set_self_protection", { enabled: on });
      config.protect_self = on;
    } catch (err) {
      alert(String(err));
      el.checked = !on;
    }
  });
  $("#veil-toggle").addEventListener("change", async (e) => {
    const el = e.target as HTMLInputElement;
    const on = el.checked;
    try {
      const status = await invoke<WaBlurStatus>("set_privacy_veil", { enabled: on });
      config.privacy_veil = on;
      applyWablurStatus(status);
    } catch (err) {
      alert(String(err));
      el.checked = !on;
    }
  });
  $("#activity-toggle").addEventListener("change", async (e) => {
    const el = e.target as HTMLInputElement;
    const on = el.checked;
    try {
      activityConfig = await invoke<ActivityConfig>("set_activity_config", {
        settings: { enabled: on },
      });
      config.activity.enabled = on;
    } catch (err) {
      alert(String(err));
      el.checked = !on;
    }
  });
  $("#activity-configure").addEventListener("click", openActivityModal);
  $("#activity-modal-close").addEventListener("click", closeActivityModal);
  $("#activity-modal-cancel").addEventListener("click", closeActivityModal);
  $("#activity-modal-save").addEventListener("click", saveActivityModal);
  $("#activity-modal").addEventListener("click", (e) => {
    if (e.target === $("#activity-modal")) closeActivityModal();
  });
  $("#act-record-btn").addEventListener("click", startRecording);
  $("#act-record-cancel").addEventListener("click", stopRecording);

  $("#elev-toggle").addEventListener("change", async (e) => {
    const el = e.target as HTMLInputElement;
    const on = el.checked;
    try {
      await invoke<boolean>("set_elevated_mode", { enabled: on });
      config.elevated_mode = on;
      await refreshSettings();
      if (on) {
        alert(
          "Elevated mode enabled. It starts elevated at your next logon.\nClick “Restart elevated now” to switch immediately."
        );
      }
    } catch (err) {
      alert(String(err));
      el.checked = !on;
    }
  });
  $("#elev-restart").addEventListener("click", async () => {
    try {
      await invoke("restart_elevated");
    } catch (err) {
      alert(String(err));
    }
  });
  const range = $("#interval-range") as HTMLInputElement;
  range.addEventListener("input", () => updateIntervalUi(Number(range.value)));
  range.addEventListener("change", async () => {
    config = await invoke<Config>("update_settings", {
      settings: { interval_secs: Number(range.value) },
    });
  });
  $("#open-folder").addEventListener("click", () => invoke("open_config_folder"));
  $("#check-update-btn").addEventListener("click", () => checkForUpdates(true));
  $("#restart-update-btn").addEventListener("click", onRestartToUpdate);
  $("#clear-log").addEventListener("click", () => {
    $("#log").innerHTML = `<div class="log-empty">No activity yet.</div>`;
  });

  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if (recording) { stopRecording(); return; }
    if (!$("#activity-modal").classList.contains("hidden")) { closeActivityModal(); return; }
    closeModal();
  });
}

async function listenEvents() {
  await listen<TargetStatus[]>("status-update", (e) => {
    applyStatuses(e.payload);
    renderCards();
    renderMaster();
  });
  await listen<LogEntry>("log", (e) => addLogRow(e.payload, true));
  await listen<{ fullscreen_active: boolean }>("system-status", (e) =>
    setFullscreenBanner(e.payload.fullscreen_active)
  );
  await listen<WaBlurStatus>("wablur-status", (e) => applyWablurStatus(e.payload));
  await listen<ActivityStatus>("activity-status", (e) => applyActivityStatus(e.payload));
  await listen<SyncStatus>("sync-status", (e) => renderSyncStatus(e.payload));
  await listen<SyncEvent>("sync-event", (e) => addSyncEventRow(e.payload));
}

// ---- Boot ----
async function boot() {
  wireEvents();
  await listenEvents();
  const state = await invoke<FullState>("get_state");
  config = state.config;
  applyStatuses(state.statuses);
  renderLog([...state.log].reverse()); // newest first
  renderCards();
  renderMaster();
  renderSettings(state.autostart_enabled, state.is_elevated);
  setFullscreenBanner(state.fullscreen_active);
  loadTargetIcons(); // fill in real app icons (non-blocking)
  invoke<WaBlurStatus>("get_wablur_status").then(applyWablurStatus);
  invoke<ActivityStatus>("get_activity_status").then(applyActivityStatus);
  invoke<SyncConfig>("get_sync_config").then((c) => {
    syncConfig = c;
    renderSyncConfig(c);
  });
  invoke<SyncStatus>("get_sync_status").then(renderSyncStatus);
  invoke<SyncEvent[]>("get_sync_events", { limit: 200 }).then(renderSyncEvents);
  initUpdater();
}

window.addEventListener("DOMContentLoaded", boot);
