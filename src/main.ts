import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getVersion } from "@tauri-apps/api/app";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

// ---- Types mirroring the Rust payloads ----
type Method = "inject" | "electron-patch" | "hide-during-capture";
type CaptureStatus =
  | "not-running"
  | "protected"
  | "partial"
  | "unprotected"
  // Running, but no window is countable: tray-minimized (benign) OR we cannot
  // see its windows at all (UIPI/session mismatch, renamed exe) — possible
  // exposure. Never present this as reassuring.
  | "unknown";

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

// Whether the on-disk Electron patch that KEEPS a target protected is still
// there. Separate from CaptureStatus, which says what the windows are doing
// right now: an app update can silently revert the patch while the still-running
// process keeps its protection, so the next launch is capturable.
type PatchState = "not-applicable" | "absent" | "pending-restart" | "active";

interface PatchStateEntry {
  id: string;
  patch_state: PatchState;
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

// Backend health of the protection engine. Optional on the wire: older builds
// (and any build where the Rust side hasn't shipped the field yet) simply omit
// it, and an absent value is treated as Ready so the UI behaves exactly as it
// did before. See applyEngineHealth().
type EngineHealth =
  | { state: "ready" }
  | { state: "unavailable"; reason: string }
  | { state: "degraded"; reason: string };

interface FullState {
  config: Config;
  statuses: TargetStatus[];
  autostart_enabled: boolean;
  is_elevated: boolean;
  elevated_task_installed: boolean;
  fullscreen_active: boolean;
  log: LogEntry[];
  engine_health?: EngineHealth;
  // Present when the saved config could not be read normally at startup —
  // corrupt (renamed aside and reset to defaults) or unreadable (defaults used
  // in memory, the file left untouched). Either way the user is running with
  // settings they did not choose, which is silent state loss they should see
  // rather than have to find in the log pane. Optional: older backends omit it.
  config_notice?: string | null;
}

function setFullscreenBanner(on: boolean) {
  $("#fullscreen-banner").classList.toggle("hidden", !on);
}

// ---- Engine health ----
// The single source of truth for "is protection actually working". Deliberately
// NOT derived from the log stream: log rows are wiped on every renderLog() and
// aren't persisted before the backend's state is managed, so a banner driven by
// them can miss the very error it exists to show.
let engineHealth: EngineHealth = { state: "ready" };

function applyEngineHealth(h: EngineHealth | undefined) {
  // Absent field (older backend) => assume ready; never invent a failure.
  engineHealth = h ?? { state: "ready" };
  const banner = $("#engine-banner");
  const title = $("#engine-banner-title");
  const reason = $("#engine-banner-reason");

  if (engineHealth.state === "ready") {
    banner.classList.add("hidden");
    return;
  }

  const degraded = engineHealth.state === "degraded";
  banner.classList.toggle("banner-degraded", degraded);
  banner.classList.toggle("banner-error", !degraded);
  title.textContent = degraded
    ? "Protection is only partly working."
    : "Protection engine unavailable — your apps are NOT protected.";
  // textContent, never innerHTML: this string is a Rust error carrying OS text.
  reason.textContent = engineHealth.reason ?? "";
  banner.classList.remove("hidden");
  renderMaster();
}

// ---- Config notice ----
// Shown when the saved config could not be read at startup: corrupt (kept aside
// as config.corrupt.json) or unreadable (left untouched). This is state LOSS,
// not a protection failure — the engine is fine — so it gets its own calm blue
// presentation rather than being folded into the engine banner, which would
// then be claiming the user is unprotected when they are not.
function applyConfigNotice(notice: string | null | undefined) {
  const banner = $("#config-notice-banner");
  if (!notice) {
    banner.classList.add("hidden");
    return;
  }
  // The backend builds this across a multi-line format!(), so it arrives with a
  // run of source indentation in the middle. Collapse it or the sentence renders
  // with a visible gap.
  const clean = notice.replace(/\s+/g, " ").trim();
  // textContent: carries a filesystem path and an OS error string.
  $("#config-notice-reason").textContent = clean;
  banner.classList.remove("hidden");
}

// ---- Staleness heartbeat ----
// The backend's monitor thread is the only source of status-update events. If it
// dies (a panic, a poisoned config mutex) the UI would otherwise hold its last
// snapshot forever — a frozen green light is indistinguishable from a working
// one. Track when we last heard anything and say so once it goes quiet.
let lastStatusMs = Date.now();
let expectedIntervalSecs = 15;

function markStatusFresh() {
  lastStatusMs = Date.now();
  $("#stale-banner").classList.add("hidden");
}

function checkStaleness() {
  // Allow 3 missed ticks (and a 20s floor) before crying wolf.
  const graceMs = Math.max(20_000, expectedIntervalSecs * 3 * 1000);
  const ageMs = Date.now() - lastStatusMs;
  const stale = ageMs > graceMs;
  $("#stale-banner").classList.toggle("hidden", !stale);
  if (stale) {
    $("#stale-reason").textContent =
      `No update from the protection monitor for ${Math.round(ageMs / 1000)}s. ` +
      `What you see below may no longer be true.`;
  }
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
const patchStateById = new Map<string, PatchState>();
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
  unknown: "Can't verify",
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

// A one-line explanation under a card whose state needs one. Without this,
// "it used to say Protected and now it doesn't" has no visible cause — the
// user sees the colour change but not the reason for it.
function cardNote(t: Target, status: CaptureStatus): string {
  if (!t.enabled) return "";
  const patch = patchStateById.get(t.id) ?? "not-applicable";

  // The patch is on disk but the running process predates it. Reporting either
  // Protected or Capturable here would be wrong; only a relaunch activates it.
  if (patch === "pending-restart") {
    return `<div class="card-note attention">${escapeHtml(t.name)} was updated — protection has been re-applied. Fully quit and relaunch ${escapeHtml(t.name)} to activate it.</div>`;
  }
  // Patch missing entirely (e.g. wiped by an app update): a real exposure.
  if (patch === "absent") {
    return `<div class="card-note attention">The protection patch is missing from ${escapeHtml(t.name)} — an update may have removed it. Click Re-apply.</div>`;
  }
  // Partial almost always means an extra window (a dialog, file picker or
  // popup) opened without protection. Say so, rather than just going amber.
  if (status === "partial") {
    return `<div class="card-note">Some windows aren't protected — usually an open dialog or file picker. Close it, or click Re-apply.</div>`;
  }
  if (status === "unknown") {
    return `<div class="card-note attention">${escapeHtml(t.name)} is running but its windows can't be inspected — it may be minimized to the tray, or running at a level this app can't see.</div>`;
  }
  return "";
}

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
      ? `<div class="badge badge-icon"><img src="${escapeHtml(icon)}" alt="" /></div>`
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
      ${cardNote(t, status)}
      <div class="card-foot">
        <span class="status ${status}"><span class="dot"></span>${STATUS_LABELS[status]}${
          showCounts ? ` · ${st!.windows_protected}/${st!.windows_total} window${st!.windows_total === 1 ? "" : "s"}` : ""
        }</span>
        <span class="card-foot-actions">
          ${
            // Only offer a re-apply where it can actually do something: the app
            // is running but isn't fully protected. refresh_now only re-READS
            // status; this re-APPLIES it via the engine.
            t.enabled &&
            (status === "unprotected" ||
              status === "partial" ||
              status === "unknown" ||
              // A missing on-disk patch is fixable by re-applying, even if the
              // still-running process currently reads as protected.
              patchStateById.get(t.id) === "absent")
              ? `<button type="button" class="btn small reapply-btn" data-reapply="${t.id}">Re-apply</button>`
              : ""
          }
          <button type="button" class="icon-toggle-btn${t.show_icon ? " on" : ""}" data-icon-toggle="${t.id}" title="${
            t.show_icon ? "Defender icon shown on this app — click to hide" : "Show a defender status icon on this app"
          }">🛡</button>
        </span>
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
  wrap.querySelectorAll<HTMLButtonElement>("[data-reapply]").forEach((el) => {
    el.addEventListener("click", () => onReapply(el.dataset.reapply as string, el));
  });
}

// Re-run the protection engine for one app. Wired to `protect_now`, which was
// already implemented and registered in the backend but reachable from nowhere
// in the UI — leaving the user with no way to recover a failed app short of
// restarting the whole program.
async function onReapply(id: string, btn: HTMLButtonElement) {
  const prev = btn.textContent;
  btn.disabled = true;
  btn.textContent = "Applying…";
  try {
    await invoke<string>("protect_now", { id });
    const statuses = await invoke<TargetStatus[]>("refresh_now");
    applyStatuses(statuses);
    markStatusFresh();
    renderCards();
    renderMaster();
  } catch (e) {
    // Leave the card intact and say what failed, rather than silently
    // reverting to a state that looks like nothing was attempted.
    btn.disabled = false;
    btn.textContent = prev;
    alert(`Couldn't re-apply protection: ${e}`);
  }
}

function renderMaster() {
  const on = config.master_enabled;
  ($("#master-toggle") as HTMLInputElement).checked = on;

  // "Paused" (the user's choice) and "broken" (a failure) must never read the
  // same. The engine banner carries the detail; the header says which it is.
  if (engineHealth.state === "unavailable") {
    $("#master-label").textContent = "Protection FAILED";
    $("#master-sub").textContent = "The protection engine isn't running — see above";
    return;
  }
  $("#master-label").textContent = on ? "Protection ON" : "Protection paused";
  if (!on) {
    $("#master-sub").textContent = "All protection is paused";
    return;
  }

  // Count only what's actually running. Folding not-running apps into the
  // denominator made "2/3" ambiguous — the user couldn't tell whether the
  // third app was closed or exposed, and "0/3" looked like total failure when
  // every app was merely shut. Report exposure explicitly instead.
  const enabled = config.targets.filter((t) => t.enabled);
  const running = enabled.filter((t) => {
    const s = statusById.get(t.id)?.status;
    return s !== undefined && s !== "not-running";
  });
  const protectedCount = running.filter(
    (t) => statusById.get(t.id)?.status === "protected"
  ).length;
  // "unknown" is its own case: we cannot see the app's windows, so calling it
  // capturable would be as dishonest as calling it protected. Report the
  // uncertainty as uncertainty.
  const unverified = running.filter(
    (t) => statusById.get(t.id)?.status === "unknown"
  ).length;
  const exposed = running.length - protectedCount - unverified;
  const notRunning = enabled.length - running.length;

  if (!enabled.length) {
    $("#master-sub").textContent = "No apps are set to be protected";
  } else if (!running.length) {
    $("#master-sub").textContent = `No protected apps are running (${notRunning} waiting)`;
  } else if (exposed > 0) {
    const tail = unverified ? `, ${unverified} unverified` : "";
    $("#master-sub").textContent =
      `${exposed} of ${running.length} running app${running.length === 1 ? "" : "s"} still capturable${tail}`;
  } else if (unverified > 0) {
    $("#master-sub").textContent =
      `${unverified} of ${running.length} running app${running.length === 1 ? "" : "s"} can't be verified`;
  } else {
    const tail = notRunning ? `, ${notRunning} not running` : "";
    $("#master-sub").textContent =
      running.length === 1
        ? `The 1 running app is protected${tail}`
        : `All ${running.length} running apps protected${tail}`;
  }
}

function renderSettings(
  autostartEnabled: boolean,
  isElevated: boolean,
  elevatedTaskInstalled: boolean
) {
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
  status.classList.remove("pill-danger");
  if (isElevated) {
    status.textContent = "elevated";
  } else if (config.elevated_mode && !elevatedTaskInstalled) {
    // Elevated mode is ON but the scheduled task never got registered, so the
    // app will NOT come up elevated at logon however long the user waits.
    // Saying "at next logon" here would be a promise the app can't keep.
    status.textContent = "setup incomplete";
    status.classList.add("pill-danger");
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
        `<span class="key-chip">${escapeHtml(k.label)}<button type="button" data-remove="${encodeURIComponent(k.label)}" aria-label="Remove">&times;</button></span>`
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
  renderSettings(state.autostart_enabled, state.is_elevated, state.elevated_task_installed);
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
  // Stamped so renderLog() can tell which rows arrived live and preserve them.
  row.dataset.ts = String(entry.ts_ms);
  row.dataset.level = entry.level;
  row.innerHTML = `<span class="log-time">${escapeHtml(fmtTime(entry.ts_ms))}</span><span class="log-msg">${escapeHtml(entry.message)}</span>`;
  if (prepend) log.prepend(row);
  else log.appendChild(row);
  while (log.children.length > 200) log.lastChild?.remove();
}

function renderLog(entriesNewestFirst: LogEntry[]) {
  const log = $("#log");
  // Live `log` events can land between listener registration and this first
  // render. Wiping unconditionally would drop them — including the startup
  // errors this panel exists to show — so carry across anything newer than
  // the newest entry the backend just handed us.
  const newestSnapshotTs = entriesNewestFirst[0]?.ts_ms ?? 0;
  const carried: LogEntry[] = [];
  log.querySelectorAll<HTMLElement>(".log-row").forEach((row) => {
    const ts = Number(row.dataset.ts ?? "0");
    if (ts > newestSnapshotTs) {
      carried.push({
        ts_ms: ts,
        level: row.dataset.level ?? "info",
        message: row.querySelector(".log-msg")?.textContent ?? "",
      });
    }
  });

  log.innerHTML = "";
  const all = [...carried.sort((a, b) => b.ts_ms - a.ts_ms), ...entriesNewestFirst];
  if (!all.length) {
    log.innerHTML = `<div class="log-empty">No activity yet.</div>`;
    return;
  }
  for (const e of all) addLogRow(e, false);
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
    // Previously an automatic check failed in total silence, so a user whose
    // updates had been broken for months had no way to know.
    title.textContent = manual
      ? "Couldn't check for updates"
      : "Update check failed — click to retry";
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
    // Keep the check button visible so the download can be retried without
    // restarting the app.
    title.textContent = "Update download failed — click Check again to retry";
    wrap.classList.add("hidden");
    $("#check-update-btn").classList.remove("hidden");
    $("#restart-update-btn").classList.add("hidden");
    pendingUpdate = null;
    console.error(e);
  }
}

async function onRestartToUpdate() {
  if (!pendingUpdate) return;
  const btn = $("#restart-update-btn") as HTMLButtonElement;
  btn.disabled = true;
  btn.textContent = "Installing…";
  try {
    await invoke("prepare_for_update_install");
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
    tile.innerHTML = `<img src="${escapeHtml(shot.data_uri)}" alt="" loading="lazy" /><div class="shot-time">${escapeHtml(fmtTime(shot.taken_at_ms))}</div>`;
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
  try {
    const statuses = await invoke<TargetStatus[]>("set_master", { enabled: on });
    config.master_enabled = on;
    applyStatuses(statuses);
    markStatusFresh();
    renderMaster();
    renderCards();
  } catch (e) {
    // Never leave the master switch showing a state the backend didn't accept:
    // a toggle stuck on "Protection ON" while protection is off is the worst
    // possible lie this UI can tell.
    ($("#master-toggle") as HTMLInputElement).checked = config.master_enabled;
    renderMaster();
    alert(`Couldn't ${on ? "resume" : "pause"} protection: ${e}`);
  }
}

function applyStatuses(statuses: TargetStatus[]) {
  for (const s of statuses) statusById.set(s.id, s);
}

async function loadTargetIcons() {
  // config is unset if the core state load failed; don't throw a second,
  // less useful error on top of the real one.
  if (!config?.targets?.length) return;
  const procs = config.targets.map((t) => t.process);
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
      ? `<img src="${escapeHtml(a.icon)}" alt="" />`
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
    const el = e.target as HTMLInputElement;
    const on = el.checked;
    try {
      const status = await invoke<SyncStatus>("set_sync_paused", { paused: on });
      renderSyncStatus(status);
    } catch (err) {
      alert(String(err));
      el.checked = !on;
    }
  });
  $("#sync-meeting-btn").addEventListener("click", async () => {
    const mins = Number(($("#sync-meeting-mins") as HTMLInputElement).value) || 30;
    try {
      const status = await invoke<SyncStatus>("set_sync_meeting_mode", { minutes: mins });
      renderSyncStatus(status);
    } catch (err) {
      alert(String(err));
    }
  });

  const th = $("#sync-threshold-range") as HTMLInputElement;
  th.addEventListener("input", () => {
    updateRangePct(th, 50, 5000);
    $("#sync-threshold-val").textContent = `${th.value} KB`;
  });
  th.addEventListener("change", async () => {
    try {
      syncConfig = await invoke<SyncConfig>("set_sync_config", {
        settings: { spike_threshold_kb: Number(th.value) },
      });
    } catch (err) {
      alert(String(err));
      if (syncConfig) renderSyncConfig(syncConfig);
    }
  });

  const iv = $("#sync-interval-range") as HTMLInputElement;
  iv.addEventListener("input", () => {
    updateRangePct(iv, 1, 60);
    $("#sync-interval-val").textContent = `${iv.value}s`;
  });
  iv.addEventListener("change", async () => {
    try {
      syncConfig = await invoke<SyncConfig>("set_sync_config", {
        settings: { poll_interval_secs: Number(iv.value) },
      });
    } catch (err) {
      alert(String(err));
      if (syncConfig) renderSyncConfig(syncConfig);
    }
  });

  const cd = $("#sync-cooldown-range") as HTMLInputElement;
  cd.addEventListener("input", () => {
    updateRangePct(cd, 0, 60);
    $("#sync-cooldown-val").textContent = `${cd.value}s`;
  });
  cd.addEventListener("change", async () => {
    try {
      syncConfig = await invoke<SyncConfig>("set_sync_config", {
        settings: { cooldown_secs: Number(cd.value) },
      });
    } catch (err) {
      alert(String(err));
      if (syncConfig) renderSyncConfig(syncConfig);
    }
  });

  $("#sync-quiet-from").addEventListener("change", async (e) => {
    try {
      syncConfig = await invoke<SyncConfig>("set_sync_config", {
        settings: { quiet_from: (e.target as HTMLInputElement).value },
      });
    } catch (err) {
      alert(String(err));
      if (syncConfig) renderSyncConfig(syncConfig);
    }
  });
  $("#sync-quiet-to").addEventListener("change", async (e) => {
    try {
      syncConfig = await invoke<SyncConfig>("set_sync_config", {
        settings: { quiet_to: (e.target as HTMLInputElement).value },
      });
    } catch (err) {
      alert(String(err));
      if (syncConfig) renderSyncConfig(syncConfig);
    }
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
    try {
      await invoke("wipe_sync_events");
      $("#sync-events").innerHTML = `<div class="log-empty">No events yet.</div>`;
    } catch (err) {
      alert(String(err));
    }
  });
}

function wireEvents() {
  wireTabs();
  wireSyncEvents();
  $("#master-toggle").addEventListener("change", (e) =>
    onMasterToggle((e.target as HTMLInputElement).checked)
  );
  const doRefresh = async () => {
    const statuses = await invoke<TargetStatus[]>("refresh_now");
    applyStatuses(statuses);
    markStatusFresh();
    renderCards();
    renderMaster();
  };
  $("#refresh-btn").addEventListener("click", () => {
    doRefresh().catch((e) => alert(`Couldn't re-check protection: ${e}`));
  });
  $("#stale-refresh-btn").addEventListener("click", () => {
    doRefresh().catch((e) => alert(`Couldn't re-check protection: ${e}`));
  });

  // Dismissable: it reports something that already happened and cannot be
  // undone from here, so it should not sit there forever once read.
  $("#config-notice-dismiss").addEventListener("click", () => {
    $("#config-notice-banner").classList.add("hidden");
  });

  // Retry the whole core load after a boot failure, in place — no restart.
  $("#boot-retry-btn").addEventListener("click", async () => {
    const btn = $("#boot-retry-btn") as HTMLButtonElement;
    btn.disabled = true;
    btn.textContent = "Retrying…";
    // Clear the latch so a fresh failure reports its own reason, not the old one.
    $("#boot-error-banner").classList.add("hidden");
    try {
      await loadCoreState();
      loadSecondaryPanels();
    } catch (e) {
      showBootError(e);
    } finally {
      btn.disabled = false;
      btn.textContent = "Retry";
    }
  });

  // Re-apply protection for every enabled app that isn't fully protected.
  $("#engine-reapply-btn").addEventListener("click", async () => {
    const btn = $("#engine-reapply-btn") as HTMLButtonElement;
    btn.disabled = true;
    btn.textContent = "Applying…";
    const failures: string[] = [];
    for (const t of config.targets.filter((x) => x.enabled)) {
      const s = statusById.get(t.id)?.status;
      if (s === "not-running") continue;
      try {
        await invoke<string>("protect_now", { id: t.id });
      } catch (e) {
        failures.push(`${t.name}: ${e}`);
      }
    }
    try {
      await doRefresh();
    } catch (e) {
      console.error(e);
    }
    btn.disabled = false;
    btn.textContent = "Re-apply protection";
    if (failures.length) alert(`Some apps couldn't be re-protected:\n\n${failures.join("\n")}`);
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
    const el = e.target as HTMLInputElement;
    const on = el.checked;
    try {
      config = await invoke<Config>("update_settings", { settings: { start_minimized: on } });
    } catch (err) {
      alert(String(err));
      el.checked = !on;
    }
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
    try {
      config = await invoke<Config>("update_settings", {
        settings: { interval_secs: Number(range.value) },
      });
      // Keep the staleness grace window in step with the poll interval.
      expectedIntervalSecs = config.interval_secs || expectedIntervalSecs;
    } catch (err) {
      alert(String(err));
      range.value = String(config.interval_secs);
      updateIntervalUi(config.interval_secs);
    }
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
    markStatusFresh();
    renderCards();
    renderMaster();
  });
  await listen<PatchStateEntry[]>("patch-state-update", (e) => {
    for (const p of e.payload) patchStateById.set(p.id, p.patch_state);
    renderCards();
  });
  await listen<LogEntry>("log", (e) => addLogRow(e.payload, true));
  await listen<{ fullscreen_active: boolean; engine_health?: EngineHealth }>(
    "system-status",
    (e) => {
      setFullscreenBanner(e.payload.fullscreen_active);
      // Only react if the backend actually sends health; an older backend
      // omits it and must not be read as a state change.
      if (e.payload.engine_health) applyEngineHealth(e.payload.engine_health);
      markStatusFresh();
    }
  );
  await listen<WaBlurStatus>("wablur-status", (e) => applyWablurStatus(e.payload));
  await listen<ActivityStatus>("activity-status", (e) => applyActivityStatus(e.payload));
  await listen<SyncStatus>("sync-status", (e) => renderSyncStatus(e.payload));
  await listen<SyncEvent>("sync-event", (e) => addSyncEventRow(e.payload));
}

// ---- Boot ----

// Show the hard-failure banner. Used when the core state load fails, which
// leaves every panel below either empty or lying, so we say so at the top
// rather than presenting a half-drawn window as if it were fine.
function showBootError(e: unknown) {
  const banner = $("#boot-error-banner");
  // Keep the FIRST error. Later knock-on failures (a panel tripping over the
  // state that never loaded) are symptoms, and would otherwise bury the
  // backend message that actually explains what went wrong.
  if (banner.classList.contains("hidden")) {
    // textContent: the error may carry OS/backend text we don't control.
    $("#boot-error-reason").textContent = String(e);
  }
  banner.classList.remove("hidden");
  const sub = $("#master-sub");
  if (sub.textContent === "Loading…") sub.textContent = "Couldn't read protection state";
}

// Load everything that the main view needs. Split out of boot() so the Retry
// button can re-run exactly the same sequence without reloading the window.
async function loadCoreState() {
  const state = await invoke<FullState>("get_state");
  config = state.config;
  applyStatuses(state.statuses);
  markStatusFresh();
  expectedIntervalSecs = state.config.interval_secs || expectedIntervalSecs;
  applyEngineHealth(state.engine_health);
  applyConfigNotice(state.config_notice);
  renderLog([...state.log].reverse()); // newest first
  renderCards();
  renderMaster();
  renderSettings(state.autostart_enabled, state.is_elevated, state.elevated_task_installed);
  setFullscreenBanner(state.fullscreen_active);
  $("#boot-error-banner").classList.add("hidden");
}

// Secondary panels. Each is independent and must not be able to take down the
// main view (or each other) — previously these were bare .then() chains, so a
// single rejection became an unhandled rejection and left its panel showing
// placeholder text with no explanation.
function loadSecondaryPanels() {
  loadTargetIcons(); // fill in real app icons (non-blocking, self-catching)
  const soft = (label: string, p: Promise<unknown>) =>
    p.catch((e) => console.error(`${label} failed to load:`, e));

  soft("WhatsApp privacy status", invoke<WaBlurStatus>("get_wablur_status").then(applyWablurStatus));
  soft("Activity status", invoke<ActivityStatus>("get_activity_status").then(applyActivityStatus));
  soft(
    "Sync config",
    invoke<SyncConfig>("get_sync_config").then((c) => {
      syncConfig = c;
      renderSyncConfig(c);
    })
  );
  soft("Sync status", invoke<SyncStatus>("get_sync_status").then(renderSyncStatus));
  soft(
    "Sync events",
    invoke<SyncEvent[]>("get_sync_events", { limit: 200 }).then(renderSyncEvents)
  );
}

async function boot() {
  // A failure anywhere below used to abort the rest of boot() silently, leaving
  // the window on its static skeleton ("Loading…") with no error and no way
  // back short of restarting the app. Everything is now guarded.
  try {
    wireEvents();
  } catch (e) {
    console.error("Failed to wire UI events:", e);
    showBootError(e);
    return; // Nothing below can work without handlers; the banner is all we have.
  }

  try {
    await listenEvents();
  } catch (e) {
    // Live updates are dead, but a static render is still worth showing.
    console.error("Failed to subscribe to backend events:", e);
  }

  try {
    await loadCoreState();
  } catch (e) {
    console.error("Failed to load state:", e);
    showBootError(e);
  }

  loadSecondaryPanels();

  try {
    initUpdater();
  } catch (e) {
    console.error("Updater init failed:", e);
  }

  setInterval(checkStaleness, 5000);
}

// Last-resort visibility. Without this, a rejected invoke anywhere in the app
// vanishes into the console of a webview nobody has open.
window.addEventListener("unhandledrejection", (e) => {
  console.error("Unhandled rejection:", e.reason);
  if (!config) showBootError(e.reason);
});

window.addEventListener("DOMContentLoaded", boot);
