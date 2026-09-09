//! Persists Sync Monitor screenshot events to disk as one JSON file per day
//! (plus a small rebuilt index), so the event history survives restarts and
//! can be pruned by age or by total size.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::syncmon::SyncEvent;

static LAST_PRUNED_DATE: Mutex<String> = Mutex::new(String::new());

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaySummary {
    pub date: String,
    pub count: usize,
    pub first: String,
    pub last: String,
}

fn days_dir(base: &Path) -> PathBuf {
    base.join("sync-logs").join("days")
}

fn index_path(base: &Path) -> PathBuf {
    base.join("sync-logs").join("index.json")
}

fn day_path(base: &Path, date: &str) -> PathBuf {
    days_dir(base).join(format!("{date}.json"))
}

fn read_day(path: &Path) -> Vec<SyncEvent> {
    let Ok(data) = std::fs::read(path) else { return Vec::new() };
    serde_json::from_slice(&data).unwrap_or_default()
}

fn write_json<T: Serialize>(path: &Path, v: &T) -> std::io::Result<()> {
    let data = serde_json::to_vec_pretty(v)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

/// Append one event to its day's file and rebuild the index. Best-effort —
/// a disk error here shouldn't take down the detector.
pub fn append(base: &Path, evt: &SyncEvent) {
    let dir = days_dir(base);
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = day_path(base, &evt.date);
    let mut events = read_day(&path);
    events.push(evt.clone());
    let _ = write_json(&path, &events);
    rebuild_index(base);
}

pub fn load_day(base: &Path, date: &str) -> Vec<SyncEvent> {
    read_day(&day_path(base, date))
}

/// All events across all days, newest first.
pub fn load_all(base: &Path) -> Vec<SyncEvent> {
    let dir = days_dir(base);
    let Ok(entries) = std::fs::read_dir(&dir) else { return Vec::new() };
    let mut all: Vec<SyncEvent> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            all.extend(read_day(&path));
        }
    }
    all.sort_by(|a, b| b.datetime.cmp(&a.datetime));
    all
}

pub fn index(base: &Path) -> Vec<DaySummary> {
    let Ok(data) = std::fs::read(index_path(base)) else { return Vec::new() };
    serde_json::from_slice(&data).unwrap_or_default()
}

pub fn wipe_all(base: &Path) {
    let _ = std::fs::remove_dir_all(base.join("sync-logs"));
}

fn rebuild_index(base: &Path) {
    let dir = days_dir(base);
    let Ok(entries) = std::fs::read_dir(&dir) else { return };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let events = read_day(&path);
        if events.is_empty() {
            continue;
        }
        let date = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
        let mut first = events[0].time.clone();
        let mut last = events[0].time.clone();
        for e in &events {
            if e.time < first {
                first = e.time.clone();
            }
            if e.time > last {
                last = e.time.clone();
            }
        }
        out.push(DaySummary { date, count: events.len(), first, last });
    }
    out.sort_by(|a, b| b.date.cmp(&a.date));
    let _ = write_json(&index_path(base), &out);
}

fn prune_by_age(base: &Path, retention_days: u32, today: &str) {
    let dir = days_dir(base);
    let Ok(entries) = std::fs::read_dir(&dir) else { return };
    let cutoff = days_since_epoch(today).saturating_sub(retention_days as i64);
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
        if let Some(days) = parse_date_to_days(&name) {
            if days < cutoff {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

fn prune_by_cap(base: &Path, max_bytes: u64) {
    let dir = days_dir(base);
    let Ok(entries) = std::fs::read_dir(&dir) else { return };
    let mut files: Vec<(PathBuf, String, u64)> = Vec::new();
    let mut total = 0u64;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = entry.metadata() else { continue };
        let name = path.file_stem().unwrap_or_default().to_string_lossy().to_string();
        total += meta.len();
        files.push((path, name, meta.len()));
    }
    if total <= max_bytes {
        return;
    }
    files.sort_by(|a, b| a.1.cmp(&b.1)); // oldest date first
    for (path, _, size) in files {
        if total <= max_bytes {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            total = total.saturating_sub(size);
        }
    }
}

/// Days since the Unix epoch for a "YYYY-MM-DD" string (proleptic Gregorian),
/// used only to compare dates for pruning — matches `syncmon::day_key`.
fn parse_date_to_days(date: &str) -> Option<i64> {
    let mut parts = date.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = (y2 - era * 400) as i64;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146097 + doe - 719468)
}

fn days_since_epoch(today: &str) -> i64 {
    parse_date_to_days(today).unwrap_or(0)
}

/// Prune by age + size cap, but at most once per calendar day.
pub fn maybe_prune_daily(base: &Path, today: &str, retention_days: Option<u32>, max_mb: u32) {
    {
        let mut last = LAST_PRUNED_DATE.lock().unwrap_or_else(|e| e.into_inner());
        if *last == today {
            return;
        }
        *last = today.to_string();
    }
    if let Some(days) = retention_days {
        prune_by_age(base, days, today);
    }
    if max_mb > 0 {
        prune_by_cap(base, max_mb as u64 * 1024 * 1024);
    }
    rebuild_index(base);
}
