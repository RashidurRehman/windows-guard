/* CaptureGuard — WhatsApp privacy blur + in-app control panel.
   Blurs chats + messages (CSS) and the chat header + avatars (JS-driven inline
   style, since WhatsApp's own high-specificity rules beat plain CSS on those).
   Reveal on hover or a timed glance. A native-styled nav icon opens a modern
   settings modal. Settings persist in localStorage.

   Built ONCE per page load (guarded by PANEL_VERSION) — NOT rebuilt on every
   re-injection, which previously caused the nav icon to flicker/jump between
   positions every few seconds. Re-injections just refresh state/CSS. */
(() => {
  "use strict";
  const PANEL_VERSION = "v6-anchor-after-metaai";
  if (window.__cgBlurVersion === PANEL_VERSION) { window.__cgBlurRefresh && window.__cgBlurRefresh(); return; }
  window.__cgBlurVersion = PANEL_VERSION;
  // A real code update (not just a reload) — drop any previous instance's DOM.
  ["cg-blur-modal", "cg-blur-backdrop", "cg-blur-btn", "cg-blur-style", "cg-panel-style"].forEach(id => { const e = document.getElementById(id); if (e) e.remove(); });

  const NS = "cgBlurSettings";
  const CHAT_SEL = "#app #pane-side [role='row']";
  const MSG_ROW_SEL = "#app [data-tab='8'] [role='row']";
  const AVATAR_SEL = "#app [data-tab='8'] img";     // message-area avatars/media thumbnails
  // The open-chat header isn't a single stable element — `data-tab='6'` is
  // WhatsApp's roving-focus index, applied to several unrelated leaves (the
  // title text row AND each toolbar button individually). Blurring just one of
  // those leaves misses the avatar photo entirely. Walking up from any of them
  // to the nearest real <header> tag reliably gets the whole header (photo +
  // title + members) as one blurrable unit.
  const findHeaderEl = () => { const any = document.querySelector("#app [data-tab='6']"); return any ? any.closest("header") : null; };
  const DEFAULTS = { enabled: true, blurChats: true, blurMessages: true, blurHeader: true, blurPx: 7, revealMode: "hover", revealSec: 2.5 };
  const loadS = () => { try { return Object.assign({}, DEFAULTS, JSON.parse(localStorage.getItem(NS) || "{}")); } catch (e) { return Object.assign({}, DEFAULTS); } };
  const S = window.__cgBlurS = loadS();
  const save = () => { try { localStorage.setItem(NS, JSON.stringify(S)); } catch (e) {} };

  const IC = {
    shield: '<svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>',
    chats: '<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-3 12H7v-2h10v2zm0-3H7V9h10v2zm0-3H7V6h10v2z"/></svg>',
    msg: '<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M20 2H4c-1.1 0-2 .9-2 2v20l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z"/></svg>',
    person: '<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M12 12a5 5 0 1 0 0-10 5 5 0 0 0 0 10zm0 2c-3.33 0-10 1.67-10 5v3h20v-3c0-3.33-6.67-5-10-5z"/></svg>',
    gauge: '<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M20.38 8.57l-1.23 1.85a8 8 0 0 1-.22 7.58H5.07A8 8 0 0 1 15.58 6.85l1.85-1.23A10 10 0 0 0 3.35 19a2 2 0 0 0 1.72 1h13.85a2 2 0 0 0 1.74-1 10 10 0 0 0-.28-10.43zm-9.79 6.84a2 2 0 0 0 2.83 0l5.66-8.49-8.49 5.66a2 2 0 0 0 0 2.83z"/></svg>',
    spark: '<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M19 9l1.25-2.75L23 5l-2.75-1.25L19 1l-1.25 2.75L15 5l2.75 1.25L19 9zm-7.5.5L9 4 6.5 9.5 1 12l5.5 2.5L9 20l2.5-5.5L17 12l-5.5-2.5zM19 15l-1.25 2.75L15 19l2.75 1.25L19 23l1.25-2.75L23 19l-2.75-1.25z"/></svg>',
    hand: '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M23 5.5V20c0 2.2-1.8 4-4 4h-7.3c-1.08 0-2.1-.43-2.85-1.19L1 14.83s1.26-1.23 1.3-1.25a1.1 1.1 0 0 1 .79-.29c.22 0 .42.06.6.16L8 16V4a1.5 1.5 0 0 1 3 0v7h1V1.5a1.5 1.5 0 0 1 3 0V11h1V2.5a1.5 1.5 0 0 1 3 0V11h1V5.5a1.5 1.5 0 0 1 3 0z"/></svg>',
    clock: '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zM12 20a8 8 0 1 1 0-16 8 8 0 0 1 0 16zm.5-13H11v6l5.25 3.15.75-1.23-4.5-2.67z"/></svg>',
    timer: '<svg viewBox="0 0 24 24" width="20" height="20" fill="currentColor"><path d="M15 1H9v2h6V1zm-4 13h2V8h-2v6zm8.03-6.61l1.42-1.42c-.43-.51-.9-.99-1.41-1.41l-1.42 1.42A8.96 8.96 0 0 0 12 4a9 9 0 1 0 9 9c0-2.12-.74-4.07-1.97-5.61zM12 20a7 7 0 1 1 0-14 7 7 0 0 1 0 14z"/></svg>'
  };

  // ---- CSS-driven blur (chat rows + message rows only — these aren't fought by
  //      WhatsApp's own !important rules the way the header/avatars are) --------
  const BLUR_STYLE_ID = "cg-blur-style";
  const rowSelectors = () => { const s = []; if (S.blurChats) s.push(CHAT_SEL); if (S.blurMessages) s.push(MSG_ROW_SEL); return s; };
  const buildBlurCss = () => {
    if (!S.enabled) return "";
    const sels = rowSelectors(); if (!sels.length) return "";
    const px = Math.max(0, Number(S.blurPx) || 0);
    let css = sels.join(",") + "{filter:blur(" + px + "px)!important;transition:filter .12s ease}";
    css += sels.map(x => x + ".cg-reveal").join(",") + "{filter:blur(0)!important}";
    if (S.revealMode === "hover") css += sels.map(x => x + ":hover").join(",") + "{filter:blur(0)!important}";
    return css;
  };
  const applyRowBlur = () => {
    let el = document.getElementById(BLUR_STYLE_ID);
    if (!el) { el = document.createElement("style"); el.id = BLUR_STYLE_ID; (document.head || document.documentElement).appendChild(el); }
    const css = buildBlurCss(); if (el.textContent !== css) el.textContent = css;
  };
  document.addEventListener("mouseover", (e) => {
    if (!S.enabled || S.revealMode !== "timed") return;
    const sel = rowSelectors().join(","); if (!sel) return;
    const row = e.target && e.target.closest && e.target.closest(sel); if (!row) return;
    row.classList.add("cg-reveal"); clearTimeout(row.__cgT);
    row.__cgT = setTimeout(() => row.classList.remove("cg-reveal"), Math.max(200, S.revealSec * 1000));
  }, true);
  document.addEventListener("mouseout", (e) => {
    if (S.revealMode !== "timed") return;
    const sel = rowSelectors().join(","); if (!sel) return;
    const row = e.target && e.target.closest && e.target.closest(sel);
    if (row && !(row.contains && row.contains(e.relatedTarget))) { clearTimeout(row.__cgT); row.classList.remove("cg-reveal"); }
  }, true);

  // ---- JS-driven "hard" blur for the header + avatars ------------------------
  // Direct inline style + direct listeners always win over WhatsApp's own CSS,
  // sidestepping the specificity fight plain stylesheet rules lose there.
  const hardBound = new WeakSet();
  const hardBlurPx = () => Math.max(0, Number(S.blurPx) || 0);
  const onHardEnter = (el) => {
    el.__cgRevealed = true;
    el.style.setProperty("filter", "blur(0px)", "important");
    clearTimeout(el.__cgHT);
    if (S.revealMode === "timed") {
      el.__cgHT = setTimeout(() => {
        el.__cgRevealed = false;
        el.style.setProperty("filter", "blur(" + hardBlurPx() + "px)", "important");
      }, Math.max(200, S.revealSec * 1000));
    }
  };
  const onHardLeave = (el) => {
    clearTimeout(el.__cgHT);
    el.__cgRevealed = false;
    el.style.setProperty("filter", "blur(" + hardBlurPx() + "px)", "important");
  };
  const bindHard = (el) => {
    if (!hardBound.has(el)) {
      hardBound.add(el);
      el.style.setProperty("transition", "filter .12s ease");
      el.addEventListener("mouseenter", () => onHardEnter(el));
      el.addEventListener("mouseleave", () => onHardLeave(el));
    }
    if (!el.__cgRevealed) el.style.setProperty("filter", "blur(" + hardBlurPx() + "px)", "important");
  };
  const paintHardBlur = () => {
    const header = findHeaderEl();
    if (header) { if (S.enabled && S.blurHeader) bindHard(header); else header.style.removeProperty("filter"); }
    document.querySelectorAll(AVATAR_SEL).forEach(img => {
      if (S.enabled && S.blurMessages) bindHard(img); else img.style.removeProperty("filter");
    });
  };

  // ---- panel styles ----------------------------------------------------------
  const PANEL_STYLE_ID = "cg-panel-style";
  const panelCss = `
    #cg-blur-btn{width:40px;height:40px;display:flex;align-items:center;justify-content:center;color:#5b8f80;cursor:pointer;border-radius:50%;transition:background .15s,color .15s;flex:none}
    #cg-blur-btn:hover{background:#ffffff14;color:#3ee6b4}
    #cg-blur-btn.cg-on{color:#00d9a3}
    #cg-blur-btn.cg-float{position:fixed;left:7px;bottom:76px;z-index:2147483000}
    #cg-blur-btn svg{width:23px;height:23px}
    #cg-blur-backdrop{position:fixed;inset:0;background:rgba(6,12,10,.6);z-index:2147483200;display:none;animation:cgf .15s ease}
    #cg-blur-backdrop.cg-show{display:block}
    @keyframes cgf{from{opacity:0}to{opacity:1}}
    @keyframes cgp{from{opacity:0;transform:translate(-50%,-47%) scale(.96)}to{opacity:1;transform:translate(-50%,-50%) scale(1)}}
    #cg-blur-modal{position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);width:420px;max-width:94vw;
      background:#0c1512;border:1px solid #1d2b26;border-radius:18px;z-index:2147483201;color:#e9edef;
      font-family:'Segoe UI',system-ui,sans-serif;box-shadow:0 24px 70px rgba(0,0,0,.65);overflow:hidden;animation:cgp .17s ease}
    .cg-head{display:flex;align-items:center;gap:13px;padding:18px 18px;background:linear-gradient(120deg,#123a2e 0%,#0e211b 55%,#0c1512 100%);border-bottom:1px solid #1d2b26}
    .cg-hic{width:46px;height:46px;flex:none;border-radius:13px;background:linear-gradient(135deg,#00c896,#008f6c);color:#04150f;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 14px rgba(0,168,132,.35)}
    .cg-htx{flex:1;min-width:0}
    .cg-title{font-size:17px;font-weight:700;color:#eef4f1}
    .cg-hsub{font-size:12px;color:#8fa8a0;margin-top:1px}
    .cg-x{cursor:pointer;color:#8fa8a0;font-size:20px;line-height:1;padding:2px 4px;border-radius:6px}
    .cg-x:hover{color:#e9edef;background:#ffffff12}
    .cg-body{padding:6px 16px 14px;transition:opacity .15s}
    .cg-body.cg-off{opacity:.42;pointer-events:none;filter:saturate(.35)}
    .cg-row{padding:14px 4px;border-bottom:1px solid #14201c}
    .cg-row:last-child{border-bottom:none}
    .cg-rl{display:flex;align-items:center;gap:13px}
    .cg-ric{width:38px;height:38px;flex:none;border-radius:11px;background:#15241f;color:#2fd6a6;display:flex;align-items:center;justify-content:center}
    .cg-rt{flex:1;min-width:0}
    .cg-lbl{font-size:14.5px;font-weight:500;color:#eef4f1}
    .cg-sub{font-size:11.5px;color:#7f948d;margin-top:2px;line-height:1.35}
    .cg-pill{font-size:12px;font-weight:700;color:#2fd6a6;background:rgba(0,168,132,.13);border:1px solid rgba(0,168,132,.35);border-radius:20px;padding:3px 11px}
    .cg-sw{position:relative;width:44px;height:24px;flex:none;cursor:pointer}
    .cg-sw input{opacity:0;width:0;height:0;position:absolute}
    .cg-tr{position:absolute;inset:0;background:#33443d;border-radius:24px;transition:.15s}
    .cg-tr:before{content:"";position:absolute;width:18px;height:18px;left:3px;top:3px;background:#cfe0d9;border-radius:50%;transition:.15s}
    .cg-sw input:checked + .cg-tr{background:#00a884}
    .cg-sw input:checked + .cg-tr:before{transform:translateX(20px);background:#fff}
    .cg-slider{width:100%;margin-top:13px;accent-color:#00a884;cursor:pointer;height:4px}
    .cg-seg{display:flex;gap:0;margin-top:13px;background:#0a1310;border:1px solid #1d2b26;border-radius:11px;overflow:hidden;padding:4px}
    .cg-seg button{flex:1;display:flex;align-items:center;justify-content:center;gap:7px;background:transparent;border:none;color:#8fa8a0;padding:9px 0;font-size:13px;font-weight:600;cursor:pointer;border-radius:8px;transition:.13s}
    .cg-seg button.cg-active{background:#00a884;color:#04150f}
    .cg-seg svg{width:16px;height:16px}
  `;
  const ensurePanelStyle = () => {
    let el = document.getElementById(PANEL_STYLE_ID);
    if (!el) { el = document.createElement("style"); el.id = PANEL_STYLE_ID; (document.head || document.documentElement).appendChild(el); }
    if (el.textContent !== panelCss) el.textContent = panelCss;
  };

  // ---- modal (built once, lazily on first click) -----------------------------
  const buildModal = () => {
    if (document.getElementById("cg-blur-modal")) return;
    const bd = document.createElement("div"); bd.id = "cg-blur-backdrop";
    const m = document.createElement("div"); m.id = "cg-blur-modal";
    m.innerHTML =
      '<div class="cg-head">' +
        '<div class="cg-hic">' + IC.shield + '</div>' +
        '<div class="cg-htx"><div class="cg-title">Privacy Blur</div><div class="cg-hsub">Blur chats and messages</div></div>' +
        '<label class="cg-sw"><input type="checkbox" data-cg="enabled"><span class="cg-tr"></span></label>' +
        '<span class="cg-x" data-cg="close">&times;</span>' +
      '</div>' +
      '<div class="cg-body">' +
        '<div class="cg-row"><div class="cg-rl"><div class="cg-ric">' + IC.chats + '</div>' +
          '<div class="cg-rt"><div class="cg-lbl">Blur chats</div><div class="cg-sub">Hide chat previews in the sidebar</div></div>' +
          '<label class="cg-sw"><input type="checkbox" data-cg="blurChats"><span class="cg-tr"></span></label></div></div>' +
        '<div class="cg-row"><div class="cg-rl"><div class="cg-ric">' + IC.msg + '</div>' +
          '<div class="cg-rt"><div class="cg-lbl">Blur messages</div><div class="cg-sub">Hide message contents in conversations</div></div>' +
          '<label class="cg-sw"><input type="checkbox" data-cg="blurMessages"><span class="cg-tr"></span></label></div></div>' +
        '<div class="cg-row"><div class="cg-rl"><div class="cg-ric">' + IC.person + '</div>' +
          '<div class="cg-rt"><div class="cg-lbl">Blur chat header</div><div class="cg-sub">Hide the open chat\'s name &amp; photo</div></div>' +
          '<label class="cg-sw"><input type="checkbox" data-cg="blurHeader"><span class="cg-tr"></span></label></div></div>' +
        '<div class="cg-row"><div class="cg-rl"><div class="cg-ric">' + IC.gauge + '</div>' +
          '<div class="cg-rt"><div class="cg-lbl">Blur amount</div></div>' +
          '<span class="cg-pill" data-cg="blurPxVal"></span></div>' +
          '<input type="range" class="cg-slider" min="2" max="20" step="1" data-cg="blurPx"></div>' +
        '<div class="cg-row"><div class="cg-rl"><div class="cg-ric">' + IC.spark + '</div>' +
          '<div class="cg-rt"><div class="cg-lbl">Reveal on hover</div><div class="cg-sub">Choose how content unblurs on hover</div></div></div>' +
          '<div class="cg-seg"><button data-cg="mode-hover">' + IC.hand + 'Hold</button><button data-cg="mode-timed">' + IC.clock + 'Timed</button></div></div>' +
        '<div class="cg-row"><div class="cg-rl"><div class="cg-ric">' + IC.timer + '</div>' +
          '<div class="cg-rt"><div class="cg-lbl">Glance duration</div><div class="cg-sub">Re-blur after (timed mode)</div></div>' +
          '<span class="cg-pill" data-cg="revealSecVal"></span></div>' +
          '<input type="range" class="cg-slider" min="0.5" max="8" step="0.5" data-cg="revealSec"></div>' +
      '</div>';
    document.body.appendChild(bd); document.body.appendChild(m);
    bd.addEventListener("click", () => toggleModal(false));
    m.addEventListener("click", (e) => {
      const b = e.target && e.target.closest && e.target.closest("[data-cg]");
      const k = b && b.getAttribute("data-cg");
      if (k === "close") toggleModal(false);
      if (k === "mode-hover") { S.revealMode = "hover"; commit(); }
      if (k === "mode-timed") { S.revealMode = "timed"; commit(); }
    });
    m.addEventListener("change", (e) => {
      const k = e.target && e.target.getAttribute && e.target.getAttribute("data-cg"); if (!k) return;
      if (e.target.type === "checkbox") S[k] = e.target.checked;
      else if (e.target.type === "range") S[k] = Number(e.target.value);
      commit();
    });
    m.addEventListener("input", (e) => {
      const k = e.target && e.target.getAttribute && e.target.getAttribute("data-cg");
      if (k === "blurPx") { const v = document.querySelector('[data-cg="blurPxVal"]'); if (v) v.textContent = e.target.value + " px"; }
      if (k === "revealSec") { const v = document.querySelector('[data-cg="revealSecVal"]'); if (v) v.textContent = e.target.value + "s"; }
    });
  };
  const syncModal = () => {
    const q = (s) => document.querySelector(s); if (!q("#cg-blur-modal")) return;
    ["enabled", "blurChats", "blurMessages", "blurHeader"].forEach(k => { const el = q('[data-cg="' + k + '"]'); if (el) el.checked = !!S[k]; });
    const bp = q('[data-cg="blurPx"]'); if (bp) bp.value = S.blurPx;
    const bpv = q('[data-cg="blurPxVal"]'); if (bpv) bpv.textContent = S.blurPx + " px";
    const rs = q('[data-cg="revealSec"]'); if (rs) rs.value = S.revealSec;
    const rsv = q('[data-cg="revealSecVal"]'); if (rsv) rsv.textContent = S.revealSec + "s";
    const mh = q('[data-cg="mode-hover"]'), mt = q('[data-cg="mode-timed"]');
    if (mh && mt) { mh.classList.toggle("cg-active", S.revealMode === "hover"); mt.classList.toggle("cg-active", S.revealMode === "timed"); }
    const body = q("#cg-blur-modal .cg-body"); if (body) body.classList.toggle("cg-off", !S.enabled);
  };
  let modalOpen = false;
  const toggleModal = (v) => {
    modalOpen = (v === undefined) ? !modalOpen : v;
    const bd = document.getElementById("cg-blur-backdrop"), m = document.getElementById("cg-blur-modal");
    if (bd) bd.classList.toggle("cg-show", modalOpen);
    if (m) m.style.display = modalOpen ? "block" : "none";
    if (modalOpen) syncModal();
  };

  // ---- native nav button (built once; placement retried until properly
  // anchored, then frozen — no further churn). Inserted directly after the
  // "Meta AI" nav icon (falling back to other known icons if Meta AI isn't in
  // this build/locale/account), never appended to the end of the list.
  //
  // IMPORTANT: while WhatsApp is still hydrating, "Meta AI" may not exist yet.
  // If we floated the button as a temporary fallback, `btn.isConnected` becomes
  // permanently true (it's attached to <body>), so a naive "only place if not
  // connected" check would never retry — the button would be stuck floating
  // forever. `anchored` tracks whether we've actually landed on a REAL nav
  // anchor (not just "attached somewhere"), so we keep retrying every refresh
  // tick until that happens, then stop.
  const findAnchorWrap = () => {
    const labels = ["Meta AI", "Communities", "Channels", "Status", "Calls", "Chats"];
    for (const label of labels) {
      const el = document.querySelector('[aria-label="' + label + '"]');
      if (el) { const wrap = el.closest("span") || el.parentElement; if (wrap && wrap.parentElement) return wrap; }
    }
    return null;
  };
  let btn = null;
  let anchored = false;
  const ensureButton = () => {
    if (!btn) {
      btn = document.createElement("div");
      btn.id = "cg-blur-btn"; btn.setAttribute("role", "button"); btn.setAttribute("tabindex", "0");
      btn.title = "Privacy Blur"; btn.innerHTML = IC.shield;
      btn.addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); buildModal(); toggleModal(); });
    }
    if (!anchored) {
      const anchor = findAnchorWrap();
      if (anchor && anchor.parentElement) {
        btn.classList.remove("cg-float");
        anchor.parentElement.insertBefore(btn, anchor.nextSibling);
        anchored = true;
      } else if (!btn.isConnected && document.body) {
        btn.classList.add("cg-float");
        document.body.appendChild(btn);
      }
    }
    btn.classList.toggle("cg-on", !!S.enabled);
  };

  const commit = () => { save(); applyRowBlur(); paintHardBlur(); syncModal(); ensureButton(); };
  const refresh = () => { ensurePanelStyle(); applyRowBlur(); paintHardBlur(); ensureButton(); };
  window.__cgBlurRefresh = refresh;

  refresh();

  if (!window.__cgBlurObserver) {
    window.__cgBlurObserver = true;
    let raf = 0;
    new MutationObserver(() => { cancelAnimationFrame(raf); raf = requestAnimationFrame(() => { if (window.__cgBlurRefresh) window.__cgBlurRefresh(); }); })
      .observe(document.documentElement, { childList: true, subtree: true });
  }
})();
