// Ravenne Wallet — desktop shell frontend (vanilla JS)
import { bridge } from "./bridge.js";
import * as M from "./motion.js";

const $ = id => document.getElementById(id);
const el = (tag, cls, html) => { const e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };
const esc = s => String(s ?? "").replace(/[&<>"]/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]));
const sleep = ms => new Promise(r => setTimeout(r, ms));

/* ── state ── */
const state = {
  config: null,
  hwid: null,
  vault: null,        // decrypted container { profiles, active, settings }
  password: null,
  ethersReady: false,
  update: null,
};

/* ── settings (§5) — persisted locally ── */
const settings = Object.assign({
  theme: "dark", glow: "soft", motion: "on", discreet: "off",
  autolockMin: 5, clipboardClearSecs: 45, doubleConfirm: true,
  updateChannel: "stable", checkUpdateOnStart: true,
  closeToTray: true, language: "en",
  vpnGate: true,
}, JSON.parse(localStorage.getItem("rv-ui-settings") || "{}"));
const saveSettings = () => {
  localStorage.setItem("rv-ui-settings", JSON.stringify(settings));
  applySettings();
};
function applySettings() {
  document.documentElement.dataset.theme = settings.theme === "auto"
    ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : settings.theme;
  document.documentElement.dataset.glow = settings.glow;
  document.body.dataset.motion = settings.motion;
  document.body.dataset.discreet = settings.discreet;
  bridge.invoke("set_close_to_tray", { value: settings.closeToTray });
}

/* ── toasts / modals (jamais alert()) ── */
function toast(msg, ok = null) {
  const t = el("div", "toast", esc(msg));
  if (ok === true) { t.style.borderColor = "var(--ok-solid)"; }
  if (ok === false) { t.style.borderColor = "var(--err-solid)"; }
  $("toasts").appendChild(t);
  requestAnimationFrame(() => t.classList.add("on"));
  setTimeout(() => { t.classList.remove("on"); setTimeout(() => t.remove(), 300); }, 3400);
}
function modal(html, actions = []) {
  const box = $("modal-box");
  box.innerHTML = html;
  const back = $("modal-back");
  back.classList.add("on");                       // spec #14 settle via CSS
  for (const [label, cls, fn] of actions) {
    const b = el("button", "btn " + (cls || ""), esc(label));
    b.onclick = () => { back.classList.remove("on"); fn?.(); };
    box.appendChild(el("div", "row", "")).appendChild(b);
  }
  back.onclick = e => { if (e.target === back) back.classList.remove("on"); };
  return box;
}

/* ── router (spec #13 crossfade) ── */
const screens = ["s-config", "s-gate", "s-mode", "s-pass", "s-wallet"];
let activeScreen = null;
function go(id) {
  const from = activeScreen ? $(activeScreen) : null;
  const to = $(id);
  M.switchScreen(from, to);
  activeScreen = id;
}

/* ═══════════ 1. CONFIG (première exécution) ═══════════ */
async function screenConfig() {
  try { document.title = "RV: first-run configuration"; } catch {}
  go("s-config");
  const saved = await bridge.invoke("load_ui_config");
  if (saved) { state.config = saved; return screenGate(); }
  // case "mode dev" : tester sans gist ni webhook (documenté dans README-UI.md)
  const devRow = el("label", "row", `<input type="checkbox" id="cfg-dev" style="width:auto">
    <span>Mode dev — skip the machine lock (local testing)</span>`);
  devRow.style.marginTop = "16px";
  $("cfg-save").parentElement.insertBefore(devRow, $("cfg-save"));
  $("cfg-save").onclick = async () => {
    const cfg = {
      webhook: $("cfg-webhook").value.trim(),
      whitelist: $("cfg-whitelist").value.trim(),
      repo: $("cfg-repo").value.trim(),
      dev: document.getElementById("cfg-dev")?.checked === true,
    };
    if (!cfg.whitelist && !cfg.dev) return toast("Whitelist URL is required", false);
    await bridge.invoke("save_ui_config", { config: cfg });
    state.config = cfg;
    toast("Configuration saved");
    screenGate();
  };
}

/* ═══════════ 2. GATE HWID ═══════════ */
async function screenGate() {
  try { document.title = "RV: gate — checking machine…"; } catch {}
  go("s-gate");
  $("gate-computing").classList.remove("hidden");
  $("gate-denied").classList.add("hidden");
  let info;
  try { info = await bridge.invoke("get_hwid"); }
  catch (e) { uiLog("get_hwid failed: " + e); info = { hwid: "unavailable", grouped: "(fingerprint error)", machine: "?", user: "?", os: "?" }; }
  state.hwid = info;
  $("gate-hwid").textContent = info.grouped;

  // flag local présent → passage silencieux définitif
  let flag = null;
  try { flag = await bridge.invoke("check_local_flag"); } catch (e) { uiLog("flag read failed: " + e); }
  if (flag === info.hwid) { uiLog("gate: local flag ok"); return screenMode(); }

  // mode dev (config) : saute le verrou machine pour tester sans gist
  if (state.config.dev === true) {
    console.log("[ravenne] DEV MODE — machine lock skipped");
    return screenMode();
  }

  // whitelist distante (cache en secours hors ligne)
  let list = null, offline = false;
  try { list = await bridge.invoke("fetch_whitelist", { url: state.config.whitelist }); }
  catch (e) {
    uiLog("whitelist fetch failed: " + e);
    try { list = await bridge.invoke("cached_whitelist"); } catch {}
    offline = true;
  }

  const known = !!list?.machines?.some(m => m.id === info.hwid);
  if (known) {
    try { await bridge.invoke("write_local_flag", { hwid: info.hwid }); } catch (e) { uiLog("flag write failed: " + e); }
    try { await bridge.invoke("send_webhook", { url: state.config.webhook, kind: "authorized", label: "", hwid: info.hwid }); }
    catch (e) { uiLog("webhook (authorized) failed: " + e); }
    uiLog("gate: authorized via whitelist");
    return screenMode();                                    // silencieux aux prochaines fois
  }

  // accès restreint
  $("gate-computing").classList.add("hidden");
  $("gate-denied").classList.remove("hidden");
  M.reveal($("gate-denied"));
  uiLog("gate: machine not whitelisted (offline=" + offline + ")");
  bridge.invoke("send_webhook", { url: state.config.webhook, kind: "denied", label: "", hwid: info.hwid })
    .catch(e => uiLog("webhook (denied) failed: " + e));
  $("gate-neterr").textContent = offline ? "Whitelist unreachable — cached list used; unknown machines stay blocked." : "";
  $("gate-copy").onclick = async () => {
    await bridge.invoke("clipboard_copy_autoclear", { text: info.hwid, clear_after_secs: settings.clipboardClearSecs });
    M.pulse($("gate-copy"));
    toast("HWID copied (auto-clear " + settings.clipboardClearSecs + "s)", true);
  };
  $("gate-retry").onclick = () => screenGate();
}

/* ═══════════ 3. CHOIX DE MODE ═══════════ */
async function screenMode() {
  try { document.title = "RV: ready — choose a mode"; } catch {}
  go("s-mode");
  const cards = document.querySelectorAll(".mode-card");
  M.stagger(cards[0].parentElement);                       // spec #3
  $("mode-terminal").onclick = async () => {
    await bridge.invoke("open_terminal");
    toast("Terminal opened — Ravenne is in the tray");
  };
  $("mode-app").onclick = () => screenPass();
  $("mode-quit").onclick = () => window.close();
}

/* ═══════════ 4. MOT DE PASSE ═══════════ */
async function screenPass() {
  go("s-pass");
  $("pass-input").value = "";
  $("pass-err").textContent = "";
  const submit = async () => {
    const pw = $("pass-input").value;
    if (!pw) return;
    if (!(await bridge.invoke("gate_verify", { password: pw }))) {
      $("pass-err").textContent = "Wrong password.";
      return;
    }
    try {
      state.password = pw;
      state.vault = await bridge.invoke("vault_unlock", { password: pw });
      screenWallet();
    } catch { $("pass-err").textContent = "Vault decryption failed."; }
  };
  $("pass-go").onclick = submit;
  $("pass-input").onkeydown = e => { if (e.key === "Enter") submit(); };
  $("pass-input").focus();
}

function lockApp() {
  state.vault = null; state.password = null;
  toast("Session locked");
  screenPass();
}

/* ═══════════ 5. WALLET ═══════════ */
const cur = () => state.vault.profiles[state.vault.active];
const EVM = { eth: { rpc: "https://ethereum-rpc.publicnode.com", sym: "ETH", ex: "https://etherscan.io" },
  poly: { rpc: "https://polygon-bor-rpc.publicnode.com", sym: "POL", ex: "https://polygonscan.com" },
  bsc: { rpc: "https://bsc-rpc.publicnode.com", sym: "BNB", ex: "https://bscscan.com" },
  arb: { rpc: "https://arbitrum-one-rpc.publicnode.com", sym: "ETH", ex: "https://arbiscan.io" },
  base: { rpc: "https://base-rpc.publicnode.com", sym: "ETH", ex: "https://basescan.org" },
  op: { rpc: "https://optimism-rpc.publicnode.com", sym: "ETH", ex: "https://optimistic.etherscan.io" } };
const fmt18 = w => { const e = window.ethers?.formatEther?.(BigInt(w)) ?? "0"; return (+e).toFixed(6).replace(/0+$/, "").replace(/\.$/, "") || "0"; };

async function screenWallet() {
  go("s-wallet");
  await ensureEthers();
  renderProfileMenu();
  renderOverview();
  startAutolock();
  updateBadge();
  if (settings.checkUpdateOnStart) checkUpdates(false);
}
async function ensureEthers() {
  if (state.ethersReady) return;
  for (let i = 0; i < 40 && !window.ethers; i++) await sleep(120);
  state.ethersReady = !!window.ethers;
}
const active = () => state.vault.profiles[state.vault.active];
const mainEvm = () => active().wallets.find(w => w.role === "main");
const recvEvm = () => active().wallets.filter(w => w.role === "receive");
const balances = {};   // cache solde par adresse

function renderProfileMenu() {
  const names = Object.keys(state.vault.profiles);
  $("profile-btn").textContent = `${state.vault.active} ▾`;
  const menu = $("profile-menu");
  menu.innerHTML = "";
  for (const n of names) {
    const p = state.vault.profiles[n];
    const b = el("button", "", `${n} <span class="dim" style="float:right">${p.wallets.length} EVM · ${p.btcWallets.length} BTC</span>`);
    b.onclick = () => {
      state.vault.active = n;
      $("profile-dd").classList.remove("open");
      renderProfileMenu(); renderOverview();
      toast("Wallet: " + n, true);
      M.pulse($("profile-btn"));
    };
    menu.appendChild(b);
  }
  const add = el("button", "", "+ New wallet");
  add.onclick = async () => {
    const name = prompt("New wallet profile name:");
    if (!name || state.vault.profiles[name]) return;
    state.vault.profiles[name] = { name, wallets: [], btcWallets: [], xmrWallets: [], history: [], chainTx: [], network: "eth" };
    state.vault.active = name;
    await persist();
    $("profile-dd").classList.remove("open");
    renderProfileMenu(); renderOverview();
  };
  menu.appendChild(add);
  if (!M.prefers) $("profile-btn").onclick = () => $("profile-dd").classList.toggle("open");
}
async function persist() {
  await bridge.invoke("vault_write_encrypted", { password: state.password, payload: state.vault });
}

/* ── vue Overview (soldes par chaîne) ── */
async function renderOverview() {
  const pane = $("tab-overview");
  pane.innerHTML = "";
  const head = el("div", "row", `<h2 class="grow">Overview</h2><span class="dim">${cur().network.toUpperCase()}</span>`);
  pane.appendChild(head);
  const grid = el("div", "stagger", "");
  grid.style.cssText = "display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px";
  pane.appendChild(grid);

  // EVM chains
  for (const k of Object.keys(EVM)) {
    const c = el("div", "card hoverable", `<div class="dim">${EVM[k].ex.replace("https://", "")}</div>`);
    c.appendChild(el("div", "balance-val mono", "loading…"));
    grid.appendChild(c);
    try {
      const prov = new window.ethers.JsonRpcProvider(EVM[k].rpc);
      const bals = await Promise.all(cur().wallets.map(w => prov.getBalance(w.address).catch(() => null)));
      const total = bals.reduce((s, b) => b ? s + b : s, 0n);
      c.lastChild.textContent = `${fmt18(total)} ${EVM[k].sym}`;
      const funded = bals.filter(b => b && b > 0n).length;
      c.appendChild(el("div", "dim", `${funded}/${cur().wallets.length} funded`));
      balances[k] = { total, bals };
    } catch { c.lastChild.textContent = "unreachable"; }
  }
  // BTC
  const btc = el("div", "card hoverable", `<div class="dim">Bitcoin</div><div class="balance-val mono">loading…</div>`);
  grid.appendChild(btc);
  try {
    const addrs = cur().btcWallets.map(w => w.address);
    let total = 0;
    for (const a of addrs) {
      const j = await (await fetch(`https://blockstream.info/api/address/${a}`)).json();
      total += (j.chain_stats.funded_txo_sum - j.chain_stats.spent_txo_sum) / 1e8;
    }
    btc.lastChild.textContent = `${total.toFixed(8)} BTC`;
  } catch { btc.lastChild.textContent = cur().btcWallets.length ? "unreachable" : "no BTC wallet"; }
  // XMR
  const xmr = el("div", "card hoverable", `<div class="dim">Monero</div><div class="balance-val mono">${cur().xmrWallets.length ? "engine required" : "no XMR wallet"}</div>`);
  grid.appendChild(xmr);
  M.stagger(grid);
  setStatus(true);
}
function setStatus(ok) {
  $("net-dot").style.background = ok ? "var(--ok-solid)" : "var(--err-solid)";
  $("net-label").textContent = ok ? "network ok" : "offline";
}

/* ── vue Receive ── */
function renderReceive() {
  const pane = $("tab-receive"); pane.innerHTML = "";
  const wrap = el("div", "stagger");
  const w = mainEvm() || cur().wallets[0];
  if (!w) { pane.appendChild(el("div", "dim", "No wallet — run the CLI setup first.")); pane.appendChild(wrap); return; }
  const card = el("div", "card", `<h3>Receiving address (EVM, all chains)</h3>
    <div class="mono" style="margin:12px 0;word-break:break-all">${esc(w.address)}</div>`);
  const row = el("div", "row");
  const copy = el("button", "btn primary", "Copy");
  copy.onclick = async () => {
    await bridge.invoke("clipboard_copy_autoclear", { text: w.address, clear_after_secs: settings.clipboardClearSecs });
    M.pulse(copy); toast(`Copied — clipboard clears in ${settings.clipboardClearSecs}s`, true);
  };
  row.appendChild(copy);
  const qrBtn = el("button", "btn", "QR code");
  qrBtn.onclick = () => {
    let qrHtml = "(QR library not loaded)";
    try {
      const qr = window.qrcode(0, "M"); qr.addData(w.address); qr.make();
      qrHtml = qr.createSvgTag({ cellSize: 3, margin: 2 });
    } catch {}
    const m = modal(`<h3>Address QR</h3><div style="text-align:center;margin:16px 0">${qrHtml}</div>
      <div class="mono dim" style="word-break:break-all">${esc(w.address)}</div>`,
      [["Close", "primary", null]]);
    M.pulse(m);
  };
  row.appendChild(qrBtn);
  card.appendChild(row);
  wrap.appendChild(card);
  // toutes les adresses
  const list = el("div", "card", "<h3>All addresses</h3>");
  const tbl = el("div", "stagger", "");
  cur().wallets.forEach((wl, i) => {
    const r = el("div", "row", `<span class="dim mono" style="width:90px">${esc(wl.label)}</span>
      <span class="mono grow" style="word-break:break-all">${esc(wl.address)}</span>
      <span class="dim">${wl.expiresAt ? "temp ⏳" : wl.role}</span>`);
    tbl.appendChild(r);
  });
  list.appendChild(tbl); list.style.marginTop = "14px";
  wrap.appendChild(list);
  pane.appendChild(wrap);
  M.stagger(tbl);
}

/* ── vue Send (double confirmation — réglage) ── */
function renderSend() {
  const pane = $("tab-send"); pane.innerHTML = "";
  const card = el("div", "card reveal", `<h3>Send — ${EVM[cur().network].sym}</h3>
    <p class="dim" style="margin:8px 0 14px">Transactions are irreversible. Double confirmation is ${settings.doubleConfirm ? "on" : "off"}.</p>
    <label class="lbl">From</label><select id="snd-from"></select>
    <label class="lbl">To (address, wallet label or book)</label><input type="text" id="snd-to">
    <label class="lbl">Amount (or max)</label><input type="text" id="snd-amt" placeholder="0.01">
    <button class="btn primary" id="snd-go" style="margin-top:16px;width:100%">Review</button>`);
  pane.appendChild(card);
  const sel = card.querySelector("#snd-from");
  cur().wallets.filter(w => w.privateKey).forEach((w, i) => {
    sel.appendChild(el("option", "", `${w.label} — ${w.address.slice(0, 10)}…`)).value = i;
  });
  card.querySelector("#snd-go").onclick = async () => {
    const from = cur().wallets.filter(w => w.privateKey)[+sel.value];
    const to = card.querySelector("#snd-to").value.trim();
    const amt = card.querySelector("#snd-amt").value.trim();
    try {
      const prov = new window.ethers.JsonRpcProvider(EVM[cur().network].rpc);
      const signer = new window.ethers.Wallet(from.privateKey, prov);
      const bal = await prov.getBalance(from.address);
      const fee = 21000n * 2n * (await prov.getFeeData()).maxFeePerGas ?? 0n;
      const value = /^max$/i.test(amt) ? bal - fee : window.ethers.parseEther(amt.replace(",", "."));
      const confirm1 = () => modal(`<h3>Confirm send</h3>
        <p style="margin:14px 0">Send <b>${fmt18(value)} ${EVM[cur().network].sym}</b> to<br>
        <span class="mono">${esc(to)}</span><br><span class="dim">from ${esc(from.label)}</span></p>`,
        [["Cancel", "", null], ["Confirm once", "primary", () => {
          if (!settings.doubleConfirm) return doSend();
          const box = modal(`<h3>Second confirmation</h3><p style="margin:14px 0">Type <b>SEND</b> to execute:</p>`, []);
          const inp = el("input", "", ""); inp.type = "text";
          box.querySelector("p").after(inp);
          const go2 = el("button", "btn danger", "Execute");
          go2.style.marginTop = "12px";
          go2.onclick = () => inp.value === "SEND" ? doSend() : toast("Cancelled");
          box.appendChild(go2);
        }]]);
        async function doSend() {
          const tx = await signer.sendTransaction({ to, value });
          toast("Broadcasting…");
          const rc = await tx.wait();
          M.pulse($("tabs"));
          modal(`<h3>✅ Sent</h3><p class="mono" style="margin:14px 0;word-break:break-all">${rc.hash}</p>`,
            [["View on explorer", "primary", () => window.open(`${EVM[cur().network].ex}/tx/${rc.hash}`)]] );
          active().history.push({ t: new Date().toISOString(), net: cur().network, from: from.address, to,
            amount: fmt18(value), fee: "", hash: rc.hash });
          await persist();
        }
        confirm1();
    } catch (e) { toast(String(e.message || e).slice(0, 120), false); }
  };
}

/* ── vue Swap (Uniswap V2, aperçu) ── */
function renderSwap() {
  const pane = $("tab-swap"); pane.innerHTML = "";
  const card = el("div", "card reveal", `<h3>Swap — Uniswap V2 (Ethereum)</h3>
    <div class="row" style="margin-top:14px"><input type="text" id="sw-from" placeholder="ETH" style="width:110px">
    <input type="text" id="sw-to" placeholder="USDT" style="width:110px">
    <input type="text" id="sw-amt" placeholder="amount">
    <button class="btn primary" id="sw-quote">Quote</button></div>
    <div id="sw-out" class="mono dim" style="margin-top:12px"></div>`);
  pane.appendChild(card);
  card.querySelector("#sw-quote").onclick = async () => {
    const out = card.querySelector("#sw-out");
    out.textContent = "querying router…";
    try {
      const ROUTER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";
      const WETH = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
      const USDT = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
      const prov = new window.ethers.JsonRpcProvider(EVM.eth.rpc);
      const r = new window.ethers.Contract(ROUTER,
        ["function getAmountsOut(uint,address[]) view returns (uint[])"], prov);
      const amt = window.ethers.parseEther(card.querySelector("#sw-amt").value.replace(",", "."));
      const amounts = await r.getAmountsOut(amt, [WETH, USDT]);
      out.textContent = `≈ ${(+window.ethers.formatUnits(amounts[1], 6)).toFixed(2)} USDT (1% slippage protected on execution)`;
    } catch (e) { out.textContent = "error: " + String(e.message || e).slice(0, 80); }
  };
}

/* ── vue Monero ── */
function renderXmr() {
  const pane = $("tab-xmr"); pane.innerHTML = "";
  const cards = el("div", "stagger");
  const w = el("div", "card", `<h3>Monero</h3>
    <p class="dim" style="margin:10px 0;line-height:1.6">${cur().xmrWallets.length} XMR wallet(s) in this profile.
    Balances and sends use the official <span class="mono">monero-wallet-rpc</span> engine connected to a remote node.
    Configure it once in the CLI (<span class="mono">ravenne xmr install → ravenne xmr engine</span>), then the UI talks to the same engine.</p>
    <div class="mono dim">engine: ${localStorage.getItem("rv-xmr-engine") || "not configured"}</div>`);
  cards.appendChild(w);
  const list = el("div", "card", "<h3>Addresses</h3>");
  const tbl = el("div", "stagger");
  cur().xmrWallets.forEach(x => tbl.appendChild(el("div", "row",
    `<span class="dim mono" style="width:110px">${esc(x.label)}</span><span class="mono grow" style="word-break:break-all;font-size:12px">${esc(x.address)}</span><span class="dim">${x.role}</span>`)));
  if (!cur().xmrWallets.length) tbl.appendChild(el("div", "dim", "none — create in the CLI"));
  list.appendChild(tbl); list.style.marginTop = "14px";
  cards.appendChild(list);
  pane.appendChild(cards);
}

/* ── vue Temporary ── */
function renderTemp() {
  const pane = $("tab-temp"); pane.innerHTML = "";
  const card = el("div", "card reveal", `<h3>Temporary addresses</h3>
    <p class="dim" style="margin:8px 0">Burner receiving addresses. At expiry: auto-forward to main, keys erased.</p>
    <div class="row"><select id="tmp-dur" style="width:140px">
      <option value="1h">1 hour</option><option value="6h">6 hours</option>
      <option value="24h" selected>24 hours</option><option value="3d">3 days</option><option value="7d">7 days</option>
    </select><button class="btn primary" id="tmp-go">Create</button></div>`);
  pane.appendChild(card);
  card.querySelector("#tmp-go").onclick = async () => {
    const dur = card.querySelector("#tmp-dur").value;
    const hrs = dur.endsWith("h") ? +dur.slice(0, -1) : dur.endsWith("d") ? +dur.slice(0, -1) * 24 : 1;
    const w = window.ethers.Wallet.createRandom();
    cur().wallets.push({ label: `temp-${Date.now().toString(36).slice(-4)}`, address: w.address,
      privateKey: w.privateKey, role: "receive", expiresAt: Date.now() + hrs * 3600000 });
    await persist();
    M.pulse(card); toast("Temporary address created (" + dur + ")", true);
    renderTemp();
  };
  const list = el("div", "card", "<h3>Active</h3>"); list.style.marginTop = "14px";
  const tbl = el("div", "stagger");
  cur().wallets.filter(w => w.expiresAt).forEach(w => {
    const left = Math.max(0, w.expiresAt - Date.now());
    tbl.appendChild(el("div", "row", `<span class="mono grow" style="word-break:break-all">${esc(w.address)}</span>
      <span class="dim">${Math.ceil(left / 3600000)}h left</span>`));
  });
  if (!tbl.children.length) tbl.appendChild(el("div", "dim", "none"));
  list.appendChild(tbl);
  pane.appendChild(list);
}

/* ── vue History ── */
function renderHistory() {
  const pane = $("tab-history"); pane.innerHTML = "";
  const rows = [...cur().history].reverse();
  const card = el("div", "card", `<h3>History — ${rows.length} transaction(s)</h3>`);
  const tbl = el("div", "stagger", ""); tbl.style.marginTop = "12px";
  rows.slice(0, 30).forEach(x => tbl.appendChild(el("div", "row",
    `<span class="dim mono" style="width:150px">${new Date(x.t).toLocaleString()}</span>
     <span class="mono grow" style="word-break:break-all">${esc(x.from?.slice(0, 10))}… → ${esc(x.to?.slice(0, 10))}…</span>
     <span class="mono">${x.amount} ${String(x.token || "").replace("swap", "").trim() || (x.net === "xmr" ? "XMR" : x.net === "btc" ? "BTC" : EVM[x.net]?.sym || "")}</span>`)));
  if (!rows.length) tbl.appendChild(el("div", "dim", "no transactions yet"));
  card.appendChild(tbl);
  pane.appendChild(card);
}

/* ── vue Settings (§5) ── */
function renderSettings() {
  const pane = $("tab-settings"); pane.innerHTML = "";
  const card = el("div", "card reveal", `<h3>Settings</h3>`);
  const group = (title, rows) => {
    const g = el("div", "", `<h4 style="margin:18px 0 8px;color:var(--white)">${title}</h4>`);
    for (const r of rows) g.appendChild(r);
    card.appendChild(g);
  };
  const sel = (label, key, opts) => {
    const r = el("div", "row", `<span class="grow">${label}</span>`);
    const s = el("select", "", "");
    for (const [v, t] of opts) s.appendChild(el("option", "", t)).value = v;
    s.value = settings[key];
    s.onchange = () => { settings[key] = s.value; saveSettings(); toast("Saved", true); };
    r.appendChild(s);
    return r;
  };
  const chk = (label, key) => {
    const r = el("div", "row", `<span class="grow">${label}</span>`);
    const b = el("input"); b.type = "checkbox"; b.checked = settings[key];
    b.onchange = () => { settings[key] = b.checked; saveSettings(); };
    r.appendChild(b);
    return r;
  };
  const num = (label, key, min, max) => {
    const r = el("div", "row", `<span class="grow">${label}</span>`);
    const b = el("input"); b.type = "number"; b.value = settings[key]; b.min = min; b.max = max;
    b.onchange = () => { settings[key] = +b.value; saveSettings(); };
    r.appendChild(b);
    return r;
  };
  group("Appearance", [
    sel("Theme", "theme", [["dark", "Dark"], ["light", "Light"], ["auto", "Auto"]]),
    sel("Glow intensity", "glow", [["off", "Off"], ["soft", "Soft"], ["strong", "Strong"]]),
    chk("Animations", "motion"),
  ]);
  group("Security", [
    num("Auto-lock after (minutes, 0 = off)", "autolockMin", 0, 240),
    num("Clipboard auto-clear (seconds)", "clipboardClearSecs", 5, 600),
    chk("Discreet mode (blurred balances)", "discreet"),
    chk("Double confirmation for sends", "doubleConfirm"),
    chk("VPN gate before connecting", "vpnGate"),
  ]);
  group("Updates", [
    sel("Channel", "updateChannel", [["stable", "Stable"], ["beta", "Beta"]]),
    chk("Check at startup", "checkUpdateOnStart"),
  ]);
  group("Behaviour", [
    chk("Close button → tray", "closeToTray"),
    sel("Language", "language", [["en", "English"], ["fr", "Français (partiel)"]]),
  ]);
  group("Data", [
    (() => {
      const r = el("div", "row", `<span class="grow">Vault backup</span>`);
      const b = el("button", "btn", "Backup now");
      b.onclick = async () => { const p = await bridge.invoke("vault_backup"); M.pulse(b); toast("Backup written: " + p, true); };
      r.appendChild(b);
      return r;
    })(),
    (() => {
      const r = el("div", "row", `<span class="grow">Secure wipe (3× overwrite)</span>`);
      const b = el("button", "btn danger", "Wipe");
      b.onclick = () => modal(`<h3 class="err">Wipe vault</h3>
        <p class="dim" style="margin:12px 0">Destroys the vault permanently. Funds stay on-chain, recoverable only with seeds.</p>
        <input type="password" id="wipe-pw" placeholder="Master password">`,
        [["Cancel", "", null], ["Erase forever", "danger", async () => {
          try { await bridge.invoke("vault_wipe", { password: $("wipe-pw").value }); toast("Vault wiped", true); lockApp(); }
          catch { toast("Wrong password", false); }
        }]]);
      r.appendChild(b);
      return r;
    })(),
  ]);
  pane.appendChild(card);
}

/* ── tabs ── */
const TABS = { overview: renderOverview, receive: renderReceive, send: renderSend, swap: renderSwap,
               xmr: renderXmr, temp: renderTemp, history: renderHistory, settings: renderSettings };
let activeTab = "overview";
document.querySelectorAll(".tab").forEach(b => b.onclick = () => {
  document.querySelectorAll(".tab").forEach(x => x.style.borderColor = "");
  b.style.borderColor = "var(--gray)";                                  // glow onglet actif
  b.style.boxShadow = "0 0 calc(12px * var(--glow-mult)) var(--glow-color)";
  activeTab = b.dataset.tab;
  document.querySelectorAll(".tabpane").forEach(p => p.classList.add("hidden"));
  const pane = $("tab-" + activeTab);
  pane.classList.remove("hidden");
  TABS[activeTab]();
});

/* ── auto-lock (§5) + raccourcis ── */
let lastActivity = Date.now();
["mousemove", "keydown", "click"].forEach(e => document.addEventListener(e, () => lastActivity = Date.now()));
function startAutolock() {
  setInterval(() => {
    if (settings.autolockMin > 0 && Date.now() - lastActivity > settings.autolockMin * 60000
        && state.vault && activeScreen === "s-wallet") lockApp();
  }, 15000);
}
document.addEventListener("keydown", e => {
  if (e.ctrlKey && e.key.toLowerCase() === "l" && state.vault) { e.preventDefault(); lockApp(); }
  if (e.ctrlKey && e.key === ",") { e.preventDefault(); setTab("settings"); }
});
function setTab(name) {
  document.querySelector(`.tab[data-tab="${name}"]`)?.click();
}
$("btn-settings").onclick = () => setTab("settings");

/* ── updater (auto, non bloquant) ── */
async function updateBadge() {
  const info = await bridge.invoke("app_info");
  const badge = $("version-badge");
  badge.textContent = "v" + info.version;
  badge.onclick = () => bridge.openReleases(state.config?.repo);
  if (settings.checkUpdateOnStart) checkUpdates(true);
}
async function checkUpdates(silent) {
  const upd = await bridge.checkUpdate(state.config?.repo);
  if (!upd) return;
  state.update = upd;
  if (upd.available) {
    modal(`<h3>Update available — v${esc(upd.version)}</h3>
      <p class="dim" style="margin:12px 0;white-space:pre-line">${esc(upd.notes || "")}</p>`,
      [["Later", "", null], ["Download & install", "primary", async () => {
        toast("Downloading…");
        try { await bridge.installUpdate(upd); } catch (e) { toast(String(e).slice(0, 100), false); }
      }]]);
  } else if (!silent) toast("You are up to date", true);
}

/* ── boot ── */
function paintError(msg) {
  let d = document.getElementById("fatal-err");
  if (!d) {
    d = document.createElement("div");
    d.id = "fatal-err";
    d.style.cssText = "position:fixed;inset:auto 12px 12px 12px;z-index:999;background:#2a1516;color:#f3c6c6;" +
      "border:1px solid #b06a6a;border-radius:10px;padding:12px;font-family:monospace;font-size:12px;white-space:pre-wrap;max-height:40vh;overflow:auto";
    document.body.appendChild(d);
  }
  d.textContent += msg + "\n";
}
function uiLog(line) {
  try { bridge.invoke("ui_log", { line }); } catch {}
  console.error("[ravenne]", line);
}
(async () => {
  window.addEventListener("unhandledrejection", e => {
    const m = "[unhandled rejection] " + String(e.reason && e.reason.stack || e.reason);
    uiLog(m); paintError(m);
  });
  window.addEventListener("error", e => {
    const m = "[error] " + e.message + " @ " + (e.filename || "") + ":" + e.lineno;
    uiLog(m); paintError(m);
  });
  try {
    await boot();
  } catch (e) {
    const m = "[boot failed] " + String(e && e.stack || e);
    uiLog(m); paintError(m);
  }
})();
async function boot() {
  try { document.title = "RV: booting…"; } catch {}
  uiLog("boot start, bridge real=" + bridge.REAL);
  applySettings();
  const info = await bridge.invoke("app_info");
  if (!bridge.REAL) document.title = "Ravenne Wallet (mock)";
  M.rubberBand($("wallet-body"));                          // spec #11
  const cfg = await bridge.invoke("load_ui_config");
  if (!cfg) screenConfig(); else { state.config = cfg; screenGate(); }
  // verrouillage depuis le tray
  window.addEventListener("ravenne://lock", () => { if (state.vault) lockApp(); });
}
