#!/usr/bin/env node
// 🪶 Ravenne Wallet v4 — terminal wallet manager (EVM chains + Bitcoin)
//
// Security model:
//   • access.ravenne.json — scrypt(password, salt) gate checked at every launch
//   • vault.ravenne.json  — AES-256-GCM encrypted with the same master password
//   • keys never leave this machine; only balance/tx queries hit RPC endpoints

import {
  Wallet, HDNodeWallet, JsonRpcProvider, Mnemonic, Contract, Transaction,
  formatEther, parseEther, parseUnits, getAddress,
} from "ethers";
import prompts from "prompts";
import qrcode from "qrcode-terminal";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { exec } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

/* Bitcoin */
import * as bitcoin from "bitcoinjs-lib";
import { HDKey } from "@scure/bip32";
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

const VERSION = "6.4.0";
process.title = "Ravenne Wallet";

/* Network-layer privacy: when HTTPS_PROXY / ALL_PROXY is set, route ALL outgoing
   HTTP (RPC, explorers, prices) through it — e.g. a VPN box's local proxy or a
   Tor bridge (http://127.0.0.1:8118 via Privoxy). */
async function setupProxy() {
  try {
    const prox = process.env.HTTPS_PROXY || process.env.https_proxy || process.env.ALL_PROXY || process.env.all_proxy;
    if (prox) {
      const { ProxyAgent, setGlobalDispatcher } = await import("undici");
      setGlobalDispatcher(new ProxyAgent(prox));
      console.log(c.dim(`✓ proxy active: ${prox}`));
    }
  } catch { /* undici unavailable — direct connections */ }
}
/* When compiled to an .exe (pkg), files must live NEXT TO the exe (snapshot FS is read-only).
   In a CJS bundle, import.meta.url is unavailable — fall back to argv[1]. */
const IS_PKG = !!process.pkg;
function hereDir() {
  if (IS_PKG) return path.dirname(process.execPath);
  try { return path.dirname(fileURLToPath(import.meta.url)); }
  catch { return path.dirname(path.resolve(process.argv[1] || process.cwd())); }
}
const HERE = hereDir();
const VAULT_FILE = path.join(HERE, "vault.ravenne.json");
const GATE_FILE = path.join(HERE, "access.ravenne.json");

/* ─────────── Networks (EVM) ─────────── */
const NET = {
  local:{ label: "Local (test)",  rpc: "http://127.0.0.1:8545",                sym: "ETH", ex: null,                          cg: null, api: null },
  eth:  { label: "Ethereum",      rpc: "https://ethereum-rpc.publicnode.com",  sym: "ETH", ex: "https://etherscan.io",    cg: "ethereum", api: "https://eth.blockscout.com" },
  poly: { label: "Polygon",       rpc: "https://polygon-bor-rpc.publicnode.com", sym: "POL", ex: "https://polygonscan.com", cg: "polygon-ecosystem-token", api: "https://polygon.blockscout.com" },
  bsc:  { label: "BNB Chain",     rpc: "https://bsc-rpc.publicnode.com",       sym: "BNB", ex: "https://bscscan.com",     cg: "binancecoin", api: "https://bsc.blockscout.com" },
  arb:  { label: "Arbitrum",      rpc: "https://arbitrum-one-rpc.publicnode.com", sym: "ETH", ex: "https://arbiscan.io",   cg: "ethereum", api: "https://arbitrum.blockscout.com" },
  base: { label: "Base",          rpc: "https://base-rpc.publicnode.com",      sym: "ETH", ex: "https://basescan.org",    cg: "ethereum", api: "https://base.blockscout.com" },
  op:   { label: "Optimism",      rpc: "https://optimism-rpc.publicnode.com",  sym: "ETH", ex: "https://optimistic.etherscan.io", cg: "ethereum", api: "https://optimism.blockscout.com" },
};
const NET_ALIASES = { local: "local", ganache: "local", test: "local", dev: "local",
                      ethereum: "eth", eth: "eth", polygon: "poly", poly: "poly", matic: "poly",
                      bnb: "bsc", bsc: "bsc", "bnb chain": "bsc", arbitrum: "arb", arb: "arb",
                      base: "base", optimism: "op", op: "op" };
/* Bitcoin metadata (balances & broadcast via Blockstream Esplora) */
const BTC = { label: "Bitcoin", sym: "BTC", ex: "https://mempool.space", cg: "bitcoin" };
const BTC_API = () => settings().btcTest ? "https://blockstream.info/testnet/api" : "https://blockstream.info/api";
const BTC_NET = () => settings().btcTest ? bitcoin.networks.testnet : bitcoin.networks.bitcoin;
const BTC_PATH = i => `m/84'/${settings().btcTest ? 1 : 0}'/0'/0/${i}`;   // BIP84 native segwit

/* Well-known ERC-20 defaults (mainnet contracts, per chain). */
const DEFAULT_TOKENS = {
  eth:  [ { sym: "USDT", addr: "0xdAC17F958D2ee523a2206206994597C13D831ec7", dec: 6 },
          { sym: "USDC", addr: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", dec: 6 } ],
  poly: [ { sym: "USDC", addr: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", dec: 6 },
          { sym: "USDT", addr: "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", dec: 6 } ],
  bsc:  [ { sym: "USDT", addr: "0x55d398326f99059fF775485246999027B3197955", dec: 18 },
          { sym: "USDC", addr: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", dec: 18 } ],
  arb:  [ { sym: "USDT", addr: "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", dec: 6 },
          { sym: "USDC", addr: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", dec: 6 } ],
  base: [ { sym: "USDC", addr: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", dec: 6 } ],
  op:   [ { sym: "USDC", addr: "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", dec: 6 } ],
};
const ERC20_ABI = [
  "function balanceOf(address) view returns (uint256)",
  "function transfer(address to, uint256 amount) returns (bool)",
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)",
];

/* ─────────── Colors & basic helpers ─────────── */
const TTY = process.stdout.isTTY;
const c = {
  vio: s => TTY ? `\x1b[35m${s}\x1b[0m` : s,
  ok:  s => TTY ? `\x1b[32m${s}\x1b[0m` : s,
  err: s => TTY ? `\x1b[31m${s}\x1b[0m` : s,
  warn:s => TTY ? `\x1b[33m${s}\x1b[0m` : s,
  dim: s => TTY ? `\x1b[90m${s}\x1b[0m` : s,
  bold:s => TTY ? `\x1b[1m${s}\x1b[0m` : s,
  cyan:s => TTY ? `\x1b[36m${s}\x1b[0m` : s,
  wht: s => TTY ? `\x1b[97m${s}\x1b[0m` : s,
};
const sleep = ms => new Promise(r => setTimeout(r, ms));
const short = a => `${a.slice(0, 8)}…${a.slice(-6)}`;
const fmtUnits = (wei, dec = 18) => {
  let s = wei.toString().padStart(dec + 1, "0");
  const i = s.slice(0, s.length - dec) || "0", d = (dec ? s.slice(-dec) : "").slice(0, 6).replace(/0+$/, "");
  return d ? `${i}.${d}` : i;
};
const fmtAmt = wei => fmtUnits(wei, 18);
const fmtBtc = sats => { // sats -> "0.00123456" style
  let s = BigInt(sats).toString().padStart(9, "0");
  const i = s.slice(0, s.length - 8), d = s.slice(-8).replace(/0+$/, "");
  return d ? `${i}.${d}` : i;
};
const usd = n => new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(n);
const eur = n => new Intl.NumberFormat("en-US", { style: "currency", currency: "EUR" }).format(n);
const dt  = iso => new Date(iso).toLocaleString("en-GB");

/* ─────────── State ─────────── */
const DEFAULT_SETTINGS = {
  prices: false,                    // privacy: no price API calls unless enabled
  vpnCheck: true,                   // refuse to connect without an active VPN
  autolockMin: 5, rpc: {}, tokens: {}, book: [], explorers: {}, btcTest: false,
  privacy: { retainPermille: 3 },   // EVM sweeps keep a random 0–0.3% behind
  seeds: {},                        // { receive: <phrase> } for the simple mode
  xmrRpc: null, xmrRpcAuth: null, xmrDaemon: null, xmrStage: false, xmrFiles: {},
};
const state = { payload: null, pass: null, autoYes: false, flags: { delay: 0 } };
/* The vault holds several NAMED PROFILES; one is active per session.
   Each profile = its own EVM/BTC/XMR wallets, history and chain. */
const V      = () => state.payload;                            // container
const cur    = () => V().profiles[V().active];                 // active profile
const W      = () => cur().wallets;                            // EVM wallets
const BW     = () => cur().btcWallets;                         // Bitcoin wallets
const XW     = () => cur().xmrWallets;                         // Monero wallets
const netKey = () => cur().network;
const N      = () => NET[netKey()];
const settings = () => (V().settings ??= structuredClone(DEFAULT_SETTINGS));
const rpcUrl   = k => settings().rpc?.[k] || NET[k].rpc;
const explorerApi = k => settings().explorers?.[k] || NET[k].api;
const provider = () => new JsonRpcProvider(rpcUrl(netKey()));
/* USB-mounted wallets live in RAM only — strip them so save() can NEVER
   write their keys into the local vault file. */
export const stripUsb = p => {
  if (!p?.profiles) return p;
  const profiles = Object.fromEntries(Object.entries(p.profiles).map(([k, v]) =>
    [k, { ...v, wallets: v.wallets.filter(w => !w.usb), btcWallets: v.btcWallets.filter(w => !w.usb) }]));
  return { ...p, profiles };
};
const save   = () => encryptVault(stripUsb(state.payload), state.pass);

async function P(questions) {
  return prompts(questions, { onCancel: () => { console.log("\nBye 👋"); process.exit(0); } });
}
const confirm = async msg =>
  state.autoYes ? true : (await P({ type: "confirm", name: "v", message: msg, initial: false })).v;

/* ─────────── Pretty UI v4 ─────────── */
function banner() {
  console.clear();
  const p = state.payload ? V().active : null;
  console.log("");
  console.log(c.bold("RAVENNE WALLET") + c.dim(`  v${VERSION}`));
  if (p) console.log(c.dim(`wallet: `) + c.bold(p) + c.dim(` · chain: ${N().label} · ${W().length} EVM + ${BW().length} BTC + ${XW().length} XMR`));
  console.log(c.dim("─".repeat(64)));
}
function header(title) {
  const pad = Math.max(0, 44 - title.length);
  console.log(`\n${c.bold(c.vio(` ◆ ${title} `))}${c.dim("─".repeat(pad + 6))}`);
}
function box(title, lines) {
  const inner = Math.max(title.length + 4, ...lines.map(l => l.length), 20) + 2;
  console.log(c.vio(`╭─ ${title} ${"─".repeat(Math.max(0, inner - title.length - 4))}╮`));
  for (const l of lines) console.log(c.vio("│") + " " + l.padEnd(inner - 2) + c.vio("│"));
  console.log(c.vio(`╰${"─".repeat(inner)}╯`));
}
function table(headers, rows, opts = {}) {
  const aligns = opts.align || [];
  const widths = headers.map((h, i) => Math.max(h.length, ...rows.map(r => String(r[i] ?? "").length)));
  const row = cells => "  " + cells.map((cell, i) => {
    const s = String(cell ?? "");
    return aligns[i] === "r" ? s.padStart(widths[i]) : s.padEnd(widths[i]);
  }).join("  ");
  const sep = ch => c.dim("  " + widths.map(w => "─".repeat(w)).join(ch));
  if (!rows.length) { console.log(c.dim("  (nothing to show)")); return; }
  console.log(sep("┬")); console.log(c.bold(row(headers))); console.log(sep("┼"));
  rows.forEach(r => console.log(row(r))); console.log(sep("┴"));
}
function statusLine() {
  const s = `  ${c.bold("⛓")} ${N().label}  ${c.dim("·")}  👥 ${W().length} EVM ${BW().length ? c.dim(`+ ₿${BW().length} BTC`) : ""}  ${c.dim("·")}  🔒 ${settings().autolockMin || "off"}m  ${c.dim("·")}  ${settings().btcTest ? c.warn("BTC testnet") : ""}`;
  console.log(s + "\n");
}
async function spin(label, fn) {
  if (!TTY) { console.log(c.dim(`• ${label}`)); return fn(); }
  const frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"];
  let i = 0;
  const iv = setInterval(() => process.stdout.write(`\r  ${c.cyan(frames[i++ % frames.length])} ${label}`), 80);
  try { const r = await fn(); clearInterval(iv); process.stdout.write("\r\x1b[K"); return r; }
  catch (e) { clearInterval(iv); process.stdout.write("\r\x1b[K"); throw e; }
}
async function countdown(sec) {
  for (let s = sec; s > 0; s--) {
    process.stdout.write(`\r  ${c.dim(`⏳ next send in ${s}s…`)}`);
    await sleep(1000);
  }
  process.stdout.write("\r\x1b[K");
}
const keyMark = w => w.privateKey ? c.ok("● key") : w.ledgerPath ? c.warn("⧉ ledger") : c.cyan("○ watch");

/* ─────────── Password gate (scrypt verifier — password itself is never stored) ─────────── */
const kdf = (pass, salt) => crypto.scryptSync(pass, salt, 32, { N: 16384, r: 8, p: 1 });
function writeGate(pass) {
  const salt = crypto.randomBytes(16);
  fs.writeFileSync(GATE_FILE, JSON.stringify({ v: 1, salt: salt.toString("hex"), hash: kdf(pass, salt).toString("hex") }, null, 2));
}
function gateVerify(pass) {
  if (!fs.existsSync(GATE_FILE)) return false;
  const g = JSON.parse(fs.readFileSync(GATE_FILE, "utf8"));
  return crypto.timingSafeEqual(kdf(pass, Buffer.from(g.salt, "hex")), Buffer.from(g.hash, "hex"));
}
async function initGate() {
  console.log(c.vio("\n🔐 First launch — choose your master password."));
  console.log(c.dim("   It protects the tool AND encrypts the vault. It cannot be recovered."));
  let pass = process.env.RAVENNE_PASS;
  if (!pass) {
    const r = await P([
      { type: "password", name: "a", message: "New master password (8 chars min.):" },
      { type: "password", name: "b", message: "Confirm password:" },
    ]);
    if (!r.a || r.a.length < 8) { console.log(c.err("Password too short.")); process.exit(1); }
    if (r.a !== r.b) { console.log(c.err("Passwords do not match.")); process.exit(1); }
    pass = r.a;
  } else if (pass.length < 8) { console.log(c.err("RAVENNE_PASS too short (8 min.).")); process.exit(1); }
  writeGate(pass); state.pass = pass;
  console.log(c.ok("✓ Master password set (access.ravenne.json — salted hash only)."));
}
async function unlockGate() {
  if (state.pass) return;
  if (!fs.existsSync(GATE_FILE)) { await initGate(); return; }
  if (!process.env.RAVENNE_PASS) console.log(c.dim("\n🔒 Ravenne is locked — enter your master password."));
  for (let i = 0; i < 3; i++) {
    const p = process.env.RAVENNE_PASS || (await P({ type: "password", name: "p", message: "Master password:" })).p;
    if (p && gateVerify(p)) { state.pass = p; return; }
    console.log(c.err("  ✗ Wrong password."));
    if (i < 2) await sleep((i + 1) * 1200);
  }
  console.log(c.err("Too many failed attempts — exiting."));
  process.exit(1);
}
async function lockSession(clear = true) {
  if (clear) console.clear();
  state.pass = null; state.payload = null;
  console.log(c.vio("🔒 Session locked."));
  await unlockGate();
  ensureVault();
}

/* ─────────── VPN gate — no connection leaves this machine without a tunnel ─────────── */
/* Mesh/LAN VPNs (Radmin, Hamachi, ZeroTier…) link machines together but do NOT
   anonymize your traffic — by default they don't count as protection. */
const MESH_VPN = /radmin|hamachi|zerotier|tailscale|netbird|nebula|netmaker|tunngle|game ranger/i;
const REAL_VPN = /wintun|wireguard|tap-windows|tap-|openvpn|tun0|vpn|mullvad|proton|nord|express|surfshark|cyberghost|ivpn|windscribe|private internet|hidemyass|purevpn|tunnelbear|zenmate|atlas/i;
function classifyAdapters(text) {
  const lines = text.split("\n").map(s => s.trim()).filter(Boolean);
  let mesh = null, real = null;
  for (const l of lines) {
    if (MESH_VPN.test(l)) { mesh ??= l; continue; }
    if (REAL_VPN.test(l)) real ??= l;
  }
  return { real, mesh };
}
function vpnState() {
  if (process.env.RAVENNE_FORCE_VPN === "1") return Promise.resolve({ ok: true, adapter: "forced (env)" });
  if (process.env.RAVENNE_FORCE_VPN === "0") return Promise.resolve({ ok: false, adapter: null });
  return new Promise(resolve => {
    const ps = "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty InterfaceDescription";
    exec(`powershell -NoProfile -Command "${ps.replace(/"/g, '\\"')}"`, { timeout: 8000 }, (err, stdout) => {
      if (err || !stdout) return resolve({ ok: true, adapter: "unknown (check skipped)" });   // cannot tell → do not block
      const { real, mesh } = classifyAdapters(stdout);
      const meshOk = settings().meshVpnOk === true;
      if (real) return resolve({ ok: true, adapter: real });
      if (mesh && meshOk) return resolve({ ok: true, adapter: mesh + " (mesh, accepted by setting)" });
      resolve({ ok: false, adapter: null, mesh });
    });
  });
}
async function ensureVPN() {
  if (state.flags.noVpn || process.env.RAVENNE_SKIP_VPN === "1") return;
  if (settings().vpnCheck === false) return;
  while (true) {
    const st = await vpnState();
    if (st.ok) {
      if (state._vpnAnnounced !== true) { console.log(c.ok(`✓ VPN detected: ${c.bold(st.adapter)}`) + c.dim(" — network layer protected.\n")); state._vpnAnnounced = true; }
      return;
    }
    console.log("");
    box("VPN REQUIRED", [
      "No anonymity VPN is active on this machine.",
      ...(st.mesh ? [
        c.dim(`Found only: ${st.mesh.slice(0, 40)}`),
        c.dim("Mesh/LAN VPNs (Radmin, Hamachi, ZeroTier…) don't hide your traffic."),
        "" ] : []),
      "Ravenne refuses to expose your addresses and queries to",
      "network providers without an encrypted tunnel.",
      "",
      "→ Start your VPN (WireGuard, Proton, NordVPN…), then retry.",
    ]);
    if (!TTY) { console.log(c.warn("  Non-interactive session — continuing WITHOUT VPN.\n")); return; }
    const { a } = await P({ type: "select", name: "a", message: "VPN:", choices: [
      { title: "I started my VPN — check again", value: "retry" },
      { title: "Continue WITHOUT VPN (not recommended)", value: "skip" },
      { title: "Disable this check permanently", value: "off" },
      { title: "Quit", value: "quit" },
    ]});
    if (a === "retry") continue;
    if (a === "skip") { console.log(c.warn("Continuing without VPN — your IP is visible to RPC/explorer providers.\n")); return; }
    if (a === "off") { settings().vpnCheck = false; save(); console.log(c.ok("VPN check disabled (re-enable: ravenne settings vpncheck on)\n")); return; }
    process.exit(0);
  }
}

/* ─────────── Encrypted vault (AES-256-GCM) ─────────── */
export function encryptVault(payload, pass, file = VAULT_FILE) {
  const salt = crypto.randomBytes(16), iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", kdf(pass, salt), iv);
  const data = Buffer.concat([cipher.update(JSON.stringify(payload), "utf8"), cipher.final()]);
  fs.writeFileSync(file, JSON.stringify({
    app: "ravenne", v: 7,
    salt: salt.toString("hex"), iv: iv.toString("hex"),
    tag: cipher.getAuthTag().toString("hex"), data: data.toString("base64"),
  }, null, 2));
}
export function decryptVault(pass, file = VAULT_FILE) {
  const meta = JSON.parse(fs.readFileSync(file, "utf8"));
  const d = crypto.createDecipheriv("aes-256-gcm", kdf(pass, Buffer.from(meta.salt, "hex")), Buffer.from(meta.iv, "hex"));
  d.setAuthTag(Buffer.from(meta.tag, "hex"));
  return JSON.parse(Buffer.concat([d.update(Buffer.from(meta.data, "base64")), d.final()]).toString("utf8"));
}
const emptyProfile = name => ({ name, wallets: [], btcWallets: [], xmrWallets: [], history: [], chainTx: [], network: "eth" });

/* ---------- Temporary wallets - expire and self-destruct ---------- */
const parseDuration = s => {
  const m = /^(\d+(?:\.\d+)?)\s*(m|h|d)?$/i.exec(String(s ?? "").trim());
  if (!m) return null;
  const n = parseFloat(m[1]), u = (m[2] || "h").toLowerCase();
  return Math.round((u === "m" ? n / 60 : u === "d" ? n * 24 : n) * 3600000);
};
const durLabel = ms => ms >= 172800000 ? `${Math.round(ms / 3600000)}d` : ms >= 3600000 ? `${Math.round(ms / 3600000)}h` : `${Math.max(1, Math.round(ms / 60000))}m`;
/* Expired temporary wallets are forwarded to the main wallet, then their keys
   are erased from the vault. Pre-authorized at creation - no confirm needed. */
async function purgeExpired(quiet = false) {
  const now = Date.now();
  let swept = 0, purged = 0;
  const list = cur().wallets;
  for (let i = list.length - 1; i >= 0; i--) {
    const w = list[i];
    if (!w.expiresAt || w.expiresAt > now) continue;
    if (w.privateKey && mainEvm()) {
      try {
        const prov = new JsonRpcProvider(rpcUrl(netKey()));
        const bal = await prov.getBalance(w.address).catch(() => 0n);
        const per = await feePerTx(prov).catch(() => 0n);
        if (bal > per) {
          console.log(c.dim(`  ... "${w.label}" expired - forwarding ${fmtAmt(bal - per)} ${NET[netKey()].sym} to main before deleting...`));
          await doSend(list.indexOf(w), mainEvm().address, bal - per, netKey());
          swept++;
        }
      } catch (e) { console.log(c.warn(`  ! could not sweep "${w.label}": ${e.message.slice(0, 60)} - keys erased anyway, funds stay on-chain`)); }
    }
    list.splice(i, 1); purged++;
  }
  if (purged) {
    save();
    if (!quiet) {
      console.log(c.warn(`
[purge] ${purged} expired temporary wallet${purged > 1 ? "s" : ""} destroyed (keys erased).`));
      if (swept) console.log(c.ok(`   ${swept} had funds - forwarded to main first.`));
    }
  }
  return purged;
}
async function cmdTemp(args) {
  if (!mainEvm()) throw new Error("No main wallet - run the setup first (ravenne setup).");
  const dur = parseDuration(args[0] ?? "24h");
  if (dur == null) throw new Error('Duration like "30m", "12h", "3d" (default 24h).');
  let n = parseInt(args[1], 10) || 1;
  n = Math.min(n, 20);
  const expiresAt = Date.now() + dur;
  const created = [];
  for (let i = 0; i < n; i++) {
    const e = newWalletEntry(state.flags.words);
    e.label = `temp-${Date.now().toString(36).slice(-4)}-${i + 1}`;
    e.role = "receive"; e.expiresAt = expiresAt;
    W().push(e); created.push(e);
  }
  save();
  header(`TEMPORARY ADDRESSES - self-destruct in ${durLabel(dur)}`);
  table(["#", "LABEL", "ADDRESS", "EXPIRES"], created.map((w, i) =>
    [`#${W().length - n + i}`, w.label, w.address, new Date(expiresAt).toLocaleString("en-GB")]));
  console.log(c.warn(`
[!]  Give these out for ONE payment each. At expiry they are forwarded`));
  console.log(c.warn(`     to your main wallet automatically, then the keys are erased.`));
  console.log(c.dim(`
  List: ravenne temp list - forward now: ravenne sweep`));
}
/* ---------- Wallet profiles ---------- */
function profileSummary(name) {
  const p = V().profiles[name];
  const temp = p.wallets.filter(w => w.expiresAt).length;
  return `${p.wallets.length - temp} EVM + ${p.btcWallets.length} BTC + ${p.xmrWallets.length} XMR${temp ? c.dim(` - ${temp} temp`) : ""}`;
}
async function cmdProfile(args) {
  const sub = args[0] || "list";
  if (sub === "list") {
    header("WALLET PROFILES");
    table(["", "NAME", "CONTENTS"],
      Object.keys(V().profiles).map(n => [V().active === n ? c.ok("active") : "", n, profileSummary(n)]));
    console.log(c.dim("\n  ravenne profile new <name> - use <name> - rename <old> <new> - delete <name>"));
    return;
  }
  if (sub === "new") {
    const name = (args[1] || (await P({ type: "text", name: "n", message: "Profile name:" })).n || "").trim();
    if (!/^[a-zA-Z0-9 _-]{1,24}$/.test(name)) throw new Error("Name: 1-24 chars, letters/digits/space/_/-.");
    if (V().profiles[name]) throw new Error(`Profile "${name}" already exists.`);
    V().profiles[name] = emptyProfile(name); V().active = name; save();
    return console.log(c.ok(`OK Profile "${name}" created and active - empty. Run the setup: ravenne setup`));
  }
  if (sub === "use") {
    const name = args[1] || "";
    if (!V().profiles[name]) throw new Error(`Unknown profile: "${name}" (${Object.keys(V().profiles).join(", ")})`);
    V().active = name; save();
    return console.log(c.ok(`OK Active wallet: ${name}`));
  }
  if (sub === "rename") {
    const oldN = args[1], newN = (args[2] || "").trim();
    if (!V().profiles[oldN]) throw new Error(`Unknown profile: "${oldN}"`);
    if (!/^[a-zA-Z0-9 _-]{1,24}$/.test(newN)) throw new Error("Name: 1-24 chars, letters/digits/space/_/-.");
    if (V().profiles[newN]) throw new Error(`Profile "${newN}" already exists.`);
    const p = V().profiles[oldN];
    delete V().profiles[oldN];
    p.name = newN; V().profiles[newN] = p;
    if (V().active === oldN) V().active = newN;
    save();
    return console.log(c.ok(`OK Renamed: ${oldN} -> ${newN}`));
  }
  if (sub === "delete") {
    const name = args[1];
    if (!V().profiles[name]) throw new Error(`Unknown profile: "${name}"`);
    if (Object.keys(V().profiles).length < 2) throw new Error("Cannot delete the last profile.");
    const p = V().profiles[name];
    console.log(c.err(`
[!]  Deleting "${name}" removes ${p.wallets.length} EVM + ${p.btcWallets.length} BTC + ${p.xmrWallets.length} XMR wallets from the vault.`));
    console.log(c.err("   Funds stay on-chain - recoverable ONLY with their seeds/keystores."));
    const { v } = await P({ type: "text", name: "v", message: "Type the profile name to confirm:" });
    if (v !== name) return console.log("Cancelled.");
    delete V().profiles[name];
    if (V().active === name) V().active = Object.keys(V().profiles)[0];
    save();
    return console.log(c.ok(`OK Deleted. Active wallet: ${V().active}`));
  }
  throw new Error(`Unknown profile sub-command: ${sub}`);
}
/* Selection screen - after unlock, before anything else. */
async function pickProfile() {
  while (true) {
    await purgeExpired();
    header("SELECT WALLET");
    const names = Object.keys(V().profiles);
    const { a } = await P({ type: "select", name: "a", message: "Which wallet do you want to open?",
      choices: [
        ...names.map(n => ({ title: `${V().active === n ? "> " : "  "}${n}`, value: n, description: profileSummary(n) })),
        { title: "+  New wallet", value: "__new", description: "Create an empty wallet and run its setup." },
        { title: "Manage (list / rename / delete)", value: "__manage", description: "See all wallets, rename or delete one." },
      ] });
    if (a === "__new") {
      const { n } = await P({ type: "text", name: "n", message: "Name of the new wallet:" });
      const name = (n || "").trim();
      if (!/^[a-zA-Z0-9 _-]{1,24}$/.test(name)) { console.log(c.err("Invalid name (1-24 chars).")); continue; }
      if (V().profiles[name]) { console.log(c.err("Already exists.")); continue; }
      V().profiles[name] = emptyProfile(name); V().active = name; save();
      return;
    }
    if (a === "__manage") {
      await cmdProfile(["list"]);
      const { m } = await P({ type: "select", name: "m", message: "Manage:", choices: [
        { title: "Rename a wallet", value: "rename" },
        { title: "Delete a wallet", value: "delete" },
        { title: "<- Back", value: "back" },
      ] });
      if (m === "back") { console.clear(); continue; }
      const { n } = await P({ type: "text", name: "n", message: m === "rename" ? "Wallet to rename:" : "Wallet to delete:" });
      if (m === "rename") { const { n2 } = await P({ type: "text", name: "n2", message: "New name:" }); await cmdProfile(["rename", n, n2]); }
      else await cmdProfile([
"delete", n]);
      await P({ type: "text", name: "_", message: c.dim("- Enter -") });
      console.clear();
      continue;
    }
    V().active = a; save();
    return;
  }
}
function ensureVault() {
  if (state.payload) return;
  if (fs.existsSync(VAULT_FILE)) {
    try { state.payload = decryptVault(state.pass); }
    catch { console.log(c.err("Vault password differs from the master password (gate changed?). Use: ravenne changepass")); process.exit(1); }
  } else {
    state.payload = { profiles: { default: emptyProfile("default") }, active: "default", settings: structuredClone(DEFAULT_SETTINGS) };
    save();
  }
  const s = (state.payload.settings ??= structuredClone(DEFAULT_SETTINGS));
  s.rpc ??= {}; s.tokens ??= {}; s.book ??= []; s.explorers ??= {}; s.btcTest ??= false;
  s.privacy ??= { retainPermille: 3 }; s.seeds ??= {}; s.prices ??= false; s.vpnCheck ??= true;
  s.xmrRpc ??= null; s.xmrRpcAuth ??= null; s.xmrDaemon ??= null; s.xmrStage ??= false; s.xmrFiles ??= {};
  /* migration: vaults from v6.3 and earlier held ONE set of wallets directly */
  if (!state.payload.profiles) {
    const legacy = state.payload;
    const s2 = legacy.settings ?? structuredClone(DEFAULT_SETTINGS);
    state.payload = { profiles: { default: { ...emptyProfile("default"),
      wallets: legacy.wallets || [], btcWallets: legacy.btcWallets || [], xmrWallets: legacy.xmrWallets || [],
      history: legacy.history || [], chainTx: legacy.chainTx || [], network: legacy.network || "eth" } },
      active: "default", settings: s2 };
  }
  state.payload.profiles ??= {};
  if (!Object.keys(state.payload.profiles).length) state.payload.profiles.default = emptyProfile("default");
  state.payload.active ??= Object.keys(state.payload.profiles)[0];
  if (!state.payload.profiles[state.payload.active]) state.payload.active = Object.keys(state.payload.profiles)[0];
  for (const p of Object.values(state.payload.profiles)) {
    p.wallets ??= []; p.btcWallets ??= []; p.xmrWallets ??= []; p.history ??= []; p.chainTx ??= []; p.network ??= "eth";
  }
  purgeExpired(true);
}

/* ─────────── Wallet helpers (EVM) ─────────── */
function findWallet(arg) {
  const s = String(arg).trim().replace(/^#/, "");
  if (/^\d+$/.test(s)) { const i = +s; return i >= 0 && i < W().length ? i : -1; }
  return W().findIndex(w => w.label.toLowerCase() === s.toLowerCase());
}
function findBtcWallet(arg) {
  const s = String(arg).trim().replace(/^#/, "");
  if (/^\d+$/.test(s)) { const i = +s; return i >= 0 && i < BW().length ? i : -1; }
  return BW().findIndex(w => w.label.toLowerCase() === s.toLowerCase());
}
function resolveTo(arg) {
  const s = String(arg).trim();
  if (s.startsWith("0x")) { getAddress(s); return { addr: s }; }
  const i = findWallet(s);
  if (i >= 0) return { idx: i, addr: W()[i].address };
  const b = settings().book.find(x => x.label.toLowerCase() === s.toLowerCase());
  if (b) return { addr: b.address, book: b.label };
  throw new Error(`Not found: "${arg}" (index, wallet label, address-book label or 0x… address)`);
}
function nextLabel() {
  let n = W().length + 1;
  while (W().some(w => w.label === `w${n}`)) n++;
  return `w${n}`;
}
function nextBtcLabel() {
  let n = BW().length + 1;
  while (BW().some(w => w.label === `btc${n}`)) n++;
  return `btc${n}`;
}
function newWalletEntry(words) {
  const mnemonic = Mnemonic.fromEntropy(crypto.randomBytes(words === 24 ? 32 : 16));
  const w = HDNodeWallet.fromMnemonic(mnemonic);
  return { label: nextLabel(), address: w.address, privateKey: w.privateKey, phrase: mnemonic.phrase };
}
async function feePerTx(prov, gas = 21000n) {
  const f = await prov.getFeeData();
  if (f.maxFeePerGas != null) return gas * (f.maxFeePerGas + (f.maxPriorityFeePerGas ?? 0n));
  if (f.gasPrice != null) return gas * f.gasPrice;
  return gas * 30n * 10n ** 9n;
}
async function getBalances(k, prov) {
  prov = prov || new JsonRpcProvider(rpcUrl(k));
  return Promise.all(W().map(w => prov.getBalance(w.address).catch(() => null)));
}
async function maybePrices(netKeys) {
  if (!settings().prices) return null;
  try {
    const ids = [...new Set([...netKeys.map(k => NET[k]?.cg).filter(Boolean), BTC.cg])].join(",");
    const r = await fetch(`https://api.coingecko.com/api/v3/simple/price?ids=${ids}&vs_currencies=usd,eur`,
                          { signal: AbortSignal.timeout(8000) });
    return await r.json();
  } catch { return null; }
}
const netValue = (wei, k, prices) => {
  const p = prices?.[NET[k].cg];
  return p ? Number(formatEther(wei)) * p.usd : null;
};
const btcValue = (sats, prices) => {
  const p = prices?.[BTC.cg];
  return p ? (Number(sats) / 1e8) * p.usd : null;
};
const printTxLink = (hash, k) => NET[k].ex && console.log(c.dim(`   ↗ ${NET[k].ex}/tx/${hash}`));
const tokensOf = k => settings().tokens[k] || DEFAULT_TOKENS[k] || [];
const ourAddressSet = () => new Set(W().map(w => w.address.toLowerCase()));

/* ─────────── Bitcoin helpers ─────────── */
export function btcAddressFromPhrase(phrase, i, testnet = false) {
  const path = `m/84'/${testnet ? 1 : 0}'/0'/0/${i}`;
  const hd = HDKey.fromMasterSeed(mnemonicToSeedSync(phrase)).derive(path);
  const { address } = bitcoin.payments.p2wpkh({ pubkey: hd.publicKey, network: testnet ? bitcoin.networks.testnet : bitcoin.networks.bitcoin });
  return { address, hd, path };
}
function btcEntry(phrase, i) {
  const { address, path } = btcAddressFromPhrase(phrase, i, settings().btcTest);
  return { label: nextBtcLabel(), address, phrase, path, index: i };
}
async function btcFetch(pathname, body = null) {
  const r = await fetch(`${BTC_API()}${pathname}`, body
    ? { method: "POST", headers: { "Content-Type": "text/plain" }, body, signal: AbortSignal.timeout(15000) }
    : { signal: AbortSignal.timeout(15000) });
  if (!r.ok) throw new Error(`esplora answered ${r.status}`);
  return body ? r.text() : r.json();
}
async function getBtcBalances() {
  return Promise.all(BW().map(async w => {
    try {
      const j = await btcFetch(`/address/${w.address}`);
      const cs = j.chain_stats, ms = j.mempool_stats;
      return (BigInt(cs.funded_txo_sum) - BigInt(cs.spent_txo_sum))
           + (BigInt(ms.funded_txo_sum) - BigInt(ms.spent_txo_sum));
    } catch { return null; }
  }));
}
/* Builds & signs a signed P2WPKH transaction hex from UTXOs (exported for testing). */
export async function buildBtcTx(entry, utxos, toAddr, amountSat, satPerVb, testnet = settings().btcTest) {
  const VBYTE_IN = 68, VBYTE_OUT = 31, VBYTE_BASE = 11;
  const network = testnet ? bitcoin.networks.testnet : bitcoin.networks.bitcoin;
  const { address: changeAddr, hd } = btcAddressFromPhrase(entry.phrase, entry.index, testnet);
  const sorted = [...utxos].sort((a, b) => a.value - b.value);
  const picked = [];
  let acc = 0n, fee = 0n, target = BigInt(amountSat);
  for (const u of sorted) {
    picked.push(u); acc += BigInt(u.value);
    fee = BigInt((VBYTE_BASE + VBYTE_IN * picked.length + VBYTE_OUT * 2) * Math.ceil(satPerVb));
    if (acc >= target + fee) break;
  }
  if (acc < target + fee) throw new Error(`Not enough UTXOs: have ${fmtBtc(acc)} BTC, need ${fmtBtc(target + fee)} BTC (amount+fee).`);
  const psbt = new bitcoin.Psbt({ network });
  for (const u of picked) {
    const { output } = bitcoin.payments.p2wpkh({ address: changeAddr, network });
    psbt.addInput({ hash: u.txid, index: u.vout, witnessUtxo: { script: output, value: BigInt(u.value) } });
  }
  psbt.addOutput({ address: toAddr, value: target });
  const change = acc - target - fee;
  if (change >= 546n) psbt.addOutput({ address: changeAddr, value: change });
  const signer = { publicKey: hd.publicKey, sign: h => hd.sign(h) };
  for (let i = 0; i < picked.length; i++) psbt.signInput(i, signer);
  psbt.finalizeAllInputs();
  return { hex: psbt.extractTransaction().toHex(), fee, change, inputs: picked.length };
}

/* ─────────── Low-level send (EVM: native or ERC-20) ─────────── */
async function doSend(fromIdx, toAddr, valueWei, netK, token = null) {
  const src = W()[fromIdx];
  if (src.ledgerPath) return doLedgerSend(fromIdx, toAddr, valueWei, netK, token);
  const w = new Wallet(src.privateKey).connect(new JsonRpcProvider(rpcUrl(netK)));
  let tx;
  if (token) {
    const erc = new Contract(token.addr, ERC20_ABI, w);
    tx = await spin("Broadcasting token transfer…", () => erc.transfer(toAddr, valueWei));
  } else {
    tx = await spin("Broadcasting transaction…", () => w.sendTransaction({ to: toAddr, value: valueWei }));
  }
  const rc = await spin("Waiting for confirmation…", () => tx.wait());
  const gasPrice = rc.effectiveGasPrice ?? tx.gasPrice ?? tx.maxFeePerGas ?? 0n;
  const fee = BigInt(rc.gasUsed) * BigInt(gasPrice);
  cur().history.push({
    t: new Date().toISOString(), net: netK,
    from: src.address, to: toAddr,
    amount: token ? fmtUnits(valueWei, token.dec) : formatEther(valueWei),
    fee: formatEther(fee), hash: rc.hash, token: token?.sym || undefined,
  });
  save();
  return { hash: rc.hash, fee, block: rc.blockNumber };
}
/* Experimental: signs with a Ledger device (requires optional packages, see error message). */
async function doLedgerSend(fromIdx, toAddr, valueWei, netK, token = null) {
  if (token) throw new Error("Ledger + ERC-20 not supported yet — send native coin only.");
  let Transport, AppEth;
  try {
    ({ default: Transport } = await import("@ledgerhq/hw-transport-node-hid"));
    ({ default: AppEth } = await import("@ledgerhq/hw-app-eth"));
  } catch {
    throw new Error("Ledger support not installed. Run: npm i @ledgerhq/hw-transport-node-hid @ledgerhq/hw-app-eth");
  }
  const src = W()[fromIdx];
  const prov = new JsonRpcProvider(rpcUrl(netK));
  const chainId = Number((await prov.getNetwork()).chainId);
  const nonce = await prov.getTransactionCount(src.address, "pending");
  const f = await prov.getFeeData();
  const txObj = { chainId, nonce, gasLimit: 21000n, to: toAddr, value: valueWei, type: 2,
                  maxFeePerGas: f.maxFeePerGas, maxPriorityFeePerGas: f.maxPriorityFeePerGas ?? 0n };
  const unsigned = Transaction.from(txObj).unsignedSerialized.substring(2);
  const transport = await Transport.create();
  try {
    const app = new AppEth(transport);
    console.log(c.warn("  → Confirm the transaction on your Ledger device…"));
    const sig = await app.signTransaction(src.ledgerPath, unsigned);
    const bigh = v => BigInt(/^(0x)/.test(v) ? v : "0x" + v);
    const signed = Transaction.from({ ...txObj, signature: { v: bigh(sig.v), r: bigh(sig.r), s: bigh(sig.s) } });
    const tx = await spin("Broadcasting transaction…", () => prov.broadcastTransaction(signed.serialized));
    const rc = await spin("Waiting for confirmation…", () => tx.wait());
    const fee = BigInt(rc.gasUsed) * BigInt(rc.effectiveGasPrice ?? tx.maxFeePerGas ?? 0n);
    cur().history.push({ t: new Date().toISOString(), net: netK, from: src.address, to: toAddr,
                                 amount: formatEther(valueWei), fee: formatEther(fee), hash: rc.hash });
    save();
    return { hash: rc.hash, fee, block: rc.blockNumber };
  } finally { await transport.close(); }
}
const betweenSends = async (i, n) => {
  if (state.flags.delay > 0 && i < n - 1) await countdown(Math.round(state.flags.delay));
};
const requireKey = i => {
  const w = W()[i];
  if (!w.privateKey && !w.ledgerPath)
    throw new Error(`#${i} ${w.label} is watch-only (no key held) — it cannot sign here.`);
};

/* ═══════════════════════════ EVM COMMANDS ═══════════════════════════ */

async function cmdCreate(args) {
  if (state.flags.seed) return cmdCreateFromSeed(args);
  let n = parseInt(args[0], 10);
  if (!Number.isInteger(n) || n < 1)
    n = (await P({ type: "number", name: "v", message: "How many wallets to create?", initial: 1, min: 1, max: 100 })).v;
  n = Math.min(n, 100);
  const created = [];
  for (let i = 0; i < n; i++) { const e = newWalletEntry(state.flags.words); W().push(e); created.push(e); }
  save();
  header("NEW WALLETS");
  console.log(c.ok(`✓ ${n} wallet${n > 1 ? "s" : ""} created (${state.flags.words} words)`));
  table(["#", "LABEL", "ADDRESS"], created.map((w, i) => [`#${W().length - n + i}`, w.label, w.address]));
  console.log(c.dim(`\nTip: 'phrase <n>' shows a wallet's seed phrase.`));
}
async function cmdCreateFromSeed(args) {
  let n = parseInt(args[0], 10);
  const phrase = ((await P({ type: "password", name: "p", message: "Seed phrase (hidden):" })).p || "")
    .trim().split(/\s+/).join(" ").toLowerCase();
  if (!Mnemonic.isValidMnemonic(phrase)) throw new Error("Invalid seed phrase.");
  if (!Number.isInteger(n) || n < 1)
    n = (await P({ type: "number", name: "v", message: "How many accounts from this seed?", initial: 3, min: 1, max: 50 })).v;
  const base = "m/44'/60'/0'/0/";
  const created = [];
  for (let i = 0; i < n; i++) {
    // ethers ≥ 6.7 signature: fromPhrase(phrase, password, path, wordlist)
    const w = HDNodeWallet.fromPhrase(phrase, "", `${base}${i}`);
    const e = { label: nextLabel(), address: w.address, privateKey: w.privateKey, phrase, seedPath: `${base}${i}` };
    W().push(e); created.push(e);
  }
  save();
  header("ACCOUNTS FROM ONE SEED (BIP-44)");
  table(["#", "LABEL", "PATH", "ADDRESS"],
    created.map((w, i) => [`#${W().length - n + i}`, w.label, w.seedPath, w.address]));
  console.log(c.ok(`One seed phrase backs up ALL these wallets.`));
}
async function cmdImport() {
  const mode = (await P({
    type: "select", name: "m", message: "Import method:",
    choices: [
      { title: "Seed phrase → many accounts (BIP-44)", value: "seed" },
      { title: "Seed phrase → single account", value: "phrase" },
      { title: "Private key", value: "pk" },
      { title: "Keystore file (.json)", value: "ks" },
    ],
  })).m;
  if (mode === "seed") return cmdCreateFromSeed([null]);
  let entry;
  if (mode === "phrase") {
    const phrase = (await P({ type: "text", name: "v", message: "Seed phrase:" })).v.trim().split(/\s+/).join(" ").toLowerCase();
    if (!Mnemonic.isValidMnemonic(phrase)) throw new Error("Invalid seed phrase.");
    const w = HDNodeWallet.fromPhrase(phrase);
    entry = { label: nextLabel(), address: w.address, privateKey: w.privateKey, phrase };
  } else if (mode === "pk") {
    let pk = (await P({ type: "password", name: "v", message: "Private key (0x… or bare):" })).v.trim();
    if (!pk.startsWith("0x")) pk = "0x" + pk;
    const w = new Wallet(pk);
    entry = { label: nextLabel(), address: w.address, privateKey: w.privateKey };
  } else {
    const file = (await P({ type: "text", name: "f", message: "Keystore file path:" })).v.trim().replace(/^["']|["']$/g, "");
    const json = fs.readFileSync(file, "utf8");
    const pw = (await P({ type: "password", name: "p", message: "Keystore password:" })).p;
    const w = await Wallet.fromEncryptedJson(json, pw);
    entry = { label: nextLabel(), address: w.address, privateKey: w.privateKey, phrase: w.mnemonic?.phrase };
  }
  if (W().some(w => w.address.toLowerCase() === entry.address.toLowerCase()))
    throw new Error("This wallet is already in the vault.");
  W().push(entry); save();
  console.log(c.ok(`\n✓ Imported as ${c.bold(`#${W().length - 1}`)} ${entry.label} — ${entry.address}`));
}
async function cmdWatch(args) {
  let [addr, label] = args;
  if (!addr || !label || !addr.startsWith("0x")) {
    const r = await P([
      { type: "text", name: "a", message: "Address to watch (0x…):" },
      { type: "text", name: "l", message: "Label (e.g. cold-storage):" },
    ]);
    addr = r.a; label = r.l;
  }
  getAddress(addr);
  if (W().some(w => w.address.toLowerCase() === addr.toLowerCase())) throw new Error("Address already in the vault.");
  W().push({ label: label || nextLabel(), address: addr, watchOnly: true }); save();
  console.log(c.ok(`\n✓ Watch-only wallet added: ${c.bold(`#${W().length - 1}`)} ${label} ${addr}`));
  console.log(c.dim("  Balances/statistics yes — signing no (no key held)."));
}
async function cmdLedger(args) {
  const i = parseInt(args[0], 10) || 0;
  const ledgerPath = `m/44'/60'/${i}'/0/0`;
  let Transport, AppEth;
  try {
    ({ default: Transport } = await import("@ledgerhq/hw-transport-node-hid"));
    ({ default: AppEth } = await import("@ledgerhq/hw-app-eth"));
  } catch {
    throw new Error("Ledger support not installed. Run:\n  npm i @ledgerhq/hw-transport-node-hid @ledgerhq/hw-app-eth\nThen connect your device and retry.");
  }
  console.log(c.dim(`Reading address ${ledgerPath} from the device (confirm on the Ledger if asked)…`));
  const transport = await Transport.create();
  let addr;
  try { addr = (await new AppEth(transport).getAddress(ledgerPath, false, true)).address; }
  finally { await transport.close(); }
  if (W().some(w => w.address.toLowerCase() === addr.toLowerCase())) throw new Error("Address already in the vault.");
  const label = args[1] || `ledger-${i}`;
  W().push({ label, address: addr, ledgerPath }); save();
  console.log(c.ok(`\n✓ Ledger wallet added: ${c.bold(`#${W().length - 1}`)} ${label} ${addr}`));
  console.log(c.dim("  Sends from this wallet will be signed on the device (experimental)."));
}
async function cmdList() {
  const nets = state.flags.all ? Object.keys(NET) : [netKey()];
  for (const k of nets) {
    const bals = await spin(`Fetching ${NET[k].label} balances…`, () => getBalances(k));
    header(`WALLETS — ${NET[k].label} (${NET[k].sym})`);
    table(["#", "LABEL", "ADDRESS", `BALANCE (${NET[k].sym})`, "KEY"],
      W().map((w, i) => [`#${i}`, w.label, w.address, bals[i] == null ? "?" : fmtAmt(bals[i]), keyMark(w)]),
      { align: [null, null, null, "r"] });
  }
  if (state.flags.all && BW().length) await cmdBtc(["list"]);
}
async function cmdBalance() {
  const nets = state.flags.all ? Object.keys(NET) : [netKey()];
  const prices = await maybePrices(nets);
  let grand = 0n, grandUsd = 0;
  for (const k of nets) {
    const bals = await spin(`Fetching ${NET[k].label} balances…`, () => getBalances(k));
    const total = bals.reduce((s, b) => (b ? s + b : s), 0n);
    grand += total;
    const v = netValue(total, k, prices);
    if (v != null) grandUsd += v;
    const rows = W().map((w, i) => {
      if (bals[i] == null || bals[i] === 0n) return null;
      const wv = netValue(bals[i], k, prices);
      return [`#${i}`, w.label, fmtAmt(bals[i]), wv != null ? `≈ ${usd(wv)}` : ""];
    }).filter(Boolean);
    header(`BALANCES — ${NET[k].label} (${NET[k].sym})`);
    if (rows.length) table(["#", "LABEL", "BALANCE", "VALUE"], rows, { align: [null, null, "r", "r"] });
    else console.log(c.dim("  (no funded wallet on this chain)"));
    console.log(`\n   ${c.bold("TOTAL")}  ${c.ok(fmtAmt(total))} ${NET[k].sym}${v != null ? c.dim(`   ≈ ${usd(v)} / ${eur(v * 0.92)}`) : ""}`);
  }
  if (state.flags.all) {
    if (BW().length) { grandUsd += await btcTotalLine(prices); }
    console.log(`\n${c.vio("Σ ALL CHAINS")}: ${c.bold(fmtAmt(grand))} + BTC${grandUsd ? c.dim(`   ≈ ${usd(grandUsd)}`) : ""}`);
  }
}
async function btcTotalLine(prices) {
  const bals = await spin("Fetching Bitcoin balances…", () => getBtcBalances());
  const total = bals.reduce((s, b) => (b ? s + b : s), 0n);
  const v = btcValue(total, prices);
  header(`BALANCES — ${BTC.label} (${BTC.sym})${settings().btcTest ? c.warn(" · testnet") : ""}`);
  table(["#", "LABEL", "ADDRESS", "BALANCE (BTC)", "VALUE"],
    BW().map((w, i) => [`#${i}`, w.label, w.address, bals[i] == null ? "?" : fmtBtc(bals[i]), bals[i] != null && v != null ? `≈ ${usd(btcValue(bals[i], prices))}` : ""]),
    { align: [null, null, null, "r", "r"] });
  console.log(`\n   ${c.bold("TOTAL")}  ${c.ok(fmtBtc(total))} ${BTC.sym}${v != null ? c.dim(`   ≈ ${usd(v)} / ${eur(v * 0.92)}`) : ""}`);
  return v || 0;
}
async function cmdDashboard() {
  const k = netKey();
  const bals = await spin("Fetching balances…", () => getBalances(k));
  const prices = await maybePrices([k]);
  const total = bals.reduce((s, b) => (b ? s + b : s), 0n);
  const funded = bals.filter(b => b && b > 0n).length;
  const v = netValue(total, k, prices);
  const h = cur().history;
  const fees = h.filter(x => x.net !== "xmr").reduce((s, x) => s + parseEther(x.fee), 0n);
  box("OVERVIEW", [
    `Network      ${NET[k].label} (${NET[k].sym})`,
    `Wallets      ${W().length} EVM · ${funded} funded · ${W().filter(w => w.watchOnly).length} watch-only`,
    `Total        ${fmtAmt(total)} ${NET[k].sym}${v != null ? `   ≈ ${usd(v)}` : ""}`,
    `History      ${h.length} tx sent · ${cur().chainTx.length} synced`,
  ]);
  const sorted = bals.map((b, i) => ({ b: b ?? 0n, i })).filter(x => x.b > 0n)
                     .sort((a, b) => b.b > a.b ? 1 : -1).slice(0, 5);
  if (sorted.length) {
    box("TOP WALLETS", sorted.map(({ b, i }) => {
      const pct = Number((b * 1000n) / total) / 10;
      const bar = "█".repeat(Math.max(1, Math.round(pct / 5))).padEnd(10, "░");
      return `#${String(i).padEnd(3)} ${W()[i].label.padEnd(12)} ${bar} ${fmtAmt(b).padStart(10)} ${NET[k].sym}  ${pct.toFixed(1)}%`;
    }));
  }
  if (BW().length) {
    const bb = await getBtcBalances();
    const bt = bb.reduce((s, b) => (b ? s + b : s), 0n);
    box(`BITCOIN${settings().btcTest ? " · TESTNET" : ""}`,
      BW().map((w, i) => `#${i} ${w.label.padEnd(10)} ${w.address}  ${bb[i] == null ? "?" : fmtBtc(bb[i]).padStart(12)} BTC`));
  }
  const all = mergedHistory().slice(0, 3);
  if (all.length)
    box("RECENT ACTIVITY", all.map(x =>
      `${x.t}   ${x.dir.padEnd(4)} ${short(x.from)} → ${short(x.to)}   ${x.amountFmt}`));
}
async function cmdSend(args) {
  if (!W().length) throw new Error("No wallet yet — create one first.");
  let [fromA, toA, amtA] = args;
  if (fromA == null || toA == null || amtA == null) {
    const r = await P([
      { type: "text", name: "f", message: `Send from which wallet? (0-${W().length - 1})` },
      { type: "text", name: "t", message: "Send to? (index, label, book entry or 0x…)" },
      { type: "text", name: "a", message: `Amount in ${state.flags.token ? state.flags.token : N().sym} (or "max"):` },
    ]);
    fromA = r.f; toA = r.t; amtA = r.a;
  }
  const from = findWallet(fromA);
  if (from < 0) throw new Error(`Source wallet not found: "${fromA}"`);
  requireKey(from);
  const to = resolveTo(toA);
  const prov = provider();
  let token = null;
  if (state.flags.token) {
    token = tokensOf(netKey()).find(t => t.sym.toLowerCase() === state.flags.token.toLowerCase());
    if (!token) throw new Error(`Unknown token "${state.flags.token}" on ${N().label}. See: ravenne tokens`);
  }
  let value, estFee;
  if (token) {
    const erc = new Contract(token.addr, ERC20_ABI, prov);
    const tkBal = await spin("Checking token balance…", () => erc.balanceOf(W()[from].address));
    value = /^(max|all)$/i.test(amtA) ? tkBal : parseUnits(String(amtA).replace(",", "."), token.dec);
    if (value <= 0n) throw new Error("Invalid amount.");
    if (tkBal < value) throw new Error(`Insufficient token balance: ${fmtUnits(tkBal, token.dec)} ${token.sym}`);
    const balNative = await prov.getBalance(W()[from].address);
    const per = await feePerTx(prov, 65000n);
    if (balNative < per) throw new Error(`Need ≈ ${fmtAmt(per)} ${N().sym} on this wallet to pay gas.`);
    estFee = per;
  } else {
    const bal = await spin("Checking balance…", () => prov.getBalance(W()[from].address));
    const per = await feePerTx(prov);
    if (/^(max|all)$/i.test(amtA)) {
      value = bal - per;
      if (value <= 0n) throw new Error(`Insufficient balance (${fmtAmt(bal)} ${N().sym}, fee ≈ ${fmtAmt(per)})`);
    } else {
      value = parseEther(String(amtA).replace(",", "."));
      if (value <= 0n) throw new Error("Invalid amount.");
      if (bal < value + per) throw new Error(`Insufficient balance: ${fmtAmt(bal)} ${N().sym} (fee ≈ ${fmtAmt(per)} extra)`);
    }
    estFee = per;
  }
  const unit = token ? token.sym : N().sym;
  const amtStr = token ? fmtUnits(value, token.dec) : fmtAmt(value);
  header(`SEND — ${N().label}${token ? ` · ERC-20 ${token.sym}` : ""}`);
  box("CONFIRM", [
    `From      #${from} ${W()[from].label}  ${short(W()[from].address)}`,
    `To        ${to.idx != null ? `#${to.idx} ${W()[to.idx].label}  ` : to.book ? `${to.book} (book)  ` : ""}${short(to.addr)}`,
    `Amount    ${amtStr} ${unit}   (est. fee ${fmtAmt(estFee)} ${N().sym})`,
  ]);
  if (!(await confirm("Confirm and send?"))) return console.log("Cancelled.");
  const { hash, fee, block } = await doSend(from, to.addr, value, netKey(), token);
  console.log(c.ok(`\n✓ Confirmed in block ${block} — real fee ${fmtAmt(fee)} ${N().sym}`));
  printTxLink(hash, netKey());
}
async function cmdTokens(args) {
  const k = netKey();
  if (args[0] === "add") {
    let [, sym, addr, dec] = args;
    if (!sym || !addr) throw new Error("Usage: tokens add <SYMBOL> <address> [decimals]");
    getAddress(addr);
    const prov = provider();
    const erc = new Contract(addr, ERC20_ABI, prov);
    if (dec == null) {
      const realSym = await spin("Reading token on-chain…", () => erc.symbol());
      dec = Number(await erc.decimals());
      if (realSym.toUpperCase() !== sym.toUpperCase())
        console.log(c.warn(`  on-chain symbol is "${realSym}" — keeping your label "${sym}"`));
    }
    const list = (settings().tokens[k] ??= [...DEFAULT_TOKENS[k] || []]);
    if (list.some(t => t.sym.toLowerCase() === sym.toLowerCase())) throw new Error(`${sym} already exists on ${NET[k].label}.`);
    list.push({ sym: sym.toUpperCase(), addr: getAddress(addr), dec: Number(dec) });
    save();
    return console.log(c.ok(`✓ ${sym} added on ${NET[k].label} (${dec} decimals)`));
  }
  if (args[0] === "remove") {
    const list = settings().tokens[k] || DEFAULT_TOKENS[k] || [];
    const i = list.findIndex(t => t.sym.toLowerCase() === String(args[1] || "").toLowerCase());
    if (i < 0) throw new Error(`Token not found: ${args[1]}`);
    settings().tokens[k] = list.filter((_, j) => j !== i); save();
    return console.log(c.ok(`✓ ${args[1]} removed from ${NET[k].label}`));
  }
  const list = tokensOf(k);
  if (!list.length) return console.log(c.dim(`No token configured on ${NET[k].label} — add one: tokens add <SYM> <address>`));
  const prov = provider();
  header(`ERC-20 TOKENS — ${NET[k].label}`);
  const rows = [];
  for (const t of list) {
    let total = null, holders = 0;
    try {
      const bals = await Promise.all(W().map(w => new Contract(t.addr, ERC20_ABI, prov).balanceOf(w.address).catch(() => null)));
      total = bals.reduce((s, b) => (b ? s + b : s), 0n);
      holders = bals.filter(b => b && b > 0n).length;
    } catch {}
    rows.push([t.sym, short(t.addr), t.dec, total == null ? "?" : fmtUnits(total, t.dec), `${holders}/${W().length}`]);
  }
  table(["SYMBOL", "CONTRACT", "DEC", "VAULT TOTAL", "HOLDERS"], rows, { align: [null, null, null, "r"] });
  console.log(c.dim("\n  send tokens: ravenne send 0 1 100 --token USDT · manage: tokens add/remove"));
}
async function cmdBook(args) {
  const book = settings().book;
  if (args[0] === "add") {
    let [, label, addr] = args;
    if (!label || !addr) throw new Error("Usage: book add <label> <0x-address>");
    getAddress(addr);
    if (book.some(b => b.label.toLowerCase() === label.toLowerCase())) throw new Error(`Label "${label}" already used.`);
    if (book.some(b => b.address.toLowerCase() === addr.toLowerCase())) throw new Error("Address already in the book.");
    book.push({ label, address: getAddress(addr) }); save();
    return console.log(c.ok(`✓ ${label} → ${addr}`));
  }
  if (args[0] === "remove") {
    const i = book.findIndex(b => b.label.toLowerCase() === String(args[1] || "").toLowerCase());
    if (i < 0) throw new Error(`Book entry not found: ${args[1]}`);
    book.splice(i, 1); save();
    return console.log(c.ok(`✓ removed "${args[1]}"`));
  }
  header("ADDRESS BOOK");
  table(["LABEL", "ADDRESS"], book.map(b => [b.label, b.address]));
  console.log(c.dim("\n  usable in send: ravenne send 0 <label> 1.5 · manage: book add/remove"));
}
async function cmdSplit(args) {
  if (!W().length) throw new Error("No wallet yet — create one first.");
  let [fromA, nA] = args;
  if (fromA == null) fromA = (await P({ type: "text", name: "v", message: `Split which wallet? (0-${W().length - 1})` })).v;
  if (nA == null) nA = (await P({ type: "number", name: "v", message: "Split into how many NEW wallets?", initial: 2, min: 2, max: 50 })).v;
  const from = findWallet(fromA);
  if (from < 0) throw new Error(`Wallet not found: "${fromA}"`);
  requireKey(from);
  const n = Math.min(Math.max(parseInt(nA, 10) || 2, 2), 50);
  const random = state.flags.random;
  const prov = provider();
  const bal = await spin("Checking balance…", () => prov.getBalance(W()[from].address));
  const per = await feePerTx(prov);
  const available = bal - per * BigInt(n);
  if (available <= 0n) throw new Error(`Balance too low for ${n} shares (${fmtAmt(bal)} ${N().sym}, needs > ${fmtAmt(per * BigInt(n))} for fees).`);
  const amounts = Array(n).fill(0n);
  if (random) {
    const w = Array.from({ length: n }, () => 500000 + Math.floor(Math.random() * 1000000));
    const sum = w.reduce((a, b) => a + b, 0);
    let used = 0n;
    for (let i = 0; i < n - 1; i++) { amounts[i] = available * BigInt(w[i]) / BigInt(sum); used += amounts[i]; }
    amounts[n - 1] = available - used;
  } else {
    amounts.fill(available / BigInt(n));
    amounts[n - 1] = available - (available / BigInt(n)) * BigInt(n - 1);
  }
  header(`SPLIT — ${N().label}${random ? c.warn(" · random amounts") : ""}`);
  console.log(`   Source : #${from} ${W()[from].label} ${short(W()[from].address)} — ${fmtAmt(bal)} ${N().sym}`);
  amounts.forEach((a, i) => console.log(`   share ${i + 1}: ${c.bold(`${fmtAmt(a)} ${N().sym}`)}`));
  console.log(c.dim(`   est. fee per send ≈ ${fmtAmt(per)}${state.flags.delay ? ` · ${state.flags.delay}s delay between sends` : ""}`));
  if (!(await confirm(`Create ${n} wallets and send shares?`))) return console.log("Cancelled.");
  const news = [];
  for (let i = 0; i < n; i++) { const e = newWalletEntry(state.flags.words); W().push(e); news.push(e); }
  save();
  let sent = 0n;
  for (let i = 0; i < n; i++) {
    const value = i === n - 1
      ? (await new JsonRpcProvider(rpcUrl(netKey())).getBalance(W()[from].address)) - per
      : amounts[i];
    if (value <= 0n) { console.log(c.warn(`  ⚠ share ${i + 1} skipped (dust)`)); continue; }
    await betweenSends(i, n);
    console.log(c.dim(`\n→ Send ${i + 1}/${n} → #${W().indexOf(news[i])} ${news[i].label}`));
    const { hash, fee, block } = await doSend(from, news[i].address, value, netKey());
    sent += value;
    console.log(c.ok(`   ✓ ${fmtAmt(value)} ${N().sym} (block ${block}, fee ${fmtAmt(fee)})`));
    printTxLink(hash, netKey());
  }
  console.log(c.ok(`\n✅ Split done: ${fmtAmt(sent)} ${N().sym} spread across ${n} new wallets.`));
}
async function cmdConsolidate(args) {
  if (W().length < 2) throw new Error("Consolidation needs at least 2 wallets.");
  let targetA = args[0];
  if (targetA == null) targetA = (await P({ type: "text", name: "v", message: `Gather everything into which wallet? (0-${W().length - 1})` })).v;
  const target = findWallet(targetA);
  if (target < 0) throw new Error(`Target wallet not found: "${targetA}"`);
  const prov = provider();
  const bals = await spin("Scanning wallets…", () => getBalances(netKey(), prov));
  const per = await feePerTx(prov);
  const plan = W().map((w, i) => ({ i, w, bal: bals[i] ?? 0n, get: (bals[i] ?? 0n) > per ? bals[i] - per : 0n }))
               .filter(x => x.i !== target && x.get > 0n && x.w.privateKey);
  if (!plan.length) throw new Error("No spendable wallet (with a key) can cover the transfer fee.");
  const total = plan.reduce((s, x) => s + x.get, 0n);
  header(`CONSOLIDATE — ${N().label}`);
  plan.forEach(x => console.log(`   #${x.i} ${c.cyan(x.w.label.padEnd(12))} ${short(x.w.address)}  ${fmtAmt(x.bal).padStart(10)} → ${c.ok(fmtAmt(x.get))} ${N().sym}`));
  console.log(`   ${c.bold("─".repeat(52))}`);
  console.log(`   Target #${target} ${W()[target].label} ${short(W()[target].address)} will receive ≈ ${c.bold(`${fmtAmt(total)} ${N().sym}`)}`);
  console.log(c.dim(`   ${plan.length} sends · fee ≈ ${fmtAmt(per)} each${state.flags.delay ? ` · ${state.flags.delay}s delay between sends` : ""}`));
  if (!(await confirm("Start consolidation?"))) return console.log("Cancelled.");
  let got = 0n, done = 0;
  for (const x of plan) {
    const bal = await prov.getBalance(x.w.address);
    const value = bal - per;
    if (value <= 0n) { console.log(c.warn(`\n⚠ #${x.i} empty, skipped.`)); continue; }
    await betweenSends(done, plan.length);
    console.log(c.dim(`\n→ #${x.i} ${x.w.label} → #${target}…`));
    const { hash, fee, block } = await doSend(x.i, W()[target].address, value, netKey());
    got += value; done++;
    console.log(c.ok(`   ✓ ${fmtAmt(value)} ${N().sym} (block ${block}, fee ${fmtAmt(fee)})`));
    printTxLink(hash, netKey());
  }
  console.log(c.ok(`\n✅ Consolidation done: ≈ ${fmtAmt(got)} ${N().sym} gathered on #${target} ${W()[target].label}.`));
}
async function cmdStats() {
  const nets = state.flags.all ? Object.keys(NET) : [netKey()];
  const prices = await maybePrices(nets);
  header("STATISTICS");
  console.log(`   ${state.flags.all ? "All chains" : `Chain: ${N().label}`} · ${W().length} EVM wallet${W().length === 1 ? "" : "s"}${BW().length ? c.dim(` + ${BW().length} BTC`) : ""}`);
  let totalUsd = 0;
  for (const k of nets) {
    const bals = (await spin(`Fetching ${NET[k].label}…`, () => getBalances(k))).map(b => b ?? 0n);
    const total = bals.reduce((a, b) => a + b, 0n);
    const active = bals.filter(b => b > 0n).length;
    const v = netValue(total, k, prices);
    if (v != null) totalUsd += v;
    if (state.flags.all)
      console.log(`\n   ${c.bold(NET[k].label)}: ${fmtAmt(total)} ${NET[k].sym} — ${active}/${W().length} funded${v != null ? c.dim(`  ≈ ${usd(v)}`) : ""}`);
    const sorted = bals.map((b, i) => ({ b, i })).filter(x => x.b > 0n)
                       .sort((a, b) => b.b > a.b ? 1 : -1).slice(0, 8);
    if (total > 0n) {
      console.log(c.dim(`\n   Distribution on ${NET[k].label}:`));
      for (const { b, i } of sorted) {
        const pct = Number((b * 10000n) / total) / 100;
        const bar = "█".repeat(Math.max(1, Math.round(pct / 4))).padEnd(14, "░");
        console.log(`      #${String(i).padEnd(3)} ${c.cyan(W()[i].label.padEnd(12))} ${bar} ${fmtAmt(b).padStart(10)} ${NET[k].sym}  ${pct.toFixed(1)}%`);
      }
      const empty = W().length - active;
      if (empty > 0) console.log(c.dim(`      … + ${empty} empty wallet${empty > 1 ? "s" : ""}`));
    }
    if (!state.flags.all && total > 0n) {
      const nums = bals.map(b => Number(formatEther(b))).sort((a, b) => a - b);
      const med = nums.length % 2 ? nums[(nums.length - 1) / 2] : (nums[nums.length / 2 - 1] + nums[nums.length / 2]) / 2;
      console.log(`\n   ${c.bold("Wealth")} : max ${fmtAmt(sorted[0].b)} · avg ${fmtAmt(total / BigInt(W().length))} · median ${med.toFixed(4)} ${NET[k].sym}`);
      if (v != null) console.log(`   ${c.bold("Value")}  : ${c.ok(usd(v))} / ${c.ok(eur(v * 0.92))} ${c.dim("(indicative)")}`);
    }
  }
  if (BW().length) {
    const bb = (await spin("Fetching Bitcoin…", () => getBtcBalances())).map(b => b ?? 0n);
    const bt = bb.reduce((a, b) => a + b, 0n);
    const bv = btcValue(bt, prices);
    if (bv != null) totalUsd += bv;
    console.log(`\n   ${c.bold("Bitcoin")} : ${fmtBtc(bt)} BTC — ${bb.filter(b => b > 0n).length}/${BW().length} funded${bv != null ? c.dim(`  ≈ ${usd(bv)}`) : ""}${settings().btcTest ? c.warn(" (testnet)") : ""}`);
  }
  if (state.flags.all && totalUsd) console.log(`\n   ${c.bold("Total value")}: ${c.ok(usd(totalUsd))} ${c.dim("(indicative)")}`);
  const h = cur().history;
  const native = h.filter(x => !x.token && x.net !== "xmr"), tokens = h.filter(x => x.token);
  const xmrTx = h.filter(x => x.net === "xmr");
  if (native.length) {
    const byNet = {};
    for (const x of native) { byNet[x.net] ??= { vol: 0n, fees: 0n }; byNet[x.net].vol += parseEther(x.amount); byNet[x.net].fees += parseEther(x.fee); }
    const parts = Object.entries(byNet).map(([k, v]) => `${fmtAmt(v.vol)} ${k === "btc" ? "BTC" : NET[k]?.sym || ""} (fees ${fmtAmt(v.fees)})`);
    console.log(`\n   ${c.bold("History")}: ${native.length} tx · volume ${parts.join(" · ")}`);
  }
  if (tokens.length) {
    const byTok = {};
    tokens.forEach(x => byTok[x.token] = (byTok[x.token] || 0) + 1);
    console.log(`   ${c.bold("Tokens")} : ${Object.entries(byTok).map(([s, n]) => `${n}× ${s}`).join(", ")}`);
  }
  if (xmrTx.length) console.log(`   ${c.bold("Monero")} : ${xmrTx.length} tx · volume ${xmrTx.reduce((s2, x) => s2 + Number(x.amount), 0).toFixed(4)} XMR`);
  if (cur().chainTx.length) console.log(`   ${c.bold("Synced")}: ${cur().chainTx.length} chain transactions (ravenne sync)`);
  if (!h.length && !cur().chainTx.length) console.log(c.dim("\n   No transaction recorded yet."));
}
function mergedHistory() {
  const ours = ourAddressSet();
  const btcOurs = new Set(BW().map(w => w.address));
  const xmrOurs = new Set(XW().map(w => w.address));
  const allOurs = a => ours.has((a || "").toLowerCase()) || btcOurs.has(a) || xmrOurs.has(a);
  const dirOf = x => allOurs(x.from) && allOurs(x.to) ? "SELF" : allOurs(x.from) ? "OUT" : allOurs(x.to) ? "IN" : "—";
  const rows = [
    ...cur().history.map(x => ({ ...x, src: "ravenne", iso: x.t })),
    ...cur().chainTx.map(x => ({ ...x, src: "chain", iso: x.t })),
  ].sort((a, b) => new Date(b.iso) - new Date(a.iso));
  return rows.map(x => ({ ...x, t: dt(x.iso), dir: dirOf(x),
    amountFmt: `${(+x.amount).toFixed(8).replace(/0+$/, "").replace(/\.$/, "")} ${x.token || (x.net === "btc" ? "BTC" : x.net === "xmr" ? "XMR" : NET[x.net]?.sym || "")}` }));
}
const chainLabel = net => net === "btc" ? BTC.label : net === "xmr" ? XMR.label : NET[net]?.label || net;
async function cmdHistory() {
  const rows = mergedHistory();
  if (!rows.length) return console.log(c.dim("No transaction recorded yet. Try: ravenne sync"));
  header(`TRANSACTION HISTORY ${c.dim(`(${cur().history.length} sent · ${cur().chainTx.length} synced)`)}`);
  table(["WHEN", "DIR", "CHAIN", "FROM", "TO", "AMOUNT", "FEE", "SRC"],
    rows.slice(0, 25).map(x => [x.t, x.dir, chainLabel(x.net), short(x.from), short(x.to), x.amountFmt,
                                (+x.fee).toFixed(6), x.src]));
  if (rows.length > 25) console.log(c.dim(`  … ${rows.length - 25} more (full list: ravenne export-csv)`));
}
export function mergeChainTx(payload, items, netK) {
  const seen = new Set(payload.chainTx.map(x => x.hash));
  let added = 0;
  for (const it of items) {
    if (!it?.hash || seen.has(it.hash)) continue;
    seen.add(it.hash);
    payload.chainTx.push({
      t: it.timestamp || new Date().toISOString(), net: netK,
      from: it.from?.hash || it.from || "", to: it.to?.hash || it.to || "(contract creation)",
      amount: formatEther(BigInt(it.value || 0)),
      fee: formatEther(BigInt(it.fee?.value || (it.gas_price && it.gas_used ? BigInt(it.gas_price) * BigInt(it.gas_used) : 0))),
      hash: it.hash,
    });
    added++;
  }
  payload.chainTx.sort((a, b) => new Date(b.t) - new Date(a.t));
  payload.chainTx = payload.chainTx.slice(0, 1000);
  return added;
}
async function cmdSync() {
  if (netKey() === "local") throw new Error("No explorer for the local chain.");
  const api = explorerApi(netKey());
  let total = 0;
  for (const w of W()) {
    const items = await spin(`Syncing ${w.label}…`, async () => {
      const r = await fetch(`${api}/api/v2/addresses/${w.address}/transactions?filter=to%20%7C%20from`,
                            { signal: AbortSignal.timeout(12000) });
      if (!r.ok) throw new Error(`explorer answered ${r.status}`);
      return (await r.json()).items || [];
    }).catch(e => { console.log(c.warn(`  ⚠ ${w.label}: ${e.message}`)); return null; });
    if (!items) continue;
    total += mergeChainTx(state.payload, items, netKey());
  }
  save();
  console.log(c.ok(`\n✓ Sync done: ${total} new transaction${total === 1 ? "" : "s"} fetched.`));
  console.log(c.dim("  See them with: ravenne history · export with: ravenne export-csv"));
}
const csvCell = v => { const s = String(v ?? ""); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
async function cmdCsv(args) {
  const rows = mergedHistory();
  if (!rows.length) return console.log(c.dim("Nothing to export yet."));
  const file = args[0] || path.join(process.cwd(), `ravenne-history-${new Date().toISOString().slice(0, 10)}.csv`);
  const lines = rows.map(x => [
    x.t, chainLabel(x.net), x.dir, x.from, x.to,
    +x.amount, x.token || (x.net === "btc" ? "BTC" : x.net === "xmr" ? "XMR" : NET[x.net]?.sym || ""), +x.fee, x.src, x.hash,
  ].map(csvCell).join(","));
  fs.writeFileSync(file, ["date,chain,direction,from,to,amount,symbol,fee,tx_source,hash", ...lines].join("\r\n") + "\r\n");
  console.log(c.ok(`✓ ${rows.length} transactions exported to ${file}`));
}
async function cmdQr(args) {
  let a = args[0];
  if (a == null) a = (await P({ type: "text", name: "v", message: `Which address? (0-${W().length - 1}, btc:<n°>, label, book or 0x…)` })).v;
  let addr, label;
  if (String(a).trim().startsWith("0x")) { getAddress(a); addr = a; label = ""; }
  else if (String(a).startsWith("btc:")) {
    const i = findBtcWallet(String(a).slice(4));
    if (i < 0) throw new Error(`BTC wallet not found: ${a}`);
    addr = BW()[i].address; label = `btc#${i} ${BW()[i].label}`;
  } else {
    const i = findWallet(a);
    if (i >= 0) { addr = W()[i].address; label = `#${i} ${W()[i].label}`; }
    else {
      const b = settings().book.find(x => x.label.toLowerCase() === String(a).toLowerCase());
      if (!b) throw new Error(`Not found: "${a}"`);
      addr = b.address; label = `${b.label} (book)`;
    }
  }
  header("ADDRESS QR");
  console.log(`${c.bold(label || "Address")}  ${addr}\n`);
  qrcode.generate(addr, { small: true });
}
async function cmdPhrase(args) {
  let a = args[0];
  if (a == null) a = (await P({ type: "text", name: "v", message: `Which wallet? (0-${W().length - 1} or btc:<n°>)` })).v;
  if (String(a).startsWith("btc:")) return btcPhrase(findBtcWallet(String(a).slice(4)));
  const i = findWallet(a);
  if (i < 0) throw new Error(`Wallet not found: "${a}"`);
  const w = W()[i];
  if (!w.phrase) return console.log(c.warn(`#${i} has no stored seed phrase (imported by key, watch-only or Ledger).`));
  console.log(c.warn(`\n⚠  Seed phrase of #${i} ${w.label}${w.seedPath ? ` (${w.seedPath})` : ""} — never show this to anyone:`));
  if (!(await confirm("Reveal anyway?"))) return console.log("Cancelled.");
  console.log(c.bold(`\n  ${w.phrase}\n`));
  if (!state.autoYes) {
    await P({ type: "text", name: "_", message: c.dim("Press Enter to clear the screen…") });
    console.clear();
  }
}
async function cmdExport(args) {
  let a = args[0];
  if (a == null) a = (await P({ type: "text", name: "v", message: `Export which wallet? (0-${W().length - 1})` })).v;
  const i = findWallet(a);
  if (i < 0) throw new Error(`Wallet not found: "${a}"`);
  if (!W()[i].privateKey) throw new Error(`#${i} holds no key (watch-only/Ledger) — nothing to export.`);
  let pw = process.env.RAVENNE_KEYPASS || (await P({ type: "password", name: "p", message: "Keystore file password (8 chars min.):" })).p;
  if (!pw || pw.length < 8) throw new Error("Password too short (8 min.).");
  const json = await spin("Encrypting keystore…", () => new Wallet(W()[i].privateKey).encrypt(pw));
  const file = args[1] || path.join(process.cwd(), `ravenne-keystore-${W()[i].address.slice(0, 10)}.json`);
  fs.writeFileSync(file, json);
  console.log(c.ok(`✓ Keystore written: ${file}`));
  console.log(c.dim("  (importable back here, or in MetaMask via 'Import wallet')"));
}
async function cmdRename(args) {
  let [a, label] = args;
  if (a == null || !label) {
    const r = await P([
      { type: "text", name: "a", message: `Rename which wallet? (0-${W().length - 1})` },
      { type: "text", name: "l", message: "New label:" },
    ]);
    a = r.a; label = r.l;
  }
  const i = findWallet(a);
  if (i < 0) throw new Error(`Wallet not found: "${a}"`);
  if (!label.trim()) throw new Error("Empty label.");
  const old = W()[i].label;
  W()[i].label = label.trim(); save();
  console.log(c.ok(`✓ #${i}: ${old} → ${c.cyan(label.trim())}`));
}
async function cmdRemove(args) {
  let a = args[0];
  if (a == null) a = (await P({ type: "text", name: "v", message: `Remove which wallet from the vault? (0-${W().length - 1} or btc:<n°>)` })).v;
  if (String(a).startsWith("btc:")) {
    const i = findBtcWallet(String(a).slice(4));
    if (i < 0) throw new Error(`BTC wallet not found: ${a}`);
    if (!(await confirm(`Remove BTC wallet #${i} ${BW()[i].label}?`))) return console.log("Cancelled.");
    BW().splice(i, 1); save();
    return console.log(c.ok(`✓ Removed from vault.`));
  }
  const i = findWallet(a);
  if (i < 0) throw new Error(`Wallet not found: "${a}"`);
  const w = W()[i];
  console.log(c.warn(`\n⚠  You are about to remove #${i} ${w.label} ${w.address} from the vault.`));
  if (w.privateKey)
    console.log(c.err("   Without its seed phrase, private key or a keystore elsewhere, its funds are UNRECOVERABLE."));
  else console.log(c.dim("   (watch-only/Ledger entry — the key is not stored here, nothing to lose)"));
  if (w.phrase && (await confirm("Show the seed phrase one last time before removing?")))
    console.log(c.bold(`\n   ${w.phrase}\n`));
  if (!(await confirm(`Really remove #${i} from the vault?`))) return console.log("Cancelled.");
  W().splice(i, 1); save();
  console.log(c.ok(`✓ Removed from vault (indexes of the following wallets are shifted).`));
}
async function cmdNetwork(args) {
  if (args[0]) {
    const k = NET_ALIASES[String(args[0]).toLowerCase()];
    if (!k) throw new Error(`Unknown network: ${args[0]} (local, eth, poly, bsc, arb, base, op)`);
    cur().network = k; save();
    console.log(c.ok(`✓ Active chain: ${NET[k].label} (${NET[k].sym})`));
  } else {
    console.log(`Active chain: ${c.bold(N().label)} (${N().sym}) — switch: ravenne network eth|poly|bsc|arb|base|op|local`);
  }
}
async function cmdRpc(args) {
  const s = settings();
  if (args.length === 0) {
    header("RPC ENDPOINTS");
    table(["CHAIN", "ENDPOINT", "SOURCE"],
      Object.keys(NET).map(k => [NET[k].label, s.rpc[k] || NET[k].rpc, s.rpc[k] ? "custom" : "default"]));
    console.log(c.dim("\n  set: ravenne rpc eth http://your-node:8545   ·   reset: ravenne rpc eth reset"));
  } else {
    const k = NET_ALIASES[String(args[0]).toLowerCase()];
    if (!k) throw new Error(`Unknown network: ${args[0]}`);
    if (args[1] === "reset") { delete s.rpc[k]; save(); return console.log(c.ok(`✓ ${NET[k].label}: back to default RPC`)); }
    if (!args[1] || !/^https?:\/\//.test(args[1])) throw new Error("Provide an http(s) URL, or 'reset'.");
    s.rpc[k] = args[1]; save();
    console.log(c.ok(`✓ ${NET[k].label} → ${args[1]}`));
  }
}
async function cmdSettings(args) {
  const s = settings();
  if (!args.length) {
    box("SETTINGS", [
      `vpn check   ${s.vpnCheck ? c.ok("ON  (no connection without an active VPN)") : "OFF"}`,
      `prices      ${s.prices ? "ON  (fiat values via CoinGecko)" : "OFF (no price queries — better privacy)"}`,
      `autolock    ${s.autolockMin} min of inactivity in the menu (0 = off)`,
      `btc network ${s.btcTest ? "testnet" : "mainnet"}`,
      `custom rpc  ${Object.keys(s.rpc).length} chain(s) · address book ${s.book.length} entries`,
    ]);
    console.log(c.dim("\n  ravenne settings vpncheck on|off · settings prices on|off · settings autolock <minutes>"));
    return;
  }
  if (args[0] === "vpncheck") {
    s.vpnCheck = args[1] !== "off"; save();
    return console.log(c.ok(`✓ VPN requirement ${s.vpnCheck ? "enabled" : "DISABLED (not recommended)"}`));
  }
  if (args[0] === "prices") {
    s.prices = args[1] !== "off"; save();
    return console.log(c.ok(`✓ Price lookups ${s.prices ? "enabled" : "disabled"}`));
  }
  if (args[0] === "autolock") {
    const m = parseInt(args[1], 10);
    if (!Number.isInteger(m) || m < 0 || m > 240) throw new Error("Minutes: 0 (off) to 240.");
    s.autolockMin = m; save();
    return console.log(c.ok(`✓ Auto-lock after ${m === 0 ? "disabled" : `${m} min`}`));
  }
  throw new Error("Unknown setting. Try: settings prices off");
}
async function cmdPrice() {
  const prices = await maybePrices(Object.keys(NET).filter(k => NET[k].cg));
  if (!prices) return console.log(c.err("Prices unavailable (offline or disabled in settings)."));
  header("LIVE PRICES");
  const rows = [ [BTC.label, BTC.sym, prices["bitcoin"]?.usd, prices["bitcoin"]?.eur],
    [XMR.label, XMR.sym, prices["monero"]?.usd, prices["monero"]?.eur],
    ...Object.keys(NET).filter(k => NET[k].cg)
      .map(k => [NET[k].label, NET[k].sym, prices[NET[k].cg]?.usd, prices[NET[k].cg]?.eur]) ]
    .filter(r => r[2] != null)
    .map(r => [r[0], r[1], usd(r[2]), eur(r[3])]);
  table(["CHAIN", "COIN", "USD", "EUR"], rows, { align: [null, null, "r", "r"] });
  console.log(c.dim("\n   indicative rates — crypto is volatile"));
}
async function cmdChangePass() {
  console.log(c.vio("\n🔑 Change master password (re-encrypts the vault)."));
  let old = process.env.RAVENNE_PASS || state.pass || (await P({ type: "password", name: "v", message: "Current master password:" })).v;
  if (!gateVerify(old)) throw new Error("Current password is wrong.");
  const r = await P([
    { type: "password", name: "a", message: "New master password (8 chars min.):" },
    { type: "password", name: "b", message: "Confirm new password:" },
  ]);
  if (!r.a || r.a.length < 8) throw new Error("New password too short.");
  if (r.a !== r.b) throw new Error("Passwords do not match.");
  if (r.a === old) throw new Error("New password must differ from the current one.");
  if (fs.existsSync(VAULT_FILE)) {
    decryptVault(old);
    encryptVault(state.payload, r.a);
  }
  writeGate(r.a); state.pass = r.a;
  console.log(c.ok("✓ Master password changed (gate + vault re-encrypted)."));
}
async function cmdWipe() {
  console.log(c.err("\n☠  WIPE destroys the vault file permanently (wallets, labels, history)."));
  console.log(c.warn("   Your funds survive on-chain — recoverable ONLY with each wallet's seed phrase / keystore."));
  if (!state.autoYes) {
    const { v } = await P({ type: "text", name: "v", message: `Type ${c.bold("ERASE")} to confirm:` });
    if (v !== "ERASE") return console.log("Cancelled.");
  } else if (!(await confirm("Really wipe the vault now?"))) return console.log("Cancelled.");
  if (fs.existsSync(VAULT_FILE)) {
    const size = fs.statSync(VAULT_FILE).size;
    const fh = fs.openSync(VAULT_FILE, "r+");
    for (let i = 0; i < 3; i++) { fs.writeSync(fh, crypto.randomBytes(size), 0, size, 0); fs.fsyncSync(fh); }
    fs.closeSync(fh);
    fs.unlinkSync(VAULT_FILE);
  }
  state.payload = null;
  console.log(c.ok("✓ Vault wiped (3× random overwrite + delete)."));
  console.log(c.dim("  The password gate (access.ravenne.json) is kept — relaunch to start a fresh vault."));
}

/* ─────────── Bitcoin commands ─────────── */
async function cmdBtc(args) {
  const sub = args[0] || "list";
  if (sub === "create") {
    let n = parseInt(args[1], 10);
    if (!Number.isInteger(n) || n < 1)
      n = (await P({ type: "number", name: "v", message: "How many Bitcoin wallets?", initial: 1, min: 1, max: 50 })).v;
    const phrase = generateMnemonic(256, wordlist);   // 24 words — one phrase backs up all derived BTC wallets
    const created = [];
    const start = BW().filter(w => !w.watchOnly).length;
    for (let i = start; i < start + n; i++) { const e = btcEntry(phrase, i); BW().push(e); created.push(e); }
    save();
    header("NEW BITCOIN WALLETS (BIP84 native segwit)");
    console.log(c.ok(`✓ ${n} wallet${n > 1 ? "s" : ""} created${settings().btcTest ? c.warn(" · TESTNET") : ""}`));
    table(["#", "LABEL", "PATH", "ADDRESS"], created.map((w, i) => [`#${BW().length - n + i}`, w.label, w.path, w.address]));
    console.log(c.warn(`\n⚠  Backup this phrase once — it owns ALL these BTC wallets:`));
    if (!state.autoYes) {
      if (await confirm("Reveal the seed phrase now?")) console.log(c.bold(`\n  ${phrase}\n`));
      await P({ type: "text", name: "_", message: c.dim("Press Enter to clear the screen…") });
      console.clear();
    } else console.log(c.dim("  (use: ravenne btc phrase btc:0)"));
    return;
  }
  if (sub === "watch") {
    let addr = args[1], label = args[2];
    if (!addr || !label) {
      const r = await P([
        { type: "text", name: "a", message: "Bitcoin address to watch (bc1… / tb1… / 1…):" },
        { type: "text", name: "l", message: "Label:" },
      ]);
      addr = r.a; label = r.l;
    }
    if (!/^(bc1|tb1|1|3|m|n)[a-zA-Z0-9]{25,}$/.test(addr)) throw new Error("This doesn't look like a Bitcoin address.");
    if (BW().some(w => w.address === addr)) throw new Error("Address already in the vault.");
    BW().push({ label: label || nextBtcLabel(), address: addr, watchOnly: true }); save();
    return console.log(c.ok(`✓ Watch-only BTC wallet added: ${addr}`));
  }
  if (sub === "network") {
    if (args[1] === "test" || args[1] === "testnet") { settings().btcTest = true; save(); return console.log(c.warn("✓ Bitcoin → TESTNET")); }
    if (args[1] === "main" || args[1] === "mainnet") { settings().btcTest = false; save(); return console.log(c.ok("✓ Bitcoin → MAINNET")); }
    return console.log(`Bitcoin network: ${settings().btcTest ? "testnet" : "mainnet"} — switch: ravenne btc network test|main`);
  }
  if (sub === "phrase") return btcPhrase(findBtcWallet(args[1] ?? ""));
  if (sub === "qr") {
    const i = findBtcWallet(args[1] ?? "");
    if (i < 0) throw new Error(`BTC wallet not found (btc:0-${BW().length - 1})`);
    header("BTC ADDRESS QR");
    console.log(`${c.bold(`btc#${i} ${BW()[i].label}`)}  ${BW()[i].address}\n`);
    return qrcode.generate(BW()[i].address, { small: true });
  }
  if (sub === "balance") return void await btcTotalLine(await maybePrices([netKey()]));
  if (sub === "list") {
    const bals = await spin("Fetching Bitcoin balances…", () => getBtcBalances());
    header(`BITCOIN WALLETS${settings().btcTest ? c.warn(" · TESTNET") : ""} (BIP84)`);
    table(["#", "LABEL", "ADDRESS", "BALANCE (BTC)", "KEY"],
      BW().map((w, i) => [`#${i}`, w.label, w.address, bals[i] == null ? "?" : fmtBtc(bals[i]), w.watchOnly ? c.cyan("○ watch") : c.ok("● key")]),
      { align: [null, null, null, "r"] });
    return;
  }
  if (sub === "send") {
    if (!BW().length) throw new Error("No Bitcoin wallet — create one first (ravenne btc create).");
    let [fromA, toA, amtA] = [args[1], args[2], args[3]];
    if (fromA == null || toA == null || amtA == null) {
      const r = await P([
        { type: "text", name: "f", message: `Send from which BTC wallet? (btc:0-${BW().length - 1})` },
        { type: "text", name: "t", message: "To? (bc1… address or book label)" },
        { type: "text", name: "a", message: `Amount in BTC (or "max"):` },
      ]);
      fromA = r.f; toA = r.t; amtA = r.a;
    }
    const from = findBtcWallet(String(fromA).startsWith("btc:") ? String(fromA).slice(4) : fromA);
    if (from < 0) throw new Error(`BTC wallet not found: "${fromA}"`);
    const src = BW()[from];
    if (src.watchOnly) throw new Error(`${src.label} is watch-only — it cannot sign.`);
    let toAddr = String(toA).trim();
    const b = settings().book.find(x => x.label.toLowerCase() === toAddr.toLowerCase());
    if (b) toAddr = b.address;
    if (!/^(bc1|tb1|1|3|m|n)[a-zA-Z0-9]{25,}$/.test(toAddr)) throw new Error("Invalid Bitcoin recipient address.");
    const utxos = await spin("Fetching UTXOs…", () => btcFetch(`/address/${src.address}/utxo`));
    if (!Array.isArray(utxos) || !utxos.length) throw new Error("No UTXO to spend (empty wallet).");
    const rates = await spin("Fetching fees…", () => btcFetch("/fee-estimates"));
    const satPerVb = Math.max(2, Math.ceil(Number(rates["6"] || rates["3"] || rates["1"] || 12)));
    const totalSat = utxos.reduce((s, u) => s + BigInt(u.value), 0n);
    const maxFee = BigInt((11 + 68 * utxos.length + 62) * satPerVb);
    let amountSat;
    if (/^(max|all)$/i.test(amtA)) amountSat = totalSat - maxFee;
    else {
      const f = Number(String(amtA).replace(",", "."));
      if (!(f > 0)) throw new Error("Invalid amount.");
      amountSat = BigInt(Math.round(f * 1e8));
    }
    if (amountSat <= 546n) throw new Error(`Amount too small after fees (available: ${fmtBtc(totalSat - maxFee)} BTC).`);
    const estFee = BigInt((11 + 68 * Math.min(utxos.length, Math.ceil(Number(amountSat) / 1e8) + 1) + 62) * satPerVb);
    header(`SEND BITCOIN${settings().btcTest ? c.warn(" · TESTNET") : ""}`);
    box("CONFIRM", [
      `From      btc#${from} ${src.label}  ${short(src.address)}`,
      `To        ${short(toAddr)}`,
      `Amount    ${fmtBtc(amountSat)} BTC   (est. fee ≈ ${fmtBtc(estFee)} @ ${satPerVb} sat/vB)`,
      `UTXOs     ${utxos.length} available — change returns to the sender address`,
    ]);
    if (!(await confirm("Confirm and broadcast?"))) return console.log("Cancelled.");
    const { hex, fee, inputs } = await spin("Building & signing transaction…", () => buildBtcTx(src, utxos, toAddr, amountSat, satPerVb));
    const txid = await spin("Broadcasting…", () => btcFetch("/tx", hex));
    cur().history.push({ t: new Date().toISOString(), net: "btc", from: src.address, to: toAddr,
                                 amount: fmtBtc(amountSat), fee: fmtBtc(fee), hash: txid });
    save();
    console.log(c.ok(`\n✓ Broadcast! txid ${txid} (${inputs} input${inputs > 1 ? "s" : ""}, fee ${fmtBtc(fee)} BTC)`));
    console.log(c.dim(`   ↗ ${BTC.ex}/tx/${txid}`));
    return;
  }
  if (sub === "sync") {
    let total = 0;
    for (const w of BW()) {
      const txs = await spin(`Syncing ${w.label}…`, () => btcFetch(`/address/${w.address}/txs`)).catch(e => {
        console.log(c.warn(`  ⚠ ${w.label}: ${e.message}`)); return null;
      });
      if (!txs) continue;
      // map esplora shape → the merge format
      const items = txs.slice(0, 50).map(tx => {
        const isIn = tx.vin.some(v => v.prevout?.scriptpubkey_address === w.address);
        return { hash: tx.txid, timestamp: new Date((tx.status?.block_time || 0) * 1000).toISOString(),
                 from: isIn ? (tx.vin[0]?.prevout?.scriptpubkey_address || "") : w.address,
                 to: isIn ? w.address : (tx.vout[0]?.scriptpubkey_address || ""),
                 value: String(isIn ? tx.vout.filter(o => o.scriptpubkey_address === w.address).reduce((s, o) => s + o.value, 0)
                                    : tx.vin.filter(v => v.prevout?.scriptpubkey_address === w.address).reduce((s, v) => s + (v.prevout?.value || 0), 0)),
                 fee: { value: String(tx.fee || 0) } };
      }).filter(x => x.value !== "0");
      total += mergeChainTx(state.payload, items, "btc");
    }
    save();
    return console.log(c.ok(`✓ Bitcoin sync done: ${total} new transaction${total === 1 ? "" : "s"}.`));
  }
  throw new Error(`Unknown 'btc' sub-command: ${sub}. Try: btc create | list | balance | send | watch | qr | phrase | sync | network`);
}
async function btcPhrase(i) {
  if (i < 0) throw new Error(`BTC wallet not found (btc:0-${BW().length - 1})`);
  const w = BW()[i];
  if (!w.phrase) return console.log(c.warn(`btc#${i} is watch-only — no phrase stored.`));
  console.log(c.warn(`\n⚠  Seed phrase of btc#${i} ${w.label} (${w.path}) — never show this to anyone:`));
  if (!(await confirm("Reveal anyway?"))) return console.log("Cancelled.");
  console.log(c.bold(`\n  ${w.phrase}\n`));
  if (!state.autoYes) {
    await P({ type: "text", name: "_", message: c.dim("Press Enter to clear the screen…") });
    console.clear();
  }
}

/* ─────────── Offline signing (EVM) ─────────── */
async function buildTxPlan(fromIdx, toAddr, amountStr, token) {
  const src = W()[fromIdx];
  if (!src.privateKey) throw new Error("Offline signing needs a wallet with a stored key (not watch-only/Ledger).");
  const prov = provider();
  const chainId = Number((await prov.getNetwork()).chainId);
  const nonce = await prov.getTransactionCount(src.address, "pending");
  const f = await prov.getFeeData();
  let value, gasLimit, tok = null;
  if (token) {
    tok = tokensOf(netKey()).find(t => t.sym.toLowerCase() === token.toLowerCase());
    if (!tok) throw new Error(`Unknown token "${token}".`);
    const erc = new Contract(tok.addr, ERC20_ABI, prov);
    value = /^(max|all)$/i.test(amountStr) ? await erc.balanceOf(src.address) : parseUnits(String(amountStr).replace(",", "."), tok.dec);
    gasLimit = 65000n;
  } else {
    const bal = await prov.getBalance(src.address);
    const g = 21000n;
    const per = f.maxFeePerGas != null ? g * (f.maxFeePerGas + (f.maxPriorityFeePerGas ?? 0n)) : g * f.gasPrice;
    value = /^(max|all)$/i.test(amountStr) ? bal - per : parseEther(String(amountStr).replace(",", "."));
    gasLimit = g;
  }
  if (value <= 0n) throw new Error("Invalid amount.");
  return { v: 1, chain: netKey(), chainId, nonce, from: src.address, to: toAddr,
           value: value.toString(), gasLimit: gasLimit.toString(),
           maxFeePerGas: (f.maxFeePerGas ?? f.gasPrice).toString(),
           maxPriorityFeePerGas: (f.maxPriorityFeePerGas ?? 0n).toString(),
           type: 2, token: tok ? { sym: tok.sym, addr: tok.addr, dec: tok.dec, value: value.toString() } : null };
}
async function cmdTxPrepare(args) {
  let [fromA, toA, amtA] = args;
  if (fromA == null || toA == null || amtA == null) {
    const r = await P([
      { type: "text", name: "f", message: `Sign from which wallet? (0-${W().length - 1})` },
      { type: "text", name: "t", message: "Send to? (index, label, book or 0x…)" },
      { type: "text", name: "a", message: "Amount (or 'max'):" },
    ]);
    fromA = r.f; toA = r.t; amtA = r.a;
  }
  const from = findWallet(fromA);
  if (from < 0) throw new Error(`Wallet not found: "${fromA}"`);
  const to = resolveTo(toA);
  const plan = await spin("Building unsigned transaction…", () => buildTxPlan(from, to.addr, amtA, state.flags.token));
  const file = state.flags.file || path.join(process.cwd(), "unsigned-tx.json");
  fs.writeFileSync(file, JSON.stringify(plan, null, 2));
  console.log(c.ok(`\n✓ Unsigned transaction written: ${file}`));
  console.log(c.dim(`  On the OFFLINE machine: ravenne tx-sign ${path.basename(file)} <wallet#>`));
  console.log(c.dim("  Then back online: ravenne tx-broadcast <file>.signed.json — broadcast soon (nonce can go stale)."));
}
async function cmdTxSign(args) {
  const file = args[0];
  if (!file) throw new Error("Usage: tx-sign <unsigned-tx.json> [wallet#]");
  const plan = JSON.parse(fs.readFileSync(file, "utf8"));
  let signer;
  if (state.flags.keystore) {
    const json = fs.readFileSync(state.flags.keystore, "utf8");
    const pw = (await P({ type: "password", name: "p", message: "Keystore password:" })).p;
    signer = await spin("Opening keystore…", () => Wallet.fromEncryptedJson(json, pw));
  } else {
    const i = findWallet(args[1] ?? "");
    if (i < 0) throw new Error(`Wallet not found: "${args[1]}"`);
    requireKey(i);
    if (W()[i].address !== plan.from) throw new Error(`#${i} is ${W()[i].address} but the tx expects ${plan.from}.`);
    signer = new Wallet(W()[i].privateKey);
  }
  const txObj = { chainId: plan.chainId, nonce: Number(plan.nonce ?? await new JsonRpcProvider(rpcUrl(plan.chain)).getTransactionCount(plan.from)),
                  gasLimit: BigInt(plan.gasLimit), to: plan.to, value: 0n, type: plan.type,
                  maxFeePerGas: BigInt(plan.maxFeePerGas), maxPriorityFeePerGas: BigInt(plan.maxPriorityFeePerGas) };
  let raw, meta;
  if (plan.token) {
    const erc = new Contract(plan.token.addr, ERC20_ABI, signer);
    raw = await spin("Signing token transfer…", () => erc.transfer.populateTransaction(plan.to, BigInt(plan.token.value))
      .then(pop => signer.signTransaction({ ...pop, ...txObj, value: 0n })));
    meta = { ...plan, token: plan.token };
  } else {
    txObj.value = BigInt(plan.value);
    raw = await spin("Signing transaction…", () => signer.signTransaction(txObj));
    meta = plan;
  }
  const out = `${file}.signed.json`;
  fs.writeFileSync(out, JSON.stringify({ raw, meta }, null, 2));
  console.log(c.ok(`\n✓ Signed transaction written: ${out}`));
  console.log(c.dim("  Back online: ravenne tx-broadcast " + path.basename(out)));
}
async function cmdTxBroadcast(args) {
  const file = args[0];
  if (!file) throw new Error("Usage: tx-broadcast <file.signed.json>");
  const { raw, meta } = JSON.parse(fs.readFileSync(file, "utf8"));
  const prov = new JsonRpcProvider(rpcUrl(meta.chain));
  const tx = await spin("Broadcasting…", () => prov.broadcastTransaction(raw));
  const rc = await spin("Waiting for confirmation…", () => tx.wait());
  const fee = BigInt(rc.gasUsed) * BigInt(rc.effectiveGasPrice ?? tx.maxFeePerGas ?? 0n);
  const amount = meta.token ? fmtUnits(BigInt(meta.token.value), meta.token.dec) : formatEther(BigInt(meta.value));
  cur().history.push({ t: new Date().toISOString(), net: meta.chain, from: meta.from, to: meta.to,
                               amount, fee: formatEther(fee), hash: rc.hash, token: meta.token?.sym });
  save();
  console.log(c.ok(`\n✓ Confirmed in block ${rc.blockNumber} — ${amount} ${meta.token?.sym || NET[meta.chain].sym} (fee ${fmtAmt(fee)})`));
  printTxLink(rc.hash, meta.chain);
}

/* ═══════════════════════════ SIMPLE MODE ═══════════════════════════
   One MAIN wallet (receive-only by default — its seed stays on paper)
   + fresh RECEIVING addresses that forward everything to the main.
   Two separate seeds: a vault leak can never reach the main funds. */

const mainEvm     = () => W().find(w => w.role === "main");
const mainBtc     = () => BW().find(w => w.role === "main");
const receivingEvm = () => W().filter(w => w.role === "receive");
const receivingBtc = () => BW().filter(w => w.role === "receive");

async function cmdSetup(args) {
  if (mainEvm() && !(await confirm("A main wallet already exists — run the setup again anyway?")))
    return console.log("Cancelled.");
  let n = parseInt(args[0], 10);
  if (!Number.isInteger(n) || n < 1)
    n = (await P({ type: "number", name: "v", message: "How many receiving addresses do you want?", initial: 5, min: 1, max: 100 })).v;
  const watchOnly = !state.flags.keepKey;

  header("STEP 1/3 — YOUR MAIN SEED (write it on paper)");
  console.log(c.warn("This 24-word phrase controls your MAIN wallets (EVM + Bitcoin)."));
  console.log(c.err("It is " + (watchOnly ? "NOT stored in the vault (maximum security): this screen is your only copy!" : "about to be stored in the vault (encrypted, but online).") + "\n"));
  const mainPhrase = Mnemonic.fromEntropy(crypto.randomBytes(32)).phrase;
  console.log(c.bold(`\n  ${mainPhrase.split(" ").join(" · ")}\n`));
  if (!state.autoYes) {
    if (!(await confirm("Have you written it down somewhere safe?"))) { console.log("Setup cancelled — nothing was created."); return; }
    await P({ type: "text", name: "_", message: c.dim("Press Enter to clear the phrase from the screen…") });
    console.clear();
  } else console.log(c.warn("  (--yes mode: copy it NOW from the output above — it will not be shown again)" + (watchOnly ? "" : "")));

  header("STEP 2/3 — MAIN WALLETS");
  const evmMain = HDNodeWallet.fromPhrase(mainPhrase, "", "m/44'/60'/0'/0/0");
  const btcMain = btcAddressFromPhrase(mainPhrase, 0, settings().btcTest);
  W().push({ label: "main", address: evmMain.address, role: "main",
             ...(watchOnly ? { watchOnly: true } : { privateKey: evmMain.privateKey, phrase: mainPhrase }) });
  BW().push({ label: "btc-main", address: btcMain.address, role: "main", index: 0,
              ...(watchOnly ? { watchOnly: true } : { phrase: mainPhrase }) });

  header("STEP 3/3 — RECEIVING ADDRESSES");
  console.log(c.dim("A separate hot seed (stored encrypted in the vault) creates the receiving"));
  console.log(c.dim("addresses. Everything they receive is forwarded to your main wallets.\n"));
  const recvPhrase = Mnemonic.fromEntropy(crypto.randomBytes(32)).phrase;
  settings().seeds.receive = recvPhrase;
  const existing = receivingEvm().length;
  for (let i = 0; i < n; i++) {
    const w = HDNodeWallet.fromPhrase(recvPhrase, "", `m/44'/60'/0'/0/${existing + i}`);
    W().push({ label: `in-${existing + i + 1}`, address: w.address, privateKey: w.privateKey, role: "receive" });
    const b = btcAddressFromPhrase(recvPhrase, existing + i, settings().btcTest);
    BW().push({ label: `btc-in-${existing + i + 1}`, address: b.address, phrase: recvPhrase, index: existing + i, role: "receive" });
  }
  save();
  box("READY — YOUR SETUP", [
    `Main (keep PRIVATE)    ${evmMain.address}`,
    `Main BTC               ${btcMain.address}`,
    `Main key               ${watchOnly ? c.ok("NOT in the vault (paper only) — a vault leak can't touch it") : "stored in vault (spendable here)"}`,
    `Receiving addresses    ${n} fresh EVM + ${n} BTC (give THESE out, never the main)`,
    `Backup                 main seed on paper · receiving seed inside the vault`,
    ``,
    `Next: 'ravenne' → Forward all to main · 'ravenne auto' → automatic forwarding`,
  ]);
  console.log(c.dim("\nPrivacy: give a different receiving address to each payer, and let"));
  console.log(c.dim("'ravenne auto' forward at random intervals — never reuse the main address publicly."));
}

async function cmdAddresses(args) {
  let add = parseInt(args[0], 10) || 0;
  if (add > 0) {
    const phrase = settings().seeds.receive;
    if (!phrase) throw new Error("No receiving seed — run 'ravenne setup' first.");
    const existing = receivingEvm().length;
    for (let i = 0; i < Math.min(add, 100); i++) {
      const w = HDNodeWallet.fromPhrase(phrase, "", `m/44'/60'/0'/0/${existing + i}`);
      W().push({ label: `in-${existing + i + 1}`, address: w.address, privateKey: w.privateKey, role: "receive" });
      const b = btcAddressFromPhrase(phrase, existing + i, settings().btcTest);
      BW().push({ label: `btc-in-${existing + i + 1}`, address: b.address, phrase, index: existing + i, role: "receive" });
    }
    save();
    console.log(c.ok(`✓ ${add} fresh receiving address${add > 1 ? "es" : ""} added (EVM + BTC).`));
  }
  header("RECEIVING ADDRESSES — give these out");
  console.log(c.dim("EVM (Ethereum, Polygon, BNB, Arbitrum, Base, Optimism — same address):"));
  table(["#", "LABEL", "ADDRESS"], receivingEvm().map((w, i) => [`#${i}`, w.label, w.address]));
  if (receivingBtc().length) {
    console.log(c.dim("\nBitcoin:"));
    table(["#", "LABEL", "ADDRESS"], receivingBtc().map((w, i) => [`#${i}`, w.label, w.address]));
  }
  const m = mainEvm();
  if (m) console.log(c.warn(`\nMAIN (never publish): ${m.address}`));
  console.log(c.dim("Add more: ravenne addresses 5 · QR: ravenne qr in-1"));
}

async function recordBtc(txid, from, to, amountSat, feeSat) {
  cur().history.push({ t: new Date().toISOString(), net: "btc", from, to,
    amount: fmtBtc(amountSat), fee: fmtBtc(feeSat), hash: txid });
  save();
}
async function sweepBtcOne(idx, destAddr) {
  const e = BW()[idx];
  const utxos = await btcFetch(`/address/${e.address}/utxo`);
  if (!Array.isArray(utxos) || !utxos.length) return 0n;
  const rates = await btcFetch("/fee-estimates");
  const satPerVb = Math.max(2, Math.ceil(Number(rates["6"] || rates["3"] || rates["1"] || 12)));
  const total = utxos.reduce((s, u) => s + BigInt(u.value), 0n);
  const maxFee = BigInt((11 + 68 * utxos.length + 62) * satPerVb);
  const amount = total - maxFee;
  if (amount < 1000n) return 0n;
  const { hex, fee } = await buildBtcTx(e, utxos, destAddr, amount, satPerVb);
  const txid = await btcFetch("/tx", hex);
  await recordBtc(txid, e.address, destAddr, amount, fee);
  return amount;
}

/* Forward everything from the receiving wallets to the main wallets. */
async function cmdSweep(opts = {}) {
  const args = Array.isArray(opts) ? opts : [];
  const auto = opts === Object(opts) && opts.auto === true;
  const mEvm = mainEvm(), mBtc = mainBtc();
  if (!mEvm) throw new Error("No main wallet — run 'ravenne setup' first.");
  const chains = (state.flags.all || (opts.all))
    ? Object.keys(NET) : [netKey()];
  let moved = 0n, count = 0;
  const pending = [];

  for (const k of chains) {
    const prov = new JsonRpcProvider(rpcUrl(k));
    const per = await feePerTx(prov).catch(() => null);
    if (per == null) { console.log(c.warn(`  ⚠ ${NET[k].label}: RPC unreachable`)); continue; }
    const rule = k === "eth" ? settings().convert?.eth : null;   // convert-on-forward rule
    const recv = receivingEvm();
    for (let r = 0; r < recv.length; r++) {
      const w = recv[r];
      const idx = W().indexOf(w);
      const bal = await prov.getBalance(w.address).catch(() => 0n);
      const mult = BigInt(settings().privacy.sweepFeeMult ?? 3);
      if (bal <= per * mult && !rule) continue;

      /* convert-on-forward: swap BEFORE forwarding to main (Ethereum / Uniswap) */
      if (rule) {
        const from = resolveAsset(rule.from), to = resolveAsset(rule.to);
        const gasBudget = await feePerTx(prov, from.native ? 400000n : 500000n);   // approve? + swap + transfer
        if (from.native) {
          if (bal <= gasBudget) continue;                       // too small to convert
          if (auto && count > 0) await countdown(5 + Math.floor(Math.random() * 25));
          console.log(c.dim(`\n→ ${w.label}: converting ${fmtAmt(bal - gasBudget)} ETH → ${to.sym} (Uniswap)…`));
          try {
            const { block } = await execSwap(idx, from, to, bal - gasBudget);
            console.log(c.ok(`   ✓ swapped (block ${block}) — forwarding to main…`));
          } catch (e) { console.log(c.warn(`   ⚠ swap failed (${e.shortMessage || e.message}) — forwarding as ETH instead`)); }
        } else {
          const erc = new Contract(from.addr, ERC20_ABI, prov);
          const tkBal = await erc.balanceOf(w.address).catch(() => 0n);
          if (tkBal <= 0n || bal <= gasBudget) continue;         // nothing to convert / no gas
          if (auto && count > 0) await countdown(5 + Math.floor(Math.random() * 25));
          console.log(c.dim(`\n→ ${w.label}: converting ${fmtUnits(tkBal, from.dec)} ${from.sym} → ${to.sym} (Uniswap)…`));
          try {
            const { block } = await execSwap(idx, from, to, tkBal);
            console.log(c.ok(`   ✓ swapped (block ${block}) — forwarding to main…`));
          } catch (e) { console.log(c.warn(`   ⚠ swap failed (${e.shortMessage || e.message}) — forwarding as-is`)); }
        }
        /* forward whatever the wallet now holds (converted asset) to main */
        const balNow = await prov.getBalance(w.address);
        const finalPer = await feePerTx(prov);
        if (!to.native) {
          const erc = new Contract(to.addr, ERC20_ABI, prov);
          const got = await erc.balanceOf(w.address);
          if (got > 0n && balNow > finalPer) {
            const { hash } = await doSend(idx, mEvm.address, got, k, to);
            count++; moved += 0n;
            console.log(c.ok(`   ✓ ${fmtUnits(got, to.dec)} ${to.sym} → main`));
            printTxLink(hash, k);
          }
        } else if (balNow > finalPer * 2n) {
          const { hash } = await doSend(idx, mEvm.address, balNow - finalPer, k);
          count++;
          console.log(c.ok(`   ✓ ${fmtAmt(balNow - finalPer)} ETH → main`));
          printTxLink(hash, k);
        }
        continue;   // converted — skip the plain native/token sweep below
      }

      // privacy: leave a random 0–0.3% behind so the amount doesn't match exactly
      const net = bal - per;
      const retain = net > 100000n
        ? BigInt(Math.round(Number(net) * Math.random() * (settings().privacy.retainPermille ?? 3) / 1000)) : 0n;
      const value = net - retain;
      if (auto && count > 0) await countdown(5 + Math.floor(Math.random() * 25));
      console.log(c.dim(`\n→ ${w.label} → main (${NET[k].label})  ${fmtAmt(value)} ${NET[k].sym}${retain > 0n ? c.dim(` · ${fmtAmt(retain)} kept back`) : ""}`));
      const { hash, fee, block } = await doSend(idx, mEvm.address, value, k);
      count++; moved += value;
      console.log(c.ok(`   ✓ block ${block}, fee ${fmtAmt(fee)}`));
      printTxLink(hash, k);
      // configured ERC-20 tokens left on the address (needs a little native coin for gas)
      for (const t of tokensOf(k)) {
        try {
          const erc = new Contract(t.addr, ERC20_ABI, prov);
          const tb = await erc.balanceOf(w.address);
          if (tb > 0n && bal - fee > per) {
            const { hash: h2 } = await doSend(idx, mEvm.address, tb, k, t);
            console.log(c.ok(`   ✓ + ${fmtUnits(tb, t.dec)} ${t.sym} forwarded`));
            printTxLink(h2, k);
          }
        } catch {}
      }
    }
  }
  // Bitcoin receiving → main BTC
  if (mBtc && receivingBtc().length) {
    for (let i = 0; i < receivingBtc().length; i++) {
      const e = receivingBtc()[i];
      try {
        if (auto && count > 0) await countdown(5 + Math.floor(Math.random() * 25));
        const got = await sweepBtcOne(BW().indexOf(e), mBtc.address);
        if (got > 0n) { count++; moved += 0n; console.log(c.ok(`✓ ${e.label} → btc-main  ${fmtBtc(got)} BTC`)); }
      } catch (e2) { console.log(c.warn(`  ⚠ ${e.label}: ${e2.message}`)); }
    }
  }
  if (!count) console.log(c.dim("\nNothing to forward — receiving wallets are empty (or below the fee threshold)."));
  else console.log(c.ok(`\n✅ Forwarded ${count} transaction${count > 1 ? "s" : ""} to the main wallets.`));
  return { count };
}

/* Auto-forward daemon: checks at randomized intervals. */
async function cmdAuto(args) {
  const minutes = Math.max(1, parseFloat(args[0]) || 15);
  console.clear();
  box("AUTO-FORWARD DAEMON", [
    `Interval    every ~${minutes} min (randomized ±50% for privacy)`,
    `Chains      all EVM chains + Bitcoin`,
    `Vault       stays unlocked in memory while this runs`,
    `Stop        Ctrl+C`,
    ``,
    `Receiving wallets are swept to the main as soon as they hold`,
    `more than ~3× the fee — with random delays between sends.`,
  ]);
  while (true) {
    try { await cmdSweep({ auto: true, all: true }); }
    catch (e) { console.log(c.err(`✗ ${e.message}`)); }
    const waitMs = minutes * 60000 * (0.5 + Math.random());
    const next = new Date(Date.now() + waitMs).toLocaleTimeString("en-GB");
    console.log(c.dim(`\n😴 sleeping until ~${next} …`));
    await sleep(waitMs);
    console.clear();
    console.log(c.vio("🪶  RAVENNE — auto-forward daemon · Ctrl+C to stop"));
  }
}

async function simpleBalances() {
  const k = netKey();
  const prov = provider();
  const m = mainEvm();
  const recv = receivingEvm();
  const [mBal, ...rBals] = await spin(`Fetching ${NET[k].label}…`, () =>
    Promise.all([m, ...recv].map(w => prov.getBalance(w.address).catch(() => null))));
  header(`BALANCES — ${NET[k].label} (${NET[k].sym})`);
  const rows = [[c.bold("MAIN"), m.label, m.address, fmtAmt(mBal ?? 0n)],
    ...recv.map((w, i) => [c.dim("in"), w.label, w.address, rBals[i] == null ? "?" : fmtAmt(rBals[i])])];
  table(["ROLE", "LABEL", "ADDRESS", `BALANCE (${NET[k].sym})`], rows, { align: [null, null, null, "r"] });
  const waiting = rBals.reduce((s, b) => (b ? s + b : s), 0n);
  console.log(`\n   ${c.bold("Waiting on receiving")} (to be forwarded): ${c.warn(fmtAmt(waiting))} ${NET[k].sym}`);
  if (mainBtc() && receivingBtc().length) {
    const [mb, ...rb] = await spin("Fetching Bitcoin…", () =>
      Promise.all([mainBtc(), ...receivingBtc()].map(w => btcFetch(`/address/${w.address}`)
        .then(j => BigInt(j.chain_stats.funded_txo_sum) - BigInt(j.chain_stats.spent_txo_sum)).catch(() => null))));
    header(`BITCOIN${settings().btcTest ? " · TESTNET" : ""}`);
    table(["ROLE", "LABEL", "ADDRESS", "BALANCE (BTC)"],
      [[c.bold("MAIN"), mainBtc().label, mainBtc().address, fmtBtc(mb ?? 0n)],
       ...receivingBtc().map((w, i) => [c.dim("in"), w.label, w.address, rb[i] == null ? "?" : fmtBtc(rb[i])]),
      ].map(r => r.map((x, j) => j === 0 ? x : x)), { align: [null, null, null, "r"] });
    const bw = rb.reduce((s, b) => (b ? s + b : s), 0n);
    console.log(`\n   Waiting on receiving: ${c.warn(fmtBtc(bw))} BTC`);
  }
}

async function simpleMenu() {
  banner();
  if (!mainEvm()) {
    console.log(c.vio("\n👋 Welcome! Ravenne will set up:"));
    console.log(`   ${c.bold("1 MAIN wallet")} — your vault, kept private (seed on paper${c.dim(", optionally not even stored here")})`);
    console.log(`   ${c.bold("RECEIVING addresses")} — give them out; everything is forwarded to main\n`);
    if (await confirm("Start the guided setup?")) { try { await cmdSetup([]); } catch (e) { console.log(c.err(`✗ ${e.message}`)); } }
    else { console.log("Run 'ravenne help' for the advanced commands. Bye 👋"); return; }
  }
  let lastActive = Date.now();
  while (true) {
    if (settings().autolockMin > 0 && Date.now() - lastActive > settings().autolockMin * 60000) { await lockSession(); banner(); }
    console.log(c.dim(`  main: ${short(mainEvm().address)} · receiving: ${receivingEvm().length} EVM + ${receivingBtc().length} BTC · chain: ${N().label}\n`));
    const { a } = await P({
      type: "select", name: "a", message: "What do you want to do?",
      choices: [
        { title: "Receiving addresses (give these out)", value: "addr",
          description: "Fresh addresses payers send to. One per payer for privacy — everything lands on your main." },
        { title: "Balances (main + waiting)", value: "bal",
          description: "What the main wallet holds, and what sits on receiving addresses waiting to be forwarded." },
        { title: "Forward everything to main now", value: "sweep",
          description: "Immediately move all funds from every receiving address (EVM + BTC) to the main wallets." },
        { title: "Auto-forward daemon (randomized)", value: "auto",
          description: "Runs until Ctrl+C: checks at random intervals and forwards automatically, with random delays." },
        { title: "Swap coins (ETH ⇄ USDT/USDC)", value: "swap",
          description: "Convert between coins via Uniswap (Ethereum): price preview + 1% slippage protection." },
        { title: "Spend from main", value: "spend",
          description: "Send from the main wallet to any address (requires the main key in the vault)." },
        { title: "USB wallet", value: "usb",
          description: "Create or open an encrypted wallet on a USB stick — keys stay in RAM, never on this disk." },
        { title: "New temporary address (auto-delete)", value: 'temp',
          description: 'Burner receiving address: forwards to main at expiry, then keys are erased.' },
        { title: "Switch wallet", value: 'switch',
          description: 'Open a different named wallet profile.' },
        { title: "Switch chain", value: "chain",
          description: "Change the active chain: Ethereum, Polygon, BNB, Arbitrum, Base, Optimism, local test." },
        { title: "Settings", value: "set",
          description: "VPN gate, price lookups, auto-lock delay, sweep threshold, mesh-VPN policy." },
        { title: "Backup & security", value: "sec",
          description: "Reveal seeds, export keystores, backup/restore the vault, change password, privacy notes." },
        { title: "Diagnostics (check)", value: "check",
          description: "Verify VPN, RPC connectivity, gate/vault health and the environment in one pass." },
        { title: "Advanced mode (all commands)", value: "adv",
          description: "Full menu with every feature: splits, consolidations, tokens, Bitcoin, offline signing…" },
        { title: "Lock & quit", value: "quit",
          description: "Clear the screen and exit — everything is encrypted on disk." },
      ],
    });
    lastActive = Date.now();
    try {
      if (a === "quit") { console.clear(); console.log("Bye."); process.exit(0); }
      else if (a === "addr") {
        await cmdAddresses([]);
        if (await confirm("Add new receiving addresses?")) {
          const { n } = await P({ type: "number", name: "n", message: "How many?", initial: 3, min: 1, max: 100 });
          await cmdAddresses([String(n)]);
        }
      }
      else if (a === "bal") await simpleBalances();
      else if (a === "sweep") await cmdSweep([]);
      else if (a === "auto") {
        const { m } = await P({ type: "number", name: "m", message: "Check interval in minutes (randomized)?", initial: 15, min: 1, max: 720 });
        await cmdAuto([String(m)]);
      }
      else if (a === "swap") await cmdSwap([]);
      else if (a === "chain") {
        const { k } = await P({ type: "select", name: "k", message: "Active chain:",
          choices: Object.entries(NET).map(([k, v]) => ({ title: `${v.label} (${v.sym})`, value: k,
            description: k === "local" ? "Local test chain (Ganache) — practice with fake money." : `Switch balances/sends/swaps to ${v.label}.` })) });
        await cmdNetwork([k]);
      }
      else if (a === "set") await quickSettings();
      else if (a === "check") await cmdCheck();
      else if (a === 'temp') {
        const { d } = await P({ type: 'select', name: 'd', message: 'Lifetime of the address?',
          choices: [
            { title: '1 hour', value: '1h' },
            { title: '6 hours', value: '6h' },
            { title: '24 hours (recommended)', value: '24h' },
            { title: '3 days', value: '3d' },
            { title: '7 days', value: '7d' },
          ] });
        await cmdTemp([d, 1]);
      }
      else if (a === 'switch') { console.clear(); await pickProfile(); }
      else if (a === "usb") {
        const { s } = await P({ type: "select", name: "s", message: "USB wallet:",
          choices: [ { title: "Open (mount a USB wallet)", value: "open" },
                     { title: "Create a new one on a USB stick", value: "create" },
                     ...(W().some(w => w.usb) ? [{ title: "Close / unmount (purge keys from RAM)", value: "close" }] : []) ] });
        if (s === "open") await cmdUsb(["open"]);
        else if (s === "create") await cmdUsb(["create"]);
        else await cmdUsb(["close"]);
      }
      else if (a === "spend") {
        const m = mainEvm();
        if (!m.privateKey) {
          console.log(c.warn(`\nMain is watch-only (maximum security) — its key is not in the vault.`));
          console.log(c.dim("  To spend from main: 'ravenne import' its paper seed on this machine,"));
          console.log(c.dim("  or keep a separate spending wallet. Receiving wallets can always send (advanced: send)."));
        } else {
          const r = await P([
            { type: "text", name: "t", message: "Send to? (address, wallet label or book entry)" },
            { type: "text", name: "a", message: `Amount in ${N().sym} (or "max"):` },
          ]);
          await cmdSend([String(W().indexOf(m)), r.t, r.a]);
        }
      }
      else if (a === "sec") await securityMenu();
      else if (a === "adv") { console.log(c.dim("\nAdvanced mode — Quit there exits the app.\n")); await advancedMenu(); return; }
    } catch (e) { console.log(c.err(`\n✗ ${e.message}`)); }
    await P({ type: "text", name: "_", message: c.dim("— Enter to continue —") });
    lastActive = Date.now();
    console.clear();
    console.log(c.vio("🪶  RAVENNE WALLET — simple mode"));
  }
}

async function securityMenu() {
  while (true) {
    const { a } = await P({
      type: "select", name: "a", message: "Backup & security:",
      choices: [
        { title: "Backup the vault to a file", value: "backup",
          description: "Encrypted copy of the whole vault — store it on a USB stick or cloud drive." },
        { title: "Restore the vault from a backup", value: "restore",
          description: "Replace the current vault with a backup file (same master password only)." },
        { title: "Reveal the RECEIVING seed (hot, inside vault)", value: "rseed",
          description: "The seed controlling all receiving wallets — for paper backup." },
        { title: "Reveal the MAIN seed (only if stored in vault)", value: "mseed",
          description: "Shown once at setup if watch-only — normally only on your paper." },
        { title: "Export main keystore (only if key stored)", value: "ks",
          description: "Encrypted keystore file importable in MetaMask and elsewhere." },
        { title: "Export a raw private key", value: "rawkey",
          description: "Reveal one wallet's private key — full access, handle with extreme care." },
        { title: "Change master password", value: "pass",
          description: "Re-encrypts gate and vault with a new password." },
        { title: "Privacy notes — what this protects against", value: "priv",
          description: "Honest summary of the privacy model and its limits." },
        { title: "←  Back", value: "back" },
      ],
    });
    if (a === "back") return;
    try {
      if (a === "backup") await cmdBackup([]);
      else if (a === "restore") await cmdRestore([(await P({ type: "text", name: "f", message: "Backup file path:" })).f]);
      else if (a === "rawkey") await cmdExportKey([]);
      if (a === "rseed") {
        console.log(c.warn("\n⚠  This seed controls ALL receiving wallets (funds waiting to be forwarded):"));
        if (await confirm("Reveal?")) console.log(c.bold(`\n  ${settings().seeds.receive}\n`));
      } else if (a === "mseed") {
        const m = mainEvm();
        if (!m?.phrase) console.log(c.warn("\nMain is watch-only — its seed exists only on your paper backup."));
        else if (await confirm("Reveal the main seed?")) console.log(c.bold(`\n  ${m.phrase}\n`));
      } else if (a === "ks") {
        const m = mainEvm();
        if (!m?.privateKey) console.log(c.warn("\nMain is watch-only — nothing to export."));
        else await cmdExport([String(W().indexOf(m))]);
      } else if (a === "pass") await cmdChangePass();
      else if (a === "priv") box("PRIVACY — HONEST NOTES", [
        `✓ fresh receiving address per payer (no address reuse)`,
        `✓ main address never shown to payers`,
        `✓ auto-forward at randomized intervals + random amounts kept back`,
        `✓ main seed can live on paper only (vault leak ⇒ receiving funds only)`,
        `✓ price lookups OFF by default · use your own RPC ('rpc') for IP privacy`,
        ``,
        `✗ direct forwards stay visible on the public blockchain — a patient`,
        `  analyst can still link receiving → main. This design reduces casual`,
        `  clustering, it cannot make crypto 'untraceable'.`,
        `✗ for stronger anonymity, research third-party techniques yourself and`,
        `  check your local laws — none are integrated here on purpose.`,
      ]);
    } catch (e) { console.log(c.err(`✗ ${e.message}`)); }
  }
}



/* ═══════════════════════════ VAULT BACKUP / DIAGNOSTICS / EXTRA OPTIONS ═══════════════════════════ */
async function cmdBackup(args) {
  if (!fs.existsSync(VAULT_FILE)) throw new Error("No vault yet — nothing to back up.");
  let file = args[0] || path.join(process.cwd(), `ravenne-backup-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`);
  if (path.resolve(file) === path.resolve(VAULT_FILE)) throw new Error("Backup path must differ from the vault file.");
  let n = 2;
  while (fs.existsSync(file) && !args[0]) file = path.join(process.cwd(), `ravenne-backup-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}-${n++}.json`);
  fs.copyFileSync(VAULT_FILE, file);
  console.log(c.ok(`✓ Vault backup written: ${file}`));
  console.log(c.dim(`  Still AES-256-GCM encrypted with your master password — safe to store anywhere.`));
  return file;
}
async function cmdRestore(args) {
  const file = args[0];
  if (!file) throw new Error("Usage: restore <backup-file.json>");
  const src = path.resolve(file);
  if (!fs.existsSync(src)) throw new Error(`File not found: ${file}`);
  if (src === path.resolve(VAULT_FILE)) throw new Error("That IS the vault file.");
  let probe;
  try { probe = decryptVault(state.pass, src); }
  catch { throw new Error("This backup was encrypted with a DIFFERENT master password — cannot restore here."); }
  console.log(c.warn(`\n⚠  Restoring will REPLACE the current vault (${probe.wallets.length} wallets, ${probe.btcWallets?.length || 0} BTC in the backup).`));
  if (fs.existsSync(VAULT_FILE)) {
    const keep = await confirm("Keep a safety copy of the current vault first? (recommended)");
    if (keep) {
      // never overwrite the backup we are restoring FROM
      const safety = path.join(process.cwd(), `ravenne-pre-restore-${Date.now()}.json`);
      fs.copyFileSync(VAULT_FILE, safety);
      console.log(c.ok(`✓ Safety copy: ${safety}`));
    }
  }
  if (!(await confirm("Restore now?"))) return console.log("Cancelled.");
  fs.copyFileSync(src, VAULT_FILE);
  state.payload = decryptVault(state.pass);
  console.log(c.ok(`✓ Vault restored: ${W().length} EVM + ${BW().length} BTC wallets, ${cur().history.length} tx history.`));
}
async function cmdExportKey(args) {
  let a = args[0];
  if (a == null) a = (await P({ type: "text", name: "v", message: `Export which wallet's key? (0-${W().length - 1})` })).v;
  const i = findWallet(a);
  if (i < 0) throw new Error(`Wallet not found: "${a}"`);
  if (!W()[i].privateKey) throw new Error(`#${i} holds no key (watch-only/Ledger).`);
  console.log(c.err(`\n⚠  The PRIVATE KEY of #${i} ${W()[i].label} gives FULL access to its funds — no password, no delay.`));
  if (!(await confirm("I understand — reveal it anyway"))) return console.log("Cancelled.");
  console.log(c.bold(`\n  ${W()[i].privateKey}\n`));
  if (!state.autoYes) {
    await P({ type: "text", name: "_", message: c.dim("Press Enter to clear the screen…") });
    console.clear();
  }
}
async function cmdCheck() {
  header("DIAGNOSTICS");
  const rows = [];
  rows.push(["Node.js", process.version, parseInt(process.version.slice(1)) >= 18 ? c.ok("ok") : c.err("≥18 required")]);
  rows.push(["Terminal", TTY ? "interactive (colors ok)" : "non-interactive (piped)", TTY ? c.ok("ok") : c.warn("limited")]);
  const proxy = process.env.HTTPS_PROXY || process.env.ALL_PROXY || "";
  rows.push(["Proxy", proxy || "none set", proxy ? c.ok("routed") : c.dim("direct")]);
  const st = await vpnState();
  rows.push(["VPN", st.ok ? st.adapter.slice(0, 30) : (st.mesh ? `only mesh (${st.mesh.slice(0, 18)}…)` : "none detected"),
             st.ok ? c.ok("protected") : settings().vpnCheck === false ? c.warn("check OFF") : c.err("BLOCKED")]);
  rows.push(["Gate file", fs.existsSync(GATE_FILE) ? "present" : "missing", fs.existsSync(GATE_FILE) ? c.ok("ok") : c.warn("first run")]);
  rows.push(["Vault", fs.existsSync(VAULT_FILE) ? `${W().length} EVM + ${BW().length} BTC` : "not created yet", fs.existsSync(VAULT_FILE) ? c.ok("ok") : c.dim("—")]);
  try {
    const bn = await provider().getBlockNumber();
    rows.push([`${N().label} RPC`, `block #${bn}`, c.ok("reachable")]);
  } catch { rows.push([`${N().label} RPC`, "no answer", c.err("unreachable")]); }
  try {
    const h = await btcFetch("/blocks/tip/height");
    rows.push(["Bitcoin API", `tip #${h}`, c.ok("reachable")]);
  } catch { rows.push(["Bitcoin API", "no answer", c.warn("offline?")]); }
  rows.push(["Price lookups", settings().prices ? "ON (CoinGecko sees your IP)" : "OFF", settings().prices ? c.warn("privacy") : c.ok("private")]);
  table(["CHECK", "VALUE", "STATUS"], rows);
  console.log(c.dim("\n  Fix RPC issues: ravenne rpc <chain> <url> · privacy: ravenne settings prices off"));
}
async function quickSettings() {
  const s = settings();
  while (true) {
    const { a } = await P({ type: "select", name: "a", message: "Settings:", choices: [
      { title: `VPN check: ${s.vpnCheck ? "ON" : "OFF"}`, value: "vpn",
        description: "Refuse to connect without an active anonymity VPN (WireGuard, Proton, Nord…)." },
      { title: `Mesh VPN counts as VPN: ${s.meshVpnOk ? "YES" : "NO"}`, value: "mesh",
        description: "Let Radmin/Hamachi/ZeroTier-style LAN VPNs satisfy the check. They do NOT hide your traffic." },
      { title: `Price lookups: ${s.prices ? "ON" : "OFF"}`, value: "prices",
        description: "Fiat values via CoinGecko — OFF means zero calls to price providers (better privacy)." },
      { title: `Auto-lock: ${s.autolockMin} min`, value: "lock",
        description: "Menu re-asks the master password after this idle time (0 = never)." },
      { title: `Sweep threshold: ${s.privacy.sweepFeeMult ?? 3}× fee`, value: "sweepfee",
        description: "Receiving wallets are forwarded once they hold more than fee × this number." },
      { title: `Convert on forward: ${s.convert?.eth ? `${s.convert.eth.from} → ${s.convert.eth.to}` : "off"}`, value: "convert",
        description: "Swap incoming funds via Uniswap BEFORE they reach the main wallet (Ethereum)." },
      { title: "←  Back", value: "back" },
    ]});
    if (a === "back") return;
    try {
      if (a === "vpn") { s.vpnCheck = !s.vpnCheck; save(); console.log(c.ok(`✓ VPN check ${s.vpnCheck ? "enabled" : "DISABLED"}`)); }
      if (a === "mesh") { s.meshVpnOk = !s.meshVpnOk; save(); console.log(c.ok(`✓ Mesh VPNs ${s.meshVpnOk ? "now accepted (less private)" : "no longer accepted"}`)); }
      if (a === "prices") { s.prices = !s.prices; save(); console.log(c.ok(`✓ Price lookups ${s.prices ? "enabled" : "disabled"}`)); }
      if (a === "lock") {
        const { m } = await P({ type: "number", name: "m", message: "Auto-lock minutes (0 = off):", initial: s.autolockMin, min: 0, max: 240 });
        s.autolockMin = m; save(); console.log(c.ok(`✓ Auto-lock: ${m === 0 ? "off" : `${m} min`}`));
      }
      if (a === "sweepfee") {
        const { m } = await P({ type: "number", name: "m", message: "Forward when balance > fee × :", initial: s.privacy.sweepFeeMult ?? 3, min: 1, max: 100 });
        s.privacy.sweepFeeMult = m; save(); console.log(c.ok(`✓ Sweep threshold: ${m}× fee`));
      }
      if (a === "convert") {
        const { v } = await P({ type: "select", name: "v", message: "Convert incoming funds before forwarding:",
          choices: [
            { title: "Off — forward as-is", value: "off", description: "Whatever arrives (ETH or tokens) is forwarded unchanged." },
            { title: "ETH → USDT", value: "ETH USDT", description: "Ether received is swapped to USDT before reaching main." },
            { title: "ETH → USDC", value: "ETH USDC", description: "Ether received is swapped to USDC before reaching main." },
            { title: "USDT → ETH", value: "USDT ETH", description: "Tether received (needs a little ETH for gas) is swapped to ETH." },
            { title: "USDC → ETH", value: "USDC ETH", description: "USDC received (needs a little ETH for gas) is swapped to ETH." },
          ]});
        if (v === "off") { (s.convert ??= {}); delete s.convert.eth; save(); console.log(c.ok("✓ Conversion off.")); }
        else { const [f, t] = v.split(" "); (s.convert ??= {}); s.convert.eth = { from: f, to: t }; save();
               console.log(c.ok(`✓ Everything received on Ethereum will become ${t} before reaching main.`)); }
      }
    } catch (e) { console.log(c.err(`✗ ${e.message}`)); }
  }
}

/* ═══════════════════════════ USB WALLET ═══════════════════════════
   A portable, AES-256-GCM encrypted wallet file living on a USB stick.
   Opened ONLY through Ravenne (own password). While open, keys stay in RAM
   and are NEVER written to the local disk. */
const USB_FILE = "ravenne-usb.json";
async function cmdUsb(args) {
  const sub = args[0] || "status";
  if (sub === "create") {
    const target = path.resolve(String(args[1] || (await P({ type: "text", name: "p", message: "USB drive or folder (e.g. E:\\ ):" })).p).replace(/^["']|["']$/g, ""));
    fs.mkdirSync(target, { recursive: true });
    const file = path.join(target, USB_FILE);
    if (fs.existsSync(file) && !(await confirm(`${USB_FILE} already exists there — overwrite?`))) return console.log("Cancelled.");
    const choice = args[2] === "new" ? "new"
      : /^\d+$/.test(String(args[2] ?? "")) ? args[2]
      : (await P({ type: "select", name: "s", message: "What goes on the USB wallet?", choices: [
      { title: "A brand-new wallet (fresh 24-word keys)", value: "new" },
      ...W().filter(w => w.privateKey).map(w => ({ title: `Copy existing  #${W().indexOf(w)} ${w.label}  ${short(w.address)}`, value: String(W().indexOf(w)) })),
    ]})).s;
    let wallets = [];
    if (choice === "new") {
      const e = newWalletEntry(24);
      e.label = "usb-main"; e.role = "usb-main";
      wallets = [e];
      console.log(c.warn("\n⚠  24-word seed of the USB wallet — shown ONCE:"));
      if (await confirm("Reveal it now?")) console.log(c.bold(`\n  ${e.phrase}\n`));
      else console.log(c.dim("  (the key is inside the encrypted file; keep a phrase backup anyway)"));
    } else wallets = [{ ...W()[+choice] }];
    let pw = process.env.RAVENNE_KEYPASS;
    if (!pw) {
      const r = await P([
        { type: "password", name: "a", message: "USB wallet password (8 chars min.):" },
        { type: "password", name: "b", message: "Confirm USB password:" },
      ]);
      if (r.a !== r.b) throw new Error("Passwords do not match.");
      pw = r.a;
    }
    if (!pw || pw.length < 8) throw new Error("Password too short (8 min.).");
    encryptVault({ kind: "usb", wallets, btcWallets: [], created: new Date().toISOString() }, pw, file);
    fs.writeFileSync(path.join(target, "README-USB.txt"),
      "Ravenne USB wallet\n==================\nThis folder holds ravenne-usb.json (AES-256-GCM encrypted).\nOpen it with:  ravenne usb open <this folder>\nNothing else is needed. Keep a paper backup of the seed phrase.\n");
    console.log(c.ok(`\n✓ USB wallet created: ${file}`));
    console.log(c.dim("  Open it anywhere with Ravenne:  ravenne usb open " + target));
  }
  else if (sub === "open") {
    if (W().some(w => w.usb)) throw new Error("A USB wallet is already mounted — close it first: ravenne usb close");
    const target = path.resolve(String(args[1] || (await P({ type: "text", name: "p", message: "USB folder path:" })).p).replace(/^["']|["']$/g, ""));
    const file = path.join(target, USB_FILE);
    if (!fs.existsSync(file)) throw new Error(`No ${USB_FILE} found at ${target}`);
    let pw = process.env.RAVENNE_KEYPASS;
    if (!pw) pw = (await P({ type: "password", name: "p", message: "USB wallet password:" })).p;
    let u;
    try { u = decryptVault(pw, file); } catch { throw new Error("Wrong USB password (or corrupted file)."); }
    u.wallets.forEach(w => { w.usb = true; w.label = `usb:${w.label}`; W().push(w); });
    state.usbFile = file;
    console.log(c.ok(`\n✓ USB wallet mounted (${u.wallets.length} key${u.wallets.length > 1 ? "s" : ""}, RAM only):`));
    u.wallets.forEach((w, i) => console.log(`   ${c.bold(`#${W().length - u.wallets.length + i}`)} ${w.label}  ${w.address}`));
    console.log(c.dim("  Spend from these indexes like any wallet. Unmount: ravenne usb close"));
  }
  else if (sub === "close") {
    const n = W().filter(w => w.usb).length;
    if (!n) return console.log(c.dim("No USB wallet mounted."));
    for (let i = W().length - 1; i >= 0; i--) if (W()[i].usb) W().splice(i, 1);
    state.usbFile = null;
    console.log(c.ok(`✓ USB wallet unmounted — ${n} key${n > 1 ? "s" : ""} purged from memory (nothing was written to disk).`));
  }
  else if (sub === "status") {
    const mounted = W().filter(w => w.usb);
    console.log(mounted.length
      ? c.ok(`USB wallet mounted: ${mounted.map(w => w.label).join(", ")} (from ${state.usbFile})`)
      : c.dim("No USB wallet mounted. Create one: ravenne usb create E:\\"));
  }
  else throw new Error(`Unknown usb sub-command: ${sub} (create | open | close | status)`);
}

/* ═══════════════════════════ MONERO (XMR) ═══════════════════════════
   Keys are generated locally (monero-javascript). The wallet ENGINE is the
   official monero-wallet-rpc — either started locally ('xmr install' +
   'xmr engine', it is NOT a node and connects to a REMOTE daemon) or running
   on another machine you control ('xmr connect http://pi:18083 user:pass').
   Balance/sends therefore never need a local blockchain. Privacy: the remote
   daemon sees wallet requests like with any Monero wallet; the spend key
   NEVER leaves the vault. */
const XMR = { label: "Monero", sym: "XMR", ex: "https://xmrchain.net", cg: "monero" };
const XMR_DAEMON = () => settings().xmrDaemon || (settings().xmrStage ? "https://stagenet-community.xmr.tw:18081" : "http://xmr-node.cakewallet.com:18081");
const XMR_RPC = () => settings().xmrRpc || "http://127.0.0.1:18083";
const XMR_DIR = path.join(HERE, "tools", "monero");
const PICONERO = 1000000000000n;
const fmtXmr = a => { const n = BigInt(a); const i = n / PICONERO, d = (n % PICONERO).toString().padStart(12, "0").slice(0, 7).replace(/0+$/, ""); return d ? `${i}.${d}` : `${i}`; };
const parseXmr = s => { const [i, d = ""] = String(s).replace(",", ".").split("."); return BigInt(i || "0") * PICONERO + BigInt((d + "000000000000").slice(0, 12)); };
const findXmrWallet = a => {
  const s = String(a).trim().replace(/^#/, "").replace(/^xmr:/, "");
  if (/^\d+$/.test(s)) { const i = +s; return i >= 0 && i < XW().length ? i : -1; }
  return XW().findIndex(w => w.label.toLowerCase() === s.toLowerCase());
};
async function xmrKeysLib() {
  try {
    const m = await import("monero-javascript");
    if (!m.LibraryUtils.WASM_MODULE) {
      const { createRequire } = await import("node:module");
      const req = createRequire(pathToFileURL(path.join(HERE, "package.json")));
      const dir = path.dirname(req.resolve("monero-javascript/dist/monero_wallet_keys.js"));
      const ThreadPool = req("monero-javascript/src/main/js/common/ThreadPool");
      const mod = await req("monero-javascript/dist/monero_wallet_keys.js")(
        { wasmBinary: fs.readFileSync(path.join(dir, "monero_wallet_keys.wasm")) });
      delete mod.then;
      mod.taskQueue = new ThreadPool(1);
      mod.queueTask = async fn => mod.taskQueue.submit(fn);
      m.LibraryUtils.WASM_MODULE = mod;
    }
    return m;
  } catch { throw new Error("Monero key module missing — run: npm i monero-javascript"); }
}
async function xmrDaemonHeight() {
  const r = await fetch(`${XMR_DAEMON()}/json_rpc`, { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: "0", method: "get_info" }), signal: AbortSignal.timeout(15000) });
  const j = await r.json();
  if (!j?.result?.height) throw new Error("daemon unreachable");
  return j.result.height;
}
async function xmrRpcCall(method, params = {}) {
  const headers = { "Content-Type": "application/json" };
  if (settings().xmrRpcAuth) headers.Authorization = "Basic " + Buffer.from(settings().xmrRpcAuth).toString("base64");
  const r = await fetch(`${XMR_RPC()}/json_rpc`, { method: "POST", headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: "0", method, params }), signal: AbortSignal.timeout(300000) });
  const j = await r.json();
  if (j.error) throw new Error(j.error.message || JSON.stringify(j.error));
  return j.result;
}
async function xmrRequireEngine() {
  try { await xmrRpcCall("get_version"); return true; }
  catch {
    throw new Error(`No wallet engine at ${XMR_RPC()}.\n  Start one:  ravenne xmr install   then   ravenne xmr engine\n  Or point at another machine:  ravenne xmr connect http://pi-host:18083 user:pass`);
  }
}
async function xmrOpenWallet(w) {
  const pw = crypto.randomBytes(12).toString("hex");
  const files = (settings().xmrFiles ??= {});          // remember cache file + its password per address
  await xmrRpcCall("close_wallet").catch(() => {});
  if (files[w.address]) {
    try { await xmrRpcCall("open_wallet", { filename: files[w.address].file, password: files[w.address].pw }); return; }
    catch { /* cache broken — regenerate */ }
  }
  const name = "rv-" + w.address.slice(3, 12);
  try {
    await xmrRpcCall("generate_from_keys", { restore_height: w.restoreHeight ?? 0, filename: name, password: pw,
      address: w.address, viewkey: w.viewKey, ...(w.spendKey ? { spendkey: w.spendKey } : {}), daemon_address: XMR_DAEMON() });
  } catch (e) {
    if (/exists/i.test(e.message)) await xmrRpcCall("open_wallet", { filename: name, password: files[w.address]?.pw || pw });
    else throw e;
  }
  files[w.address] = { file: name, pw }; save();
}
async function xmrNewEntry(role = "receive") {
  const m = await xmrKeysLib();
  const NETC = settings().xmrStage ? m.MoneroNetworkType.STAGENET : m.MoneroNetworkType.MAINNET;
  const w = await m.MoneroWalletKeys.createWallet({ networkType: NETC, language: "English" });
  let restoreHeight = 0;
  try { restoreHeight = Math.max(0, (await xmrDaemonHeight()) - 100); } catch { console.log(c.warn("  ⚠ daemon unreachable — restore height 0 (first sync will be slow)")); }
  const n = XW().filter(x => x.role === "receive").length;
  return { label: role === "main" ? "xmr-main" : `xmr-in-${n + 1}`, role,
           address: await w.getPrimaryAddress(), viewKey: await w.getPrivateViewKey(),
           spendKey: await w.getPrivateSpendKey(), seed: await w.getSeed(), restoreHeight };
}
async function cmdXmr(args) {
  const sub = args[0] || "list";
  if (sub === "create") {
    let n = parseInt(args[1], 10);
    if (!Number.isInteger(n) || n < 1)
      n = (await P({ type: "number", name: "v", message: "How many Monero addresses?", initial: 3, min: 1, max: 100 })).v;
    const created = [];
    if (!XW().some(w => w.role === "main")) { const e = await xmrNewEntry("main"); XW().push(e); created.push(e); }
    for (let i = 0; i < n; i++) { const e = await xmrNewEntry("receive"); XW().push(e); created.push(e); }
    save();
    header(`MONERO — ${settings().xmrStage ? c.warn("STAGENET") : "MAINNET"}`);
    console.log(c.ok(`✓ ${created.length} wallet${created.length > 1 ? "s" : ""} created (keys local, restore height from remote node)`));
    table(["#", "LABEL", "ROLE", "ADDRESS"],
      created.map((w, i) => [`#${XW().length - created.length + i}`, w.label, w.role, w.address]));
    const main = created.find(x => x.role === "main");
    if (main) {
      console.log(c.warn(`\n⚠  The FIRST wallet is your Monero MAIN — backup this 25-word seed on paper:`));
      if (!state.autoYes) {
        if (await confirm("Reveal it now?")) console.log(c.bold(`\n  ${main.seed}\n`));
        await P({ type: "text", name: "_", message: c.dim("Press Enter to clear the screen…") });
        console.clear();
      } else console.log(c.dim(`  (--yes mode: copy the seed NOW from 'xmr phrase xmr:0' — it stays in the encrypted vault)`));
    }
    console.log(c.dim("Balance & sends need the wallet engine: ravenne xmr install → ravenne xmr engine"));
    return;
  }
  if (sub === "list") {
    header(`MONERO${settings().xmrStage ? c.warn(" · STAGENET") : ""}`);
    let engine = false;
    try { await xmrRpcCall("get_version"); engine = true; } catch {}
    console.log(c.dim(`  engine: ${engine ? c.ok("running at " + XMR_RPC()) : c.warn("not running (xmr install → xmr engine, or xmr connect)")}\n`));
    if (!XW().length) return console.log(c.dim("  No Monero wallet yet — ravenne xmr create"));
    if (!engine) {
      table(["#", "LABEL", "ROLE", "ADDRESS", "RESTORE HT"],
        XW().map((w, i) => [`#${i}`, w.label, w.role, w.address, w.restoreHeight]));
      return console.log(c.dim("\n  Start the engine to see balances."));
    }
    const rows = [];
    for (const w of XW()) {
      try {
        await xmrOpenWallet(w);
        const b = await xmrRpcCall("get_balance", { account_index: 0 });
        rows.push([`#${XW().indexOf(w)}`, w.label, w.role, w.address, fmtXmr(b.balance), fmtXmr(b.unlocked_balance)]);
      } catch (e) { rows.push([`#${XW().indexOf(w)}`, w.label, w.role, w.address, `err: ${e.message.slice(0, 20)}`, ""]); }
    }
    table(["#", "LABEL", "ROLE", "ADDRESS", "BALANCE", "SPENDABLE"], rows, { align: [null, null, null, null, "r", "r"] });
    return;
  }
  if (sub === "balance") return cmdXmr(["list"]);
  if (sub === "send") {
    await xmrRequireEngine();
    let [fromA, toA, amtA] = [args[1], args[2], args[3]];
    if (fromA == null || toA == null || amtA == null) {
      const r = await P([
        { type: "text", name: "f", message: `From which XMR wallet? (0-${XW().length - 1})` },
        { type: "text", name: "t", message: "To? (xmr address, index or label)" },
        { type: "text", name: "a", message: "Amount in XMR (or max):" },
      ]);
      fromA = r.f; toA = r.t; amtA = r.a;
    }
    const from = findXmrWallet(fromA);
    if (from < 0) throw new Error(`XMR wallet not found: "${fromA}"`);
    const src = XW()[from];
    if (!src.spendKey) throw new Error(`${src.label} is watch-only — it cannot sign.`);
    let toAddr = String(toA).trim();
    const i = findXmrWallet(toAddr);
    if (i >= 0) toAddr = XW()[i].address;
    if (!/^[48][1-9A-HJ-NP-Za-km-z]{94,105}$/.test(toAddr)) throw new Error("Invalid Monero address.");
    await xmrOpenWallet(src);
    const bal = await xmrRpcCall("get_balance", { account_index: 0 });
    const atomic = /^max$/i.test(amtA) ? bal.unlocked_balance : parseXmr(amtA);
    if (atomic <= 0n) throw new Error("Invalid amount.");
    if (bal.unlocked_balance <= atomic) throw new Error(`Insufficient unlocked balance: ${fmtXmr(bal.unlocked_balance)} XMR.`);
    box("SEND MONERO" + (settings().xmrStage ? " · STAGENET" : ""), [
      `From      xmr#${from} ${src.label}  ${short(src.address)}`,
      `To        ${short(toAddr)}`,
      `Amount    ${fmtXmr(atomic)} XMR`,
    ]);
    if (!(await confirm("Confirm and broadcast?"))) return console.log("Cancelled.");
    const res = await spin("Signing & broadcasting via remote node…", () =>
      xmrRpcCall("transfer", { destinations: [{ amount: atomic.toString(), address: toAddr }], priority: 0, get_tx_key: true }));
    cur().history.push({ t: new Date().toISOString(), net: "xmr", from: src.address, to: toAddr,
      amount: fmtXmr(atomic), fee: fmtXmr(res.fee), hash: res.tx_hash });
    save();
    console.log(c.ok(`\n✓ Sent! tx ${res.tx_hash.slice(0, 18)}… (fee ${fmtXmr(res.fee)} XMR)`));
    if (XMR.ex) console.log(c.dim(`   ↗ ${XMR.ex}/tx/${res.tx_hash}`));
    console.log(c.dim("  (explorer shows the tx once mined — amounts stay hidden forever)"));
    return;
  }
  if (sub === "forward") {
    await xmrRequireEngine();
    const main = XW().find(w => w.role === "main");
    if (!main) throw new Error("No XMR main — xmr create first.");
    const recv = XW().filter(w => w.role === "receive");
    if (!recv.length) return console.log(c.dim("No receiving XMR wallets."));
    let done = 0;
    for (const w of recv) {
      if (done > 0) await countdown(5 + Math.floor(Math.random() * 25));
      try {
        await xmrOpenWallet(w);
        const bal = await xmrRpcCall("get_balance", { account_index: 0 });
        if (bal.unlocked_balance < 500000000000n) continue;   // dust skip (<0.5 XMR)
        console.log(c.dim(`→ ${w.label} → xmr-main: ${fmtXmr(bal.unlocked_balance)} XMR…`));
        const res = await xmrRpcCall("sweep_all", { address: main.address, priority: 0, get_tx_key: true });
        (Array.isArray(res.tx_hash_list) ? res.tx_hash_list : [res.tx_hash]).forEach(h =>
          cur().history.push({ t: new Date().toISOString(), net: "xmr", from: w.address, to: main.address,
            amount: fmtXmr(bal.unlocked_balance), fee: fmtXmr(res.fee_list?.[0] ?? 0), hash: h }));
        save(); done++;
        console.log(c.ok(`   ✓ forwarded (tx ${(Array.isArray(res.tx_hash_list) ? res.tx_hash_list[0] : res.tx_hash)?.slice(0, 16)}…)`));
      } catch (e) { console.log(c.warn(`  ⚠ ${w.label}: ${e.message.slice(0, 60)}`)); }
    }
    return done ? console.log(c.ok(`\n✅ ${done} XMR wallet${done > 1 ? "s" : ""} forwarded to xmr-main.`))
                : console.log(c.dim("\nNothing to forward (all dust/empty)."));
  }
  if (sub === "watch") {
    let addr = args[1], vk = args[2], label = args[3];
    if (!addr || !vk) {
      const r = await P([
        { type: "text", name: "a", message: "Monero address (4…/8…/5…):" },
        { type: "text", name: "v", message: "Private VIEW key (read-only — never the spend key):" },
        { type: "text", name: "l", message: "Label:" },
      ]);
      addr = r.a; vk = r.v; label = r.l;
    }
    if (!/^[485][1-9A-HJ-NP-Za-km-z]{94,105}$/.test(addr)) throw new Error("Invalid Monero address.");
    XW().push({ label: label || `xmr-watch-${XW().length + 1}`, role: "watch", address: addr, viewKey: vk, restoreHeight: 0 }); save();
    return console.log(c.ok(`✓ Watch-only XMR wallet added (balance via engine, sends disabled).`));
  }
  if (sub === "phrase") {
    const i = findXmrWallet(args[1] ?? "");
    if (i < 0) throw new Error(`XMR wallet not found.`);
    const w = XW()[i];
    if (!w.seed) return console.log(c.warn("Watch-only wallet — no seed stored."));
    console.log(c.warn(`\n⚠  Monero seed of #${i} ${w.label} — never show this to anyone:`));
    if (!(await confirm("Reveal anyway?"))) return console.log("Cancelled.");
    console.log(c.bold(`\n  ${w.seed}\n`));
    if (!state.autoYes) { await P({ type: "text", name: "_", message: c.dim("Press Enter to clear the screen…") }); console.clear(); }
    return;
  }
  if (sub === "remove") {
    const i = findXmrWallet(args[1] ?? "");
    if (i < 0) throw new Error(`XMR wallet not found.`);
    if (!(await confirm(`Remove XMR wallet #${i} ${XW()[i].label}?`))) return console.log("Cancelled.");
    XW().splice(i, 1); save();
    return console.log(c.ok("✓ Removed (indexes shifted)."));
  }
  if (sub === "install") {
    fs.mkdirSync(XMR_DIR, { recursive: true });
    const exe = path.join(XMR_DIR, "monero-wallet-rpc.exe");
    if (fs.existsSync(exe) && !args[1]) return console.log(c.ok(`✓ Engine already installed: ${exe}`));
    console.log(c.dim("Fetching official hash list from getmonero.org…"));
    const hl = await (await fetch("https://www.getmonero.org/downloads/hashes.txt", { signal: AbortSignal.timeout(20000) })).text();
    const line = hl.split("\n").find(l => /monero-win-x64-v[\d.]+\.zip/.test(l));
    if (!line) throw new Error("hash list unavailable — download manually from getmonero.org/downloads");
    const [hash, zipName] = line.trim().split(/\s+/).reverse();
    const zip = path.join(XMR_DIR, zipName);
    console.log(c.dim(`Downloading ${zipName} (~87 MB, official build)…`));
    const buf = Buffer.from(await (await fetch(`https://downloads.getmonero.org/cli/${zipName}`, { signal: AbortSignal.timeout(600000) })).arrayBuffer());
    const got = crypto.createHash("sha256").update(buf).digest("hex");
    if (got !== hash) throw new Error(`SHA-256 MISMATCH (got ${got}) — download NOT trusted, nothing extracted.`);
    fs.writeFileSync(zip, buf);
    console.log(c.ok(`✓ SHA-256 verified against getmonero.org: ${got.slice(0, 24)}…`));
    const { execSync } = await import("node:child_process");
    execSync(`python -c "import zipfile,shutil;z=zipfile.ZipFile(r'${zip.replace(/\\/g, "/")}');src=[n for n in z.namelist() if n.endswith('monero-wallet-rpc.exe')][0];z.extract(src);shutil.move(src,'monero-wallet-rpc.exe')"`,
             { cwd: XMR_DIR, stdio: "ignore" });
    fs.unlinkSync(zip);
    console.log(c.ok(`✓ monero-wallet-rpc installed: ${exe}`));
    console.log(c.warn(`\n⚠  Windows Defender often flags the OFFICIAL Monero binary as a false positive`));
    console.log(c.warn(`   (PUA/CryptoMiner heuristics). If the file disappears, restore it from Defender`));
    console.log(c.warn(`   protection history and add "${XMR_DIR}" to exclusions. The SHA-256 was verified`));
    console.log(c.warn(`   against getmonero.org — the binary is authentic. Verify yourself if unsure.`));
    console.log(c.dim("\nStart it: ravenne xmr engine"));
    return;
  }
  if (sub === "engine") {
    const exe = path.join(XMR_DIR, "monero-wallet-rpc.exe");
    if (!fs.existsSync(exe)) throw new Error("Engine not installed — ravenne xmr install (or 'xmr connect' to a remote one).");
    const auth = `${crypto.randomBytes(6).toString("hex")}:${crypto.randomBytes(8).toString("hex")}`;
    settings().xmrRpcAuth = auth; save();
    fs.mkdirSync(path.join(XMR_DIR, "wallets"), { recursive: true });
    const { spawn } = await import("node:child_process");
    const child = spawn(exe, ["--daemon-address", XMR_DAEMON(), "--rpc-bind-port", "18083",
      "--rpc-login", auth, "--wallet-dir", path.join(XMR_DIR, "wallets"), "--untrusted-daemon", "--log-level", "0"],
      { detached: true, stdio: "ignore" });
    child.unref();
    await sleep(4000);
    await xmrRpcCall("get_version");
    return console.log(c.ok(`✓ Engine running (localhost:18083, private login) — daemon: ${XMR_DAEMON()}`));
  }
  if (sub === "connect") {
    if (!args[1] || args[1] === "reset") {
      delete settings().xmrRpc; delete settings().xmrRpcAuth; save();
      return console.log(c.ok(`✓ Engine endpoint reset to default ${XMR_RPC()}`));
    }
    if (!/^https?:\/\//.test(args[1])) throw new Error("Usage: xmr connect http://host:18083 [user:pass]");
    settings().xmrRpc = args[1];
    settings().xmrRpcAuth = args[2] || null; save();
    try { await xmrRpcCall("get_version"); console.log(c.ok(`✓ Connected to wallet engine at ${args[1]}`)); }
    catch { console.log(c.warn(`⚠ Saved ${args[1]} — but no engine answered yet.`)); }
    return;
  }
  if (sub === "node") {
    if (!args[1] || args[1] === "reset") { delete settings().xmrDaemon; save(); return console.log(c.ok(`✓ Daemon reset to ${XMR_DAEMON()}`)); }
    settings().xmrDaemon = args[1].replace(/\/json_rpc\/?$/, ""); save();
    try {
      const h = await xmrDaemonHeight();
      console.log(c.ok(`✓ Remote daemon: ${args[1]} (height ${h})`));
    } catch { console.log(c.warn(`⚠ Saved ${args[1]} — but it did not answer get_info.`)); }
    return;
  }
  if (sub === "network") {
    if (args[1] === "stage" || args[1] === "test") { settings().xmrStage = true; save(); return console.log(c.warn("✓ Monero → STAGENET (practice, fake XMR)")); }
    if (args[1] === "main") { settings().xmrStage = false; save(); return console.log(c.ok("✓ Monero → MAINNET")); }
    return console.log(`Monero network: ${settings().xmrStage ? "stagenet" : "mainnet"} — switch: ravenne xmr network stage|main`);
  }
  if (sub === "status") {
    let ok = false; try { await xmrRpcCall("get_version"); ok = true; } catch {}
    return console.log(ok ? c.ok(`Engine: ${XMR_RPC()} · ${XW().length} XMR wallets`)
                          : c.dim(`No engine at ${XMR_RPC()} · ${XW().length} XMR wallets · install: xmr install`));
  }
  throw new Error(`Unknown xmr sub-command: ${sub} (create | list | send | forward | watch | phrase | remove | install | engine | connect | node | network | status)`);
}

/* ═══════════════════════════ SWAP (Uniswap V2, Ethereum) ═══════════════════════════ */
const V2 = {
  router: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
  weth:   "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
};
const V2_ABI = [
  "function getAmountsOut(uint amountIn, address[] path) view returns (uint[] amounts)",
  "function swapExactETHForTokens(uint amountOutMin, address[] path, address to, uint deadline) payable returns (uint[] amounts)",
  "function swapExactTokensForETH(uint amountIn, uint amountOutMin, address[] path, address to, uint deadline) returns (uint[] amounts)",
  "function swapExactTokensForTokens(uint amountIn, uint amountOutMin, address[] path, address to, uint deadline) returns (uint[] amounts)",
];
function resolveAsset(s) {
  s = String(s).trim();
  if (/^eth$/i.test(s)) return { native: true, sym: "ETH", dec: 18 };
  const t = tokensOf("eth").find(x => x.sym.toLowerCase() === s.toLowerCase()) ||
            (s.startsWith("0x") ? { sym: short(s), addr: getAddress(s), dec: null } : null);
  if (!t) throw new Error(`Unknown asset "${s}" (ETH, USDT, USDC or a token address).`);
  return { ...t, native: false };
}
/* Core swap execution (Uniswap V2, Ethereum). Returns the confirmed receipt. */
async function execSwap(idx, from, to, amountIn) {
  const signer = new Wallet(W()[idx].privateKey).connect(provider());
  const routerC = new Contract(V2.router, V2_ABI, signer);
  const swapPath = from.native ? [V2.weth, to.addr] : to.native ? [from.addr, V2.weth] : [from.addr, to.addr];
  const preview = await routerC.getAmountsOut(amountIn, swapPath);
  const outMin = preview[preview.length - 1] * 99n / 100n;          // 1% slippage
  const deadline = Math.floor(Date.now() / 1000) + 1200;
  let tx;
  if (from.native) {
    tx = await spin("Swapping ETH → token…", () => routerC.swapExactETHForTokens(outMin, swapPath, W()[idx].address, deadline, { value: amountIn }));
  } else {
    const erc = new Contract(from.addr, ERC20_ABI, signer);
    if ((await erc.allowance(W()[idx].address, V2.router)) < amountIn) {
      const ap = await spin("Approving token spend…", () => erc.approve(V2.router, amountIn));
      await ap.wait();
    }
    tx = to.native
      ? await spin("Swapping token → ETH…", () => routerC.swapExactTokensForETH(amountIn, outMin, swapPath, W()[idx].address, deadline))
      : await spin("Swapping token → token…", () => routerC.swapExactTokensForTokens(amountIn, outMin, swapPath, W()[idx].address, deadline));
  }
  const rc = await spin("Waiting for confirmation…", () => tx.wait());
  const gasPrice = rc.effectiveGasPrice ?? tx.gasPrice ?? tx.maxFeePerGas ?? 0n;
  const fee = BigInt(rc.gasUsed) * BigInt(gasPrice);
  cur().history.push({ t: new Date().toISOString(), net: "eth", from: W()[idx].address, to: "uniswap:v2",
    amount: (from.native ? fmtAmt(amountIn) : fmtUnits(amountIn, from.dec)), fee: formatEther(fee), hash: rc.hash,
    token: `swap ${from.sym}→${to.sym}` });
  save();
  return { block: rc.blockNumber, fee, hash: rc.hash };
}

/* Conversion rule: everything forwarded on a chain is swapped first. */
async function cmdConvert(args) {
  const rules = (settings().convert ??= {});
  if (args.length === 0 || args[0] === "list") {
    header("CONVERT-ON-FORWARD RULES");
    const entries = Object.entries(rules).filter(([, r]) => r);
    if (!entries.length) console.log(c.dim("  No rule — funds are forwarded as-is."));
    else table(["CHAIN", "INCOMING", "FORWARDED AS"], entries.map(([k, r]) => [NET[k].label, r.from, r.to]));
    console.log(c.dim("\n  Set: ravenne convert eth ETH USDT   ·   Clear: ravenne convert eth off"));
    console.log(c.dim("  Applies to 'sweep' and the 'auto' daemon: incoming funds are swapped via"));
    console.log(c.dim("  Uniswap BEFORE reaching the main wallet (Ethereum mainnet only)."));
    return;
  }
  const k = NET_ALIASES[String(args[0]).toLowerCase()];
  if (!k) throw new Error(`Unknown chain: ${args[0]}`);
  if (args[1] === "off" || args[1] === "none") {
    delete rules[k]; save();
    return console.log(c.ok(`✓ ${NET[k].label}: conversion disabled — funds forwarded as-is.`));
  }
  if (k !== "eth") throw new Error("Conversion runs on Uniswap (Ethereum mainnet only).");
  const from = resolveAsset(args[1]), to = resolveAsset(args[2] ?? "");
  if (from.native && to.native) throw new Error("ETH → ETH makes no sense.");
  rules[k] = { from: from.sym, to: to.sym };
  save();
  console.log(c.ok(`✓ ${NET[k].label}: everything received will be converted ${from.sym} → ${to.sym} before reaching main.`));
  console.log(c.dim("  Each conversion pays the 0.3% pool fee + gas — sensible for meaningful amounts."));
}

async function cmdSwap(args) {
  if (netKey() !== "eth") throw new Error("Swaps run on Ethereum mainnet — switch first: ravenne network eth");
  let [fromA, toA, amtA, fromIdxA] = args;
  if (!fromA || !toA || !amtA) {
    const r = await P([
      { type: "text", name: "f", message: "Swap from: ETH, USDT, USDC or 0x…" },
      { type: "text", name: "t", message: "Swap to:   ETH, USDT, USDC or 0x…" },
      { type: "text", name: "a", message: "Amount to swap:" },
      { type: "text", name: "w", message: `From which wallet? (0-${W().length - 1})` },
    ]);
    fromA = r.f; toA = r.t; amtA = r.a; fromIdxA = r.w;
  }
  const from = resolveAsset(fromA), to = resolveAsset(toA);
  if (from.native && to.native) throw new Error("ETH → ETH makes no sense.");
  const idx = fromIdxA == null || fromIdxA === "" ? -1 : findWallet(fromIdxA);
  if (idx < 0) throw new Error(`Wallet not found: "${fromIdxA}"`);
  requireKey(idx);
  if (!from.native && from.dec == null) from.dec = Number(await new Contract(from.addr, ERC20_ABI, provider()).decimals());
  if (!to.native && to.dec == null) to.dec = Number(await new Contract(to.addr, ERC20_ABI, provider()).decimals());

  const signer = new Wallet(W()[idx].privateKey).connect(provider());
  const routerC = new Contract(V2.router, V2_ABI, signer);
  const amountIn = from.native ? parseEther(String(amtA).replace(",", ".")) : parseUnits(String(amtA).replace(",", "."), from.dec);
  if (amountIn <= 0n) throw new Error("Invalid amount.");
  const swapPath = from.native ? [V2.weth, to.addr] : to.native ? [from.addr, V2.weth] : [from.addr, to.addr];

  if (from.native) {
    const bal = await provider().getBalance(W()[idx].address);
    const per = await feePerTx(provider(), 250000n);
    if (bal < amountIn + per) throw new Error(`Insufficient ETH: ${fmtAmt(bal)} (need ${fmtAmt(amountIn + per)} incl. gas).`);
  } else {
    const erc = new Contract(from.addr, ERC20_ABI, signer);
    const bal = await erc.balanceOf(W()[idx].address);
    if (bal < amountIn) throw new Error(`Insufficient ${from.sym}: ${fmtUnits(bal, from.dec)}.`);
  }

  const preview = await spin("Querying Uniswap price…", () => routerC.getAmountsOut(amountIn, swapPath));
  const outMin = preview[preview.length - 1] * 99n / 100n;          // 1% slippage

  header("SWAP — Uniswap V2 · Ethereum");
  box("CONFIRM", [
    `Wallet    #${idx} ${W()[idx].label}  ${short(W()[idx].address)}`,
    `Sell      ${from.native ? fmtAmt(amountIn) : fmtUnits(amountIn, from.dec)} ${from.sym}`,
    `Receive ≥ ${to.native ? fmtAmt(outMin) : fmtUnits(outMin, to.dec)} ${to.sym}  (1% slippage)`,
    `Fees      0.3% pool fee + gas · deadline 20 min`,
  ]);
  if (!(await confirm("Confirm the swap?"))) return console.log("Cancelled.");

  const { block, fee, hash } = await execSwap(idx, from, to, amountIn);
  console.log(c.ok(`\n✓ Swap confirmed in block ${block} — gas ${fmtAmt(fee)} ETH`));
  printTxLink(hash, "eth");
  console.log(c.dim("  New balance: ravenne tokens · ravenne balance"));
}

const MENU_ACTIONS = {
  dashboard: cmdDashboard, list: cmdList, balance: cmdBalance, stats: cmdStats, history: cmdHistory,
  sync: cmdSync, csv: cmdCsv, price: cmdPrice, create: cmdCreate, import: cmdImport, watch: cmdWatch,
  ledger: cmdLedger, rename: cmdRename, phrase: cmdPhrase, export: cmdExport, remove: cmdRemove,
  send: cmdSend, split: cmdSplit, consolidate: cmdConsolidate, tokens: cmdTokens, book: cmdBook,
  qr: cmdQr, settings: cmdSettings, changepass: cmdChangePass, wipe: cmdWipe, btc: cmdBtc,
  usb: cmdUsb, swap: cmdSwap,
};
const MENU = {
  "Insight & data": ["dashboard", "list", "balance", "stats", "history", "sync", "csv", "price"],
  "Wallets": ["profile", "create", "import", "watch", "ledger", "temp", "rename", "phrase", "export", "remove", "qr"],
  "Transfers": ["send", "swap", "split", "consolidate"],
  "Bitcoin": ["btc-list", "btc-create", "btc-balance", "btc-send", "btc-watch", "btc-qr", "btc-phrase", "btc-sync", "btc-network"],
  "Monero (XMR)": ["xmr-list", "xmr-create", "xmr-balance", "xmr-send", "xmr-forward", "xmr-watch", "xmr-phrase", "xmr-install", "xmr-connect", "xmr-node", "xmr-network"],
  "USB & advanced": ["usb", "tokens", "book", "tx-prepare", "tx-sign", "tx-broadcast"],
  "Settings & security": ["network", "rpc", "settings", "changepass", "lock", "wipe"],
};
const MENU_TITLES = {
  dashboard: "Dashboard", list: "My wallets (list + balances)", balance: "Balances per chain",
  profile: "Wallet profiles (new / rename / delete)", temp: "New temporary address (burner)",
  stats: "Statistics", history: "Transaction history", sync: "Sync chain history (incoming txs)",
  csv: "Export history to CSV", price: "Live prices", create: "Create wallets (or from one seed)",
  import: "Import a wallet (MetaMask, keystore…)", watch: "Add watch-only wallet",
  ledger: "Add Ledger wallet (device)", rename: "Rename a wallet", phrase: "Reveal a seed phrase",
  export: "Export a keystore", remove: "Remove a wallet", qr: "Show address QR code",
  send: "Send (coin or ERC-20)", swap: "Swap coins (Uniswap: ETH ↔ USDT/USDC)", split: "Split a wallet into many", consolidate: "Consolidate everything into one",
  "btc-list": "Bitcoin wallets", "btc-create": "Create Bitcoin wallets",
  "btc-balance": "Bitcoin balances", "btc-send": "Send Bitcoin",
  "btc-watch": "Watch a BTC address", "btc-qr": "BTC address QR",
  "btc-phrase": "Reveal BTC seed phrase", "btc-sync": "Sync Bitcoin history",
  "btc-network": "BTC mainnet / testnet",
  "xmr-list": "Monero wallets (keys local, remote node)", "xmr-create": "Create Monero wallets (25-word seeds)",
  "xmr-balance": "Monero balances (needs engine)", "xmr-send": "Send Monero (untraceable by design)",
  "xmr-forward": "Forward receiving XMR to main", "xmr-watch": "Watch an XMR address (view key only)",
  "xmr-phrase": "Reveal an XMR seed phrase", "xmr-install": "Install wallet engine (official, hash-verified)",
  "xmr-connect": "Use an engine on another machine (e.g. Raspberry Pi)", "xmr-node": "Remote daemon settings",
  "xmr-network": "XMR mainnet / stagenet",
  usb: "USB wallet (create / open / close)",
  tokens: "ERC-20 tokens (balances, add, remove)", book: "Address book",
  "tx-prepare": "Offline: prepare unsigned tx", "tx-sign": "Offline: sign a tx file",
  "tx-broadcast": "Offline: broadcast a signed tx", network: "Switch chain", rpc: "RPC endpoints",
  settings: "Settings (prices, VPN check, auto-lock)", changepass: "Change master password",
  lock: "Lock session", wipe: "Wipe vault",
};
async function runAction(a) {
  try {
    if (a === "network") {
      const { k } = await P({ type: "select", name: "k", message: "Active chain:",
                              choices: Object.entries(NET).map(([k, v]) => ({ title: `${v.label} (${v.sym})`, value: k })) });
      await cmdNetwork([k]);
    } else if (a === "create") {
      const mode = (await P({ type: "select", name: "m", message: "Create how?",
        choices: [ { title: "Fresh random wallets", value: "fresh" }, { title: "Multiple accounts from ONE seed (BIP-44)", value: "seed" } ] })).m;
      await cmdCreate(mode === "seed" ? ["--seed"] : []);
    } else if (a === "rpc") await cmdRpc([]);
    else if (a === "lock") { await lockSession(); banner(); }
    else if (a?.startsWith("btc-")) await cmdBtc([a.slice(4)]);
    else if (a?.startsWith("xmr-")) await cmdXmr([a.slice(4)]);
    else await (MENU_ACTIONS[a] || (() => {}))([]);
  } catch (e) { console.log(c.err(`\n✗ ${e.message}`)); }
}
async function advancedMenu() {
  banner();
  let lastActive = Date.now();
  const CAT_DESC = {
    "Insight & data": "Balances, statistics, history and exports — read-only views of everything you own.",
    "Wallets": "Create, import, watch, rename or remove wallets; reveal seeds, export keystores, QR codes.",
    "Transfers": "Send, swap on Uniswap, split one wallet into many, or consolidate everything into one.",
    "Bitcoin": "BIP84 native-segwit wallets: create, balance, send, sync, mainnet/testnet.",
    "USB & advanced": "USB wallet, ERC-20 tokens, address book, offline (air-gapped) signing.",
    "Settings & security": "Chains, RPC endpoints, VPN/prices/auto-lock, password, lock, secure wipe.",
  };
  const SUB_DESC = {
    profile: "Several named wallets, one active at a time — pick at launch.",
    temp: "Burner receiving address: forwards to main at expiry, then keys are erased.",
    dashboard: "One-screen overview: totals, top wallets, recent activity.",
    list: "Every wallet with its balance on the active chain (or all chains).",
    balance: "Balances with totals and fiat values when prices are enabled.",
    stats: "Distribution bars, wealth stats, volumes and fees across chains.",
    history: "Merged view: transactions sent via Ravenne + synced from explorers.",
    sync: "Fetch incoming/outgoing transactions from public explorer APIs.",
    csv: "Export the full history to a CSV file (accounting, taxes).",
    price: "Live coin prices in USD/EUR (CoinGecko).",
    create: "New random wallets — or several accounts from one seed (BIP-44).",
    import: "Bring in an existing wallet: seed phrase, private key or keystore.",
    watch: "Track an address without holding its key (balances only).",
    ledger: "Add an address straight from a Ledger device (experimental).",
    rename: "Change a wallet's label.", phrase: "Reveal a seed phrase (screen clears after).",
    export: "Download a wallet as an encrypted keystore JSON (MetaMask-compatible).",
    remove: "Delete a wallet from the vault — recoverable only with its seed.",
    qr: "Display an address as a scannable QR code.",
    send: "Send coins or ERC-20 tokens to any address, wallet or book entry.",
    swap: "Convert ETH ↔ USDT/USDC via Uniswap with a price preview.",
    split: "Divide one wallet across several NEW wallets (random amounts optional).",
    consolidate: "Sweep every other wallet into a single target wallet.",
    usb: "Create or open an encrypted wallet stored on a USB stick.",
    tokens: "ERC-20 token balances and management (add/remove per chain).",
    book: "Named address book — labels usable as send targets.",
    "tx-prepare": "Air-gapped step 1: build an unsigned transaction file (online).",
    "tx-sign": "Air-gapped step 2: sign the file on the offline machine.",
    "tx-broadcast": "Air-gapped step 3: broadcast the signed file (online).",
    network: "Switch the active chain.", rpc: "Point chains at your own RPC nodes.",
    settings: "VPN gate, prices, auto-lock, sweep threshold.",
    changepass: "Change the master password (re-encrypts gate + vault).",
    lock: "Lock now — password required to continue.",
    wipe: "Securely erase the vault (3× overwrite + delete).",
  };
  const BTC_DESC = {
    "btc-list": "List BTC wallets and balances.", "btc-create": "New BTC wallets from a fresh 24-word seed.",
    "btc-balance": "Balances of all BTC wallets.", "btc-send": "Send BTC (bc1…) with fee estimate.",
    "btc-watch": "Watch a BTC address without keys.", "btc-qr": "QR code of a BTC address.",
    "btc-phrase": "Reveal the BTC seed phrase.", "btc-sync": "Fetch BTC history from Blockstream.",
    "btc-network": "Switch Bitcoin between mainnet and testnet.",
    "xmr-list": "Monero wallets and balances — keys never leave the vault.",
    "xmr-create": "Generate Monero wallets offline (25-word seed + restore height).",
    "xmr-balance": "Balances via the wallet engine connected to a remote node.",
    "xmr-send": "Send XMR — Monero hides sender, receiver and amount by design.",
    "xmr-forward": "Sweep every receiving XMR address to the XMR main (random delays).",
    "xmr-watch": "Track an address with its view key only (no spending possible).",
    "xmr-phrase": "Show a Monero 25-word seed for paper backup.",
    "xmr-install": "Download the official wallet engine, SHA-256 verified vs getmonero.org.",
    "xmr-connect": "Use a monero-wallet-rpc running elsewhere (Raspberry Pi, server…).",
    "xmr-node": "Choose the remote daemon node that serves wallet requests.",
    "xmr-network": "Monero mainnet or stagenet (fake XMR for practice).",
  };
  while (true) {
    if (settings().autolockMin > 0 && Date.now() - lastActive > settings().autolockMin * 60000) await lockSession();
    statusLine();
    const { cat } = await P({
      type: "select", name: "cat", message: "Main menu:",
      choices: [...Object.keys(MENU).map(t => ({ title: t, value: t, description: CAT_DESC[t] })),
                { title: "Quit", value: "__quit", description: "Clear the screen and exit." }],
    });
    lastActive = Date.now();
    if (cat === "__quit") { console.clear(); console.log("Bye."); process.exit(0); }
    while (true) {
      const { a } = await P({
        type: "select", name: "a", message: `${cat}  →`,
        choices: [...MENU[cat].map(x => ({ title: MENU_TITLES[x] || x, value: x, description: SUB_DESC[x] || BTC_DESC[x] })),
                  { title: "←  Back", value: "__back", description: "Return to the category menu." }],
      });
      lastActive = Date.now();
      if (a === "__back") break;
      await runAction(a);
      if (!state.payload) ensureVault();
      await P({ type: "text", name: "_", message: c.dim("— Enter to continue —") });
      lastActive = Date.now();
      console.clear();
      console.log(c.vio("RAVENNE WALLET"));
    }
  }
}

const HELP = `Ravenne Wallet v${VERSION} — encrypted terminal wallet manager (EVM + Bitcoin)

WALLET PROFILES — several named wallets, one active per session
  (no command)                 Select which wallet to open (interactive)
  profile new|use|rename|delete <name>     Manage named wallets
  --profile <name>             Skip the selection screen

TEMPORARY ADDRESSES — burner receive addresses
  temp <duration> [n]          Duration like 30m, 12h, 3d (default 24h).
                               At expiry: auto-forward to main, keys erased.

SIMPLE MODE (default, no command)
  setup [n] [--keep-key]       Guided: 1 MAIN wallet + n receiving addresses.
                               Main seed stays on paper; receiving forward to it.
  addresses [n]                Show/add receiving addresses (give these out)
  sweep [--all]                Forward everything from receiving → main
  auto [minutes]               Auto-forward daemon (randomized intervals)
  (no command)                 Simple interactive menu — advanced: 'menu'

PRIVACY / SECURITY LAYERS
  VPN gate                     No connection without an active ANONYMITY VPN
                               (mesh VPNs like Radmin/Hamachi don't count).
                               (--no-vpn once · 'settings vpncheck off' forever)
  HTTPS_PROXY / ALL_PROXY      Route ALL traffic (RPC, explorers) via your tunnel
  usb create|open|close [path] Encrypted wallet on a USB stick (own password,
                               keys stay in RAM, never touch the local disk)
  swap ETH USDT 0.5 [wallet#]  Coin swap via Uniswap V2 (Ethereum mainnet)
  convert eth ETH USDT         Convert-on-forward: incoming funds are swapped
                               BEFORE reaching main (sweep + auto). 'off' to clear

MAINTENANCE
  backup [file]                Encrypted copy of the vault (store anywhere)
  restore <file>               Restore the vault from a backup
  export-key <n°>              Reveal a wallet's raw private key (careful!)
  check                        Diagnostics: VPN, RPC, gate/vault, environment
  settings                     + meshvpn on|off · sweepfee <mult>

Chains (EVM): eth · poly · bsc · arb · base · op · local (test)
Bitcoin: BIP84 native segwit (bc1…) — mainnet & testnet

Wallets (EVM)
  create [n] [--words 24]      Create n wallets (12/24-word seeds)
  create [n] --seed            n accounts derived from ONE seed phrase (BIP-44)
  import                       Import: seed (1 or many accounts), key, keystore
  watch <0x…> <label>          Watch-only wallet (balances yes, signing no)
  ledger [acct] [label]        Add a Ledger device address (optional pkgs)
  list [--all]                 Wallets + balances (all chains with --all)
  rename <i> <label> · remove <i> · phrase <i> · export <i> · qr <i>

Bitcoin
  btc create [n]               Create BTC wallets (24-word seed, BIP84)
  btc list · btc balance       Addresses & balances (Blockstream API)
  btc send <btc:i> <addr> <amt>   Send BTC (or "max")
  btc watch <addr> <label> · btc qr <btc:i> · btc phrase <btc:i>
  btc sync                     Fetch incoming/outgoing BTC history
  btc network main|test        Switch Bitcoin mainnet / testnet

Monero (XMR) — privacy coin: sender, receiver and amounts are hidden on-chain
  xmr create [n]               Generate XMR wallets locally (25-word seeds)
  xmr list | balance           Addresses & balances (engine required)
  xmr send <from> <to> <amt>   Send XMR (or "max") via remote node
  xmr forward                  Sweep receiving XMR addresses → xmr-main
  xmr watch <addr> <viewkey> <label>   View-only tracking
  xmr install                  Download official engine (SHA-256 vs getmonero.org)
  xmr engine                   Start the local engine (connects to REMOTE daemon)
  xmr connect <url> [user:pass]   Use an engine on another machine (Pi…)
  xmr node <url> | xmr network stage|main | xmr phrase | xmr remove

Transfers (EVM)
  send <from> <to> <amount>    Send coin (index/label/book/0x…, or "max")
  send … --token <SYM>         Send an ERC-20 token instead
  split <from> <n>             Split a wallet into n NEW wallets
        --random               Random share sizes (anti-clustering)
  consolidate <target>         Sweep ALL other wallets into <target>
        --delay <sec>          Pause between batch sends (anti time-clustering)

Tokens (ERC-20)
  tokens · tokens add <SYM> <addr> [dec] · tokens remove <SYM>

Address book
  book · book add <label> <0x…> · book remove <label>   (labels = send targets)

Insight
  dashboard · balance [--all] · stats [--all] · price
  history                      Sent + synced transactions (IN/OUT/SELF)
  sync                         Fetch incoming txs from explorer APIs
  export-csv [file]            Full history as CSV (accounting/taxes)

Offline signing (air-gapped, EVM)
  tx-prepare <from> <to> <amt> --file u.json   [ONLINE]
  tx-sign u.json <wallet#>                     [OFFLINE machine]
  tx-broadcast u.json.signed.json              [ONLINE, soon after]

Security & privacy
  changepass · lock · wipe     Master password · session lock · secure erase
  rpc [chain] [url|reset]      Use your own node (IP privacy)
  settings                     Prices on/off · auto-lock minutes
  network [chain]              eth · poly · bsc · arb · base · op · local

Flags: --yes · --all · --random · --delay <s> · --words 24 · --seed
       --token <SYM> · --file <path> · --keystore <file>
Scripting: RAVENNE_PASS=<password> (also RAVENNE_KEYPASS for keystores).

Examples:
  ravenne create 10
  ravenne send 0 alice 25 --token USDT
  ravenne btc create 2 && ravenne btc send btc:0 bc1q… 0.001
  ravenne split 0 5 --random --delay 30
  ravenne consolidate 2 --delay 15
  ravenne sync && ravenne export-csv

No command → interactive menu.`;

const ROUTES = {
  create: cmdCreate, import: cmdImport, watch: cmdWatch, ledger: cmdLedger,
  list: cmdList, dashboard: cmdDashboard, home: cmdDashboard, balance: cmdBalance,
  send: cmdSend, split: cmdSplit, consolidate: cmdConsolidate, tokens: cmdTokens,
  book: cmdBook, stats: cmdStats, history: cmdHistory, sync: cmdSync,
  "export-csv": cmdCsv, csv: cmdCsv, qr: cmdQr, phrase: cmdPhrase, export: cmdExport,
  rename: cmdRename, remove: cmdRemove, network: cmdNetwork, rpc: cmdRpc,
  settings: cmdSettings, price: cmdPrice, changepass: cmdChangePass, btc: cmdBtc,
  setup: cmdSetup, addresses: cmdAddresses, sweep: cmdSweep, auto: cmdAuto,
  simple: simpleMenu, usb: cmdUsb, swap: cmdSwap, convert: cmdConvert, xmr: cmdXmr,
  profile: cmdProfile, temp: cmdTemp,
  backup: cmdBackup, restore: cmdRestore, "export-key": cmdExportKey, check: cmdCheck,
  lock: async () => { await lockSession(false); console.log("Session locked — run a command to continue."); },
  wipe: cmdWipe,
  "tx-prepare": cmdTxPrepare, "tx-sign": cmdTxSign, "tx-broadcast": cmdTxBroadcast,
  menu: advancedMenu,
};

function parseArgs(argv) {
  const flags = { yes: false, all: false, random: false, delay: 0, words: 12, seed: false, token: null, file: null, keystore: null, keepKey: false, profile: null };
  const args = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--yes" || a === "-y") flags.yes = true;
    else if (a === "--all" || a === "-a") flags.all = true;
    else if (a === "--random" || a === "-r") flags.random = true;
    else if (a === "--seed") flags.seed = true;
    else if (a === "--keep-key") flags.keepKey = true;
    else if (a === "--delay") flags.delay = parseFloat(argv[++i]) || 0;
    else if (a === "--words") flags.words = parseInt(argv[++i], 10) === 24 ? 24 : 12;
    else if (a === "--token") flags.token = argv[++i];
    else if (a === "--file") flags.file = argv[++i];
    else if (a === "--keystore") flags.keystore = argv[++i];
    else if (a === "--no-vpn") flags.noVpn = true;
    else if (a === "--profile") flags.profile = argv[++i];
    else if (a.startsWith("--")) { /* unknown flag: ignored */ }
    else args.push(a);
  }
  return { args, flags };
}

async function main() {
  const { args, flags } = parseArgs(process.argv.slice(2));
  state.autoYes = flags.yes;
  state.flags = flags;
  await setupProxy();
  if (!args.length) {
    await unlockGate();
    ensureVault();
    await ensureVPN();
    if (TTY && !state.autoYes && !state.flags.profile) await pickProfile();
    else if (state.flags.profile) {
      if (!V().profiles[state.flags.profile]) { console.log(c.err(`Unknown profile: ${state.flags.profile}`)); process.exit(1); }
      V().active = state.flags.profile;
    }
    await purgeExpired();
    return simpleMenu();
  }
  if (args[0] === "menu") {
    await unlockGate();
    ensureVault();
    await ensureVPN();
    if (TTY && !state.autoYes && !state.flags.profile) await pickProfile();
    await purgeExpired();
    return advancedMenu();
  }
  if (["help", "-h", "--help"].includes(args[0])) { console.log(HELP); return; }
  const fn = ROUTES[args[0]];
  if (!fn) { console.log(c.err(`Unknown command: ${args[0]}
`)); console.log(HELP); process.exit(1); }
  await unlockGate();
  ensureVault();
  await ensureVPN();
  if (state.flags.profile) {
    if (!V().profiles[state.flags.profile]) { console.log(c.err(`Unknown profile: ${state.flags.profile}`)); process.exit(1); }
    V().active = state.flags.profile;
  }
  await purgeExpired(!TTY);
  await fn(args.slice(1));
}

/* Direct execution — including bundled .cjs and pkg .exe forms. */
const isMain = (() => {
  const a = process.argv[1] || "";
  try { if (import.meta.url === pathToFileURL(a).href) return true; } catch {}
  return /ravenne\.(mjs|cjs|exe)$/i.test(path.basename(a));
})();
if (isMain) main().catch(e => { console.error(c.err(`\n✗ ${e.shortMessage || e.message}`)); process.exit(1); });
