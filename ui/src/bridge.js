// Bridge: Tauri IPC when running in the shell, a complete MOCK when opened
// standalone in a browser (so every screen is testable without Rust).

const REAL = typeof window !== "undefined" && !!window.__TAURI_INTERNALS__;

async function invoke(cmd, args = {}) {
  if (REAL) return window.__TAURI_INTERNALS__.invoke(cmd, args);
  return mock(cmd, args);
}

/* ─────────── MOCK (browser testing) ─────────── */
const LS = {
  get(k, d) { const v = localStorage.getItem("rv-" + k); return v == null ? d : JSON.parse(v); },
  set(k, v) { localStorage.setItem("rv-" + k, JSON.stringify(v)); },
};

function mockHwid() {
  if (!LS.get("hwid")) {
    const hex = () => Math.floor(Math.random() * 65536).toString(16).padStart(4, "0").toUpperCase();
    LS.set("hwid", Array.from({ length: 4 }, () => hex() + hex()).join(""));
  }
  return LS.get("hwid");
}
function mockVault() {
  if (!LS.get("vault")) {
    const mk = (label, role, extra = {}) => {
      const w = requireEthers().Wallet.createRandom();
      return { label, address: w.address, privateKey: w.privateKey, role, ...extra };
    };
    LS.set("vault", {
      profiles: {
        default: { name: "default", network: "eth", history: [], chainTx: [],
          wallets: [mk("main", "main", { watchOnly: true }), mk("in-1", "receive"), mk("in-2", "receive")],
          btcWallets: [], xmrWallets: [] },
      },
      active: "default",
      settings: { prices: false, vpnCheck: true, autolockMin: 5, rpc: {}, tokens: {}, book: [], explorers: {}, btcTest: false,
                  privacy: { retainPermille: 3 }, seeds: {}, xmrRpc: null, xmrRpcAuth: null, xmrDaemon: null, xmrStage: false, xmrFiles: {} },
    });
  }
  return LS.get("vault");
}
function requireEthers() { return window.ethers; }

const MOCK_PASSWORD = "Demo12345";

async function mock(cmd, a) {
  switch (cmd) {
    case "app_info":
      return { version: "7.0.0-mock", dev: true, base_dir: "(browser mock)", vault: true, gate: true };
    case "load_ui_config": return LS.get("uiconfig", null);
    case "save_ui_config": LS.set("uiconfig", a.config); return;
    case "get_hwid": {
      const hw = mockHwid();
      return { hwid: hw, grouped: hw.match(/.{4}/g).join("-"), machine: "MOCK-PC", user: "tester",
               os: "Windows mock", components_present: [true, true, true] };
    }
    case "fetch_whitelist": {
      await new Promise(r => setTimeout(r, 600));
      const list = LS.get("whitelist", { machines: [] });
      LS.set("whitelist-cache", list);
      return list;
    }
    case "cached_whitelist": return LS.get("whitelist-cache", null);
    case "check_local_flag": return LS.get("flag", null);
    case "write_local_flag": LS.set("flag", a.hwid); return;
    case "send_webhook": {
      await new Promise(r => setTimeout(r, 500));
      console.log("[mock webhook]", a.kind, a.hwid);
      return;
    }
    case "gate_verify": return a.password === MOCK_PASSWORD;
    case "vault_unlock": {
      if (a.password !== MOCK_PASSWORD) throw "WRONG_PASSWORD";
      return mockVault();
    }
    case "vault_write_encrypted": LS.set("vault", a.payload); return;
    case "vault_backup": return "(mock path)";
    case "vault_restore": {
      if (a.password !== MOCK_PASSWORD) throw "different password";
      return { restored: true };
    }
    case "vault_wipe": { if (a.password !== MOCK_PASSWORD) throw "WRONG_PASSWORD"; localStorage.clear(); return; }
    case "clipboard_copy_autoclear":
    case "clipboard_copy": {
      try { await navigator.clipboard.writeText(a.text); } catch {}
      return;
    }
    case "open_terminal": return;
    case "set_close_to_tray": return;
    case "emit_lock": window.dispatchEvent(new CustomEvent("ravenne://lock")); return;
    default: throw "mock: unknown command " + cmd;
  }
}

/* ─────────── updater (plugin) avec mock ─────────── */
async function checkUpdate(repo) {
  if (!REAL) {
    const last = LS.get("lastVersion", "7.0.0");
    return { available: last !== "7.0.0", version: "7.0.1", notes: "(mock changelog)" };
  }
  try {
    const { check } = await import("@tauri-apps/plugin-updater");
    return await check();
  } catch { return null; }
}
async function installUpdate(upd) {
  if (!REAL) { LS.set("lastVersion", upd.version); return; }
  await upd.downloadAndInstall();
  const { relaunch } = await import("@tauri-apps/plugin-process");
  await relaunch();
}
function openReleases(repo) {
  const url = `https://github.com/${repo || "OWNER/REPO"}/releases`;
  if (REAL) window.__TAURI_INTERNALS__.invoke("plugin:opener|open_url", { url });
  else window.open(url, "_blank");
}

export const bridge = { REAL, invoke, checkUpdate, installUpdate, openReleases, mockPassword: MOCK_PASSWORD };
