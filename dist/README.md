# Ravenne Wallet v6.4 — named wallet profiles + temporary addresses

Main wallet + auto-forwarding receiving addresses, **VPN-gated**, with
USB wallets, Uniswap swaps and a privacy-first design.

## What's new in v6.4 — profiles & temporary wallets

- **Named wallet profiles** — keep several important wallets side by side
  (`Principal`, `Trading`, `Savings`…). At every launch (after the password)
  a selection screen lists them with their contents; arrow-keys pick one.
  `profile new <name>` · `use` · `rename` · `delete` · flag `--profile <name>`
  skips the screen for scripts. Each profile holds its own EVM/BTC/XMR wallets,
  history and active chain. Existing vaults migrate automatically.
- **Temporary addresses** — `temp 12h 3` creates burner receiving addresses
  with a lifetime. At expiry they are **auto-forwarded to your main wallet,
  then their keys are erased** from the vault. Durations: `30m`, `12h`, `3d`.
- **Sober UI** — compact banner showing the active profile, less visual noise.
- Everything from v6.3 stays: Monero module, VPN gate, swaps, USB wallets…

## What was new in v6.3 — Monero (XMR) module

| Command | What it does |
|---|---|
| `xmr create [n]` | Generate Monero wallets **locally** (25-word seeds), restore height fetched from a remote node |
| `xmr list` / `balance` | Addresses & balances — the wallet **engine** (official monero-wallet-rpc, not a node) scans via a **remote daemon** |
| `xmr send <from> <to> <amt>` | Send XMR — sender, receiver and amount are hidden by design |
| `xmr forward` | Sweep receiving XMR addresses → xmr-main with random delays |
| `xmr watch <addr> <viewkey> <label>` | View-only tracking (no spend key held) |
| `xmr install` | Download the **official** engine binary, SHA-256 verified against getmonero.org (⚠ Windows Defender false-positive possible — hash is verified, see output) |
| `xmr engine` / `xmr connect <url>` | Start the engine locally, or use one on **another machine** (Raspberry Pi!) |
| `xmr node <url>` · `xmr network stage` | Remote daemon choice · stagenet for practice |

Architecture: keys never leave the vault · remote daemon only sees normal wallet requests ·
`npm i monero-javascript` needed for key generation (auto-detected, clear error otherwise).
Tested live: key generation + mnemonic roundtrip (mainnet `4…`/stagenet `5…`), remote-node height,
restore heights, engine install flow with hash verification. Real broadcasts need funds — start small on stagenet.

## What was new in v6.2

| Feature | Command |
|---|---|
| **Convert-on-forward** | `ravenne convert eth ETH USDT` — everything received on a receiving address is swapped via Uniswap BEFORE reaching the main wallet. Works with `sweep` and the `auto` daemon. `convert eth off` to disable, also in Settings. Tested both ways on a mainnet fork (3 ETH → 6251 USDT and 1500 USDT → 0.726 ETH delivered to main). |

## What was new in v6.1

| Feature | Command |
|---|---|
| **Strict VPN gate** | Mesh/LAN VPNs (Radmin, Hamachi, ZeroTier…) no longer count — only anonymity VPNs pass. Detected adapter is displayed. Override: `settings meshvpn on` |
| **Menu hints** | Every menu option shows a one-line description when highlighted |
| **Vault backup / restore** | `backup [file]` · `restore <file>` — encrypted copies, safety copy on restore |
| **Raw key export** | `export-key <n°>` — reveal a private key (double confirm, screen clears) |
| **Diagnostics** | `check` — VPN, RPC reachability, gate/vault health, proxy, environment |
| **More settings** | Sweep threshold (`sweepfee`), quick Settings menu, chain switch in simple mode |
| **UTF-8 launchers** | `chcp 65001` in all .bat files — no more glyph bugs on Windows consoles |

## What was new in v6

| Feature | Command |
|---|---|
| **VPN gate** | No connection leaves the machine without an active VPN (auto-detected). Retry loop, `--no-vpn` once, `settings vpncheck off` forever |
| **Proxy layer** | Set `HTTPS_PROXY` / `ALL_PROXY` → ALL traffic (RPC, explorers, prices) goes through your tunnel (VPN local proxy, Tor bridge…) |
| **USB wallet** | `usb create E:\` · `usb open E:\` · `usb close` — AES-256-GCM file with its own password, keys stay in RAM, **never written to the local disk** (proven by test) |
| **Coin swaps** | `swap ETH USDT 0.5 [wallet]` — Uniswap V2 on Ethereum (ETH ↔ USDT/USDC ↔ tokens), price preview, 1% slippage, one-time approve. Tested against real Uniswap on a mainnet fork |
| **Cleaner UI** | Emoji-free professional menus, new banner, console title, generated icon (`ravenne.ico`) |

## Simple mode (default: just run it)

`ravenne.bat` → guided setup: 1 **MAIN** wallet (seed on paper, optionally
watch-only = not even stored in the vault) + **receiving** addresses that
forward everything to main (`sweep`, or the randomized `auto` daemon).

Chains: Ethereum · Polygon · BNB · Arbitrum · Base · Optimism · Bitcoin (BIP84).

## Privacy & security layers (honest)

- ✅ VPN gate + optional proxy for every outbound request
- ✅ fresh address per payer, main never exposed, randomized forwarding
  (intervals ±50%, 5–30 s delays, 0–0.3% random retention)
- ✅ main seed can live on paper only — vault leak exposes nothing main
- ✅ USB wallets encrypted with their own password, RAM-only when open
- ✅ price lookups OFF by default · custom RPC per chain (`ravenne rpc`)
- ✅ auto-lock, secure wipe (3× overwrite), offline signing (`tx-*`)
- ✗ direct forwards remain visible on-chain — this raises the cost of casual
  clustering, it does not make crypto untraceable. Stronger third-party
  techniques are not integrated on purpose (legal risks in many countries).

## Build & share

`build.bat` → `ravenne-wallet-vX.Y.Z.zip` with a **standalone ravenne.exe**
(no Node.js needed; icon step self-heals if the packager rejects it),
single-file bundle, launcher, README. Ships with no vault, keys or password.

## Files

`ravenne.js` · `access.ravenne.json` (gate) · `vault.ravenne.json` (encrypted
vault) · `ravenne.bat` · `build.bat` + `make-icon.mjs` · `ravenne.ico`
