// Ravenne Wallet — desktop shell (Tauri v2)
// Gate HWID, whitelist, webhook Discord, verification du mot de passe (scrypt,
// STRICTEMENT compatible avec le CLI), dechiffrement du coffre (AES-256-GCM),
// lancement du terminal, presse-papiers a effacement differe, backup/wipe.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Salt statique integre au binaire — separe du sel aleatoire du coffre.
/// Ce verrou est une barriere de confort, pas de la cryptographie (cf README-UI.md).
const GATE_SALT: &str = "ravenne-gate::v1::static-salt::7f3a-92c1";
const UA: &str = "RavenneShell/7.0";

/* ---------- chemins : cherche vault.ravenne.json autour de l'exe ---------- */
fn base_dir() -> PathBuf {
    let exe = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf));
    let mut dir = exe.clone();
    for _ in 0..5 {
        if let Some(d) = &dir {
            if d.join("vault.ravenne.json").exists() || d.join("access.ravenne.json").exists() {
                return d.clone();
            }
            dir = d.parent().map(Path::to_path_buf);
        } else { break; }
    }
    if cfg!(debug_assertions) {
        if let Ok(m) = std::env::var("CARGO_MANIFEST_DIR") {
            return PathBuf::from(m).parent().unwrap().to_path_buf();
        }
    }
    exe.unwrap_or_else(|| std::env::current_dir().unwrap_or_default())
}

fn vault_path() -> PathBuf { base_dir().join("vault.ravenne.json") }
fn gate_path() -> PathBuf { base_dir().join("access.ravenne.json") }
fn flag_path() -> PathBuf { base_dir().join("authorized.flag") }
fn config_path() -> PathBuf { base_dir().join("ui.config.json") }
fn whitelist_cache() -> PathBuf { base_dir().join(".whitelist-cache.json") }

/* ---------- commandes utilitaires ---------- */

#[tauri::command]
fn app_info() -> Value {
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "dev": cfg!(debug_assertions),
        "base_dir": base_dir().to_string_lossy(),
        "vault": vault_path().exists(),
        "gate": gate_path().exists(),
    })
}

#[tauri::command]
fn load_ui_config() -> Option<Value> {
    fs::read_to_string(config_path()).ok().and_then(|s| serde_json::from_str(&s).ok())
}

#[tauri::command]
fn save_ui_config(config: Value) -> Result<(), String> {
    fs::write(config_path(), serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    harden(&config_path());
    Ok(())
}

/* ---------- HWID : SHA-256(salt + MachineGuid + baseboard + disque systeme) ---------- */

fn ps(query: &str) -> String {
    std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", query])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .ok()
        .and_then(|o| Some(String::from_utf8_lossy(&o.stdout).trim().to_string()))
        .unwrap_or_default()
}

fn machine_guid() -> String {
    std::process::Command::new("reg")
        .args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
        .creation_flags(0x08000000)
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).lines().find(|l| l.contains("MachineGuid")).map(|l| l.split_whitespace().last().unwrap_or("").to_string()))
        .unwrap_or_default()
}

use std::os::windows::process::CommandExt;
use tauri::{Emitter, Manager};
use aes_gcm::AeadInPlace;
use aes_gcm::aead::generic_array::GenericArray;

fn hardware_fingerprint() -> (String, String, String, String) {
    let guid = machine_guid();
    let board = ps("(Get-CimInstance Win32_BaseBoard).SerialNumber");
    let disk = ps("(Get-CimInstance Win32_DiskDrive | Where-Object Index -eq 0).SerialNumber");
    let host = std::env::var("COMPUTERNAME").unwrap_or_default();
    (guid, board, disk, host)
}

fn hwid_hex() -> String {
    let (guid, board, disk, _) = hardware_fingerprint();
    let mut h = Sha256::new();
    h.update(GATE_SALT.as_bytes());
    h.update(guid.as_bytes());
    h.update(b"|");
    h.update(board.as_bytes());
    h.update(b"|");
    h.update(disk.trim().as_bytes());
    hex::encode(h.finalize()).to_uppercase()
}

#[tauri::command]
fn get_hwid() -> Value {
    let (guid, board, disk, host) = hardware_fingerprint();
    let full = hwid_hex();
    let grouped: Vec<String> = (0..4).map(|i| full[i * 8..i * 8 + 8].to_string()).collect();
    let grouped: Vec<String> = grouped.iter().map(|b| format!("{}-{}", &b[0..4], &b[4..8])).collect();
    json!({
        "hwid": full,
        "grouped": grouped.join("-"),
        "machine": host,
        "user": std::env::var("USERNAME").unwrap_or_default(),
        "os": format!("Windows {} ({})", std::env::var("OS").unwrap_or_else(|_| "Windows".into()),
                      std::env::var("PROCESSOR_ARCHITECTURE").unwrap_or_default()),
        "components_present": [!guid.is_empty(), !board.is_empty(), !disk.trim().is_empty()],
    })
}

/* ---------- whitelist distante + cache ---------- */

#[tauri::command]
async fn fetch_whitelist(url: String) -> Result<Value, String> {
    let client = reqwest::Client::builder().user_agent(UA).timeout(Duration::from_secs(12)).build().map_err(|e| e.to_string())?;
    let resp = client.get(&url).send().await.map_err(|e| format!("network: {e}"))?;
    if !resp.status().is_success() { return Err(format!("http {}", resp.status())); }
    let body: Value = resp.json().await.map_err(|e| format!("json: {e}"))?;
    // cache pour les demarrages hors ligne
    let _ = fs::write(whitelist_cache(), serde_json::to_string_pretty(&body).unwrap_or_default());
    Ok(body)
}

#[tauri::command]
fn cached_whitelist() -> Option<Value> {
    fs::read_to_string(whitelist_cache()).ok().and_then(|s| serde_json::from_str(&s).ok())
}

#[tauri::command]
fn check_local_flag() -> Option<String> {
    fs::read_to_string(flag_path()).ok().map(|s| s.trim().to_string())
}

#[tauri::command]
fn write_local_flag(hwid: String) -> Result<(), String> {
    fs::write(flag_path(), hwid.trim()).map_err(|e| e.to_string())?;
    harden(&flag_path());
    Ok(())
}

fn harden(p: &Path) {
    let user = std::env::var("USERNAME").unwrap_or_default();
    if user.is_empty() { return; }
    let _ = std::process::Command::new("icacls")
        .arg(p)
        .args(["/inheritance:r", &format!("{}:F", user)])
        .creation_flags(0x08000000)
        .output();
}

/* ---------- webhook Discord (embeds propres) ---------- */

#[derive(Serialize)]
struct EmbedField { name: String, value: String, inline: bool }
#[derive(Serialize)]
struct Embed { title: String, description: String, color: i64, fields: Vec<EmbedField>, footer: Footer }
#[derive(Serialize)]
struct Footer { text: String }
#[derive(Serialize)]
struct WhBody { username: String, embeds: Vec<Embed> }

#[tauri::command]
async fn send_webhook(url: String, kind: String, label: String, hwid: String) -> Result<(), String> {
    if url.trim().is_empty() { return Err("webhook URL empty".into()); }
    let green = 0x2ea043; let red = 0xd93f3c;
    let (title, color, desc) = match kind.as_str() {
        "authorized" => ("✅ Machine autorisée", green, "Une machine autorisée a ouvert Ravenne Wallet."),
        _ => ("🔒 Demande d'accès", red, "Une machine non autorisée a tenté d'ouvrir Ravenne Wallet."),
    };
    let (host, user, os, _) = hardware_fingerprint();
    let body = WhBody {
        username: "Ravenne Gate".into(),
        embeds: vec![Embed {
            title: title.into(),
            description: desc.into(),
            color,
            fields: vec![
                EmbedField { name: "Label".into(), value: if label.is_empty() { "—".into() } else { label }, inline: true },
                EmbedField { name: "Machine".into(), value: if host.is_empty() { "—".into() } else { host }, inline: true },
                EmbedField { name: "User".into(), value: std::env::var("USERNAME").unwrap_or_else(|_| "—".into()), inline: true },
                EmbedField { name: "OS".into(), value: os, inline: false },
                EmbedField { name: "HWID".into(), value: format!("`{hwid}`"), inline: false },
            ],
            footer: Footer { text: "Ravenne Gate".into() },
        }],
    };
    let client = reqwest::Client::builder().user_agent(UA).timeout(Duration::from_secs(12)).build().map_err(|e| e.to_string())?;
    client.post(&url).json(&body).send().await.map_err(|e| format!("network: {e}"))?;
    Ok(())
}

/* ---------- gate + vault : STRICTEMENT compatible avec le CLI (node crypto) ---------- */

const SCRYPT_N: u32 = 16384; const SCRYPT_R: u32 = 8; const SCRYPT_P: u32 = 1;

fn scrypt_key(pass: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = scrypt::Params::new(14, SCRYPT_R, SCRYPT_P, 32).map_err(|e| e.to_string())?;
    let mut out = [0u8; 32];
    scrypt::scrypt(pass.as_bytes(), salt, &params, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[tauri::command]
fn gate_verify(password: String) -> bool {
    let Some(meta) = fs::read_to_string(gate_path()).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()) else { return false; };
    let salt = match hex::decode(meta["salt"].as_str().unwrap_or("")) { Ok(s) => s, Err(_) => return false };
    let hash = match hex::decode(meta["hash"].as_str().unwrap_or("")) { Ok(s) => s, Err(_) => return false };
    match scrypt_key(&password, &salt) { Ok(k) => ct_eq(&k, &hash), Err(_) => false }
}

#[tauri::command]
fn vault_unlock(password: String) -> Result<Value, String> {
    let meta: Value = serde_json::from_str(&fs::read_to_string(vault_path()).map_err(|_| "vault missing".to_string())?)
        .map_err(|_| "vault corrupt".to_string())?;
    let salt = hex::decode(meta["salt"].as_str().unwrap_or("")).map_err(|_| "salt")?;
    let iv = hex::decode(meta["iv"].as_str().unwrap_or("")).map_err(|_| "iv")?;
    let tag = hex::decode(meta["tag"].as_str().unwrap_or("")).map_err(|_| "tag")?;
    let data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, meta["data"].as_str().unwrap_or("")).map_err(|_| "data")?;
    let key = scrypt_key(&password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "key")?;
    let mut buf = data;
    let nonce: &aes_gcm::Nonce<_> = GenericArray::from_slice(&iv);
    let tg: &aes_gcm::Tag<_> = GenericArray::from_slice(&tag);
    cipher.decrypt_in_place_detached(nonce, b"", &mut buf, tg)
        .map_err(|_| "WRONG_PASSWORD")?;
    let parsed: Value = serde_json::from_str(&String::from_utf8_lossy(&buf)).map_err(|e| e.to_string())?;
    Ok(parsed)
}

#[tauri::command]
fn vault_write_encrypted(password: String, payload: Value) -> Result<(), String> {
    // meme format que le CLI (v7): scrypt + AES-256-GCM, tag separe
    let salt: [u8; 16] = rand_bytes16();
    let iv = { let mut b = [0u8; 12]; getrandom::getrandom(&mut b).expect("csprng"); b };
    let key = scrypt_key(&password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "key")?;
    let plain = serde_json::to_string(&payload).map_err(|e| e.to_string())?;
    let nonce: &aes_gcm::Nonce<_> = GenericArray::from_slice(&iv);
    let sealed = cipher.encrypt(nonce, plain.as_bytes()).map_err(|e| e.to_string())?;
    let (ct, tag) = sealed.split_at(sealed.len() - 16);
    let out = json!({
        "app": "ravenne", "v": 7,
        "salt": hex::encode(salt), "iv": hex::encode(iv),
        "tag": hex::encode(tag), "data": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ct),
    });
    fs::write(vault_path(), serde_json::to_string_pretty(&out).unwrap()).map_err(|e| e.to_string())
}

fn rand_bytes16() -> [u8; 16] {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("csprng");
    b
}

#[tauri::command]
fn vault_backup(dest: Option<String>) -> Result<String, String> {
    let p = vault_path();
    if !p.exists() { return Err("no vault".into()); }
    let name = format!("ravenne-backup-{}.json", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis());
    let dest = dest.unwrap_or_else(|| p.with_file_name(name).to_string_lossy().to_string());
    fs::copy(&p, &dest).map_err(|e| e.to_string())?;
    Ok(dest)
}

#[tauri::command]
fn vault_restore(file: String, password: String) -> Result<Value, String> {
    // verifie que la sauvegarde s'ouvre avec le mot de passe avant d'ecraser
    let raw = fs::read_to_string(&file).map_err(|e| e.to_string())?;
    let meta: Value = serde_json::from_str(&raw).map_err(|_| "corrupt")?;
    let salt = hex::decode(meta["salt"].as_str().unwrap_or("")).map_err(|_| "salt")?;
    let iv = hex::decode(meta["iv"].as_str().unwrap_or("")).map_err(|_| "iv")?;
    let tag = hex::decode(meta["tag"].as_str().unwrap_or("")).map_err(|_| "tag")?;
    let data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, meta["data"].as_str().unwrap_or("")).map_err(|_| "data")?;
    let key = scrypt_key(&password, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| "key")?;
    let mut buf = data;
    let nonce: &aes_gcm::Nonce<_> = GenericArray::from_slice(&iv);
    let tg: &aes_gcm::Tag<_> = GenericArray::from_slice(&tag);
    cipher.decrypt_in_place_detached(nonce, b"", &mut buf, tg)
        .map_err(|_| "different password")?;
    fs::copy(&file, vault_path()).map_err(|e| e.to_string())?;
    Ok(json!({"restored": true}))
}

#[tauri::command]
fn vault_wipe(password: String) -> Result<(), String> {
    let p = vault_path();
    if !p.exists() { return Err("no vault".into()); }
    // confirmation par le mot de passe: wipe securise 3 x overwrite (comme le CLI)
    let payload = vault_unlock(password.clone())?;
    let _ = payload;
    let size = fs::metadata(&p).map_err(|e| e.to_string())?.len() as usize;
    let mut fh = fs::OpenOptions::new().write(true).open(&p).map_err(|e| e.to_string())?;
    use std::io::{Seek, SeekFrom, Write};
    for _ in 0..3 {
        let mut i = 0usize;
        while i < size {
            let rnd = rand_bytes16();
            let n = (size - i).min(rnd.len());
            fh.seek(SeekFrom::Start(i as u64)).map_err(|e| e.to_string())?;
            fh.write_all(&rnd[..n]).map_err(|e| e.to_string())?;
            i += n;
        }
        fh.sync_all().map_err(|e| e.to_string())?;
    }
    drop(fh);
    fs::remove_file(&p).map_err(|e| e.to_string())?;
    let _ = fs::remove_file(flag_path());
    Ok(())
}

/* ---------- presse-papiers a effacement differe ---------- */

#[tauri::command]
fn clipboard_copy_autoclear(text: String, clear_after_secs: u64) -> Result<(), String> {
    let text2 = text.clone();
    let secs = clear_after_secs.max(1);
    std::thread::spawn(move || {
        if let Ok(mut cb) = arboard::Clipboard::new() {
            if cb.set_text(text2).is_ok() {
                std::thread::sleep(Duration::from_secs(secs));
                let _ = cb.clear();
            }
        }
    });
    Ok(())
}

#[tauri::command]
fn clipboard_copy(text: String) -> Result<(), String> {
    arboard::Clipboard::new().and_then(|mut c| c.set_text(text)).map_err(|e| e.to_string())
}

/* ---------- terminal ---------- */

#[tauri::command]
fn open_terminal(app_handle: tauri::AppHandle) -> Result<(), String> {
    use tauri::Manager;
    let base = base_dir();
    let exe = app_handle.path().resource_dir().map(|d| d.join("ravenne.exe")).ok();
    let prod = exe.as_ref().map(|p| p.exists()).unwrap_or(false);
    let script = if prod {
        let p = exe.unwrap();
        let dir = p.parent().map(|d| d.to_string_lossy().to_string()).unwrap_or_default();
        format!("cd /d \"{dir}\" && ravenne.exe")
    } else {
        format!("cd /d \"{}\" && node ravenne.js", base.to_string_lossy())
    };
    std::process::Command::new("cmd")
        .args(["/C", "start", "Ravenne Terminal", "cmd", "/K", &script])
        .creation_flags(0x08000000)
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Some(w) = app_handle.get_webview_window("main") { let _ = w.hide(); } // minimise vers le tray
    Ok(())
}

/* ---------- etat fenetre : fermer -> tray ---------- */

struct AppState { close_to_tray: std::sync::Mutex<bool> }

/* ---------- run ---------- */

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            use tauri::Manager;
            if let Some(w) = app.get_webview_window("main") { let _ = w.show(); let _ = w.set_focus(); }
        }))
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(AppState { close_to_tray: std::sync::Mutex::new(true) })
        .invoke_handler(tauri::generate_handler![
            app_info, load_ui_config, save_ui_config,
            get_hwid, fetch_whitelist, cached_whitelist, check_local_flag, write_local_flag,
            send_webhook, gate_verify, vault_unlock, vault_write_encrypted,
            vault_backup, vault_restore, vault_wipe,
            clipboard_copy, clipboard_copy_autoclear, open_terminal,
            set_close_to_tray, emit_lock,
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let state: tauri::State<AppState> = window.app_handle().state();
                if *state.close_to_tray.lock().unwrap() {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .setup(|app| {
            let tray_menu = tauri::menu::MenuBuilder::new(app)
                .text("open", "Ouvrir Ravenne")
                .text("lock", "Verrouiller")
                .separator()
                .text("quit", "Quitter")
                .build()?;
            let _ = tauri::tray::TrayIconBuilder::new()
                .icon(app.default_window_icon().cloned().unwrap())
                .menu(&tray_menu)
                .on_menu_event(|app, ev| {
                    use tauri::Manager;
                    match ev.id().as_ref() {
                        "open" => { if let Some(w) = app.get_webview_window("main") { let _ = w.show(); let _ = w.set_focus(); } }
                        "lock" => { if let Some(w) = app.get_webview_window("main") { let _ = w.show(); let _ = w.set_focus(); let _ = w.emit("ravenne://lock", ()); } }
                        "quit" => { app.exit(0); }
                        _ => {}
                    }
                })
                .show_menu_on_left_click(true)
                .build(app)?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Ravenne");
}

#[tauri::command]
fn set_close_to_tray(app_handle: tauri::AppHandle, value: bool) {
    let state: tauri::State<AppState> = app_handle.state();
    *state.close_to_tray.lock().unwrap() = value;
}

#[tauri::command]
fn emit_lock(app_handle: tauri::AppHandle) {
    use tauri::Manager;
    if let Some(w) = app_handle.get_webview_window("main") { let _ = w.emit("ravenne://lock", ()); }
}

