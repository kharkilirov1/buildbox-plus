//! C ABI bridge around the [`isideload`] engine for BuildBox.
//!
//! BuildBox (Swift, iOS) calls the functions below through
//! `bridge/include/buildbox_sideload.h` (imported by `src/Bridging.h`).
//!
//! Flow implemented here:
//!   bbs_init -> bbs_login (Apple ID + 2FA callback) -> bbs_sign_ipa
//!
//! All calls are blocking and must be made from a background thread on the
//! Swift side. Strings returned by the library must be released with
//! `bbs_string_free`.

use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr, CString};
use std::future::Ready;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use isideload::{
    anisette::remote_v3::RemoteV3AnisetteProvider,
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::{
        app_ids::AppIdsApi,
        developer_session::DeveloperSession,
        devices::DevicesApi,
        teams::{DeveloperTeam, TeamsApi},
    },
    sideload::{
        builder::{ExtensionsBehavior, ExtensionsBehaviorSelection, MaxCertsBehavior},
        cert_identity::CertificateIdentity,
        sideloader::Sideloader, SideloaderBuilder, TeamSelection,
    },
    util::{
        callbacks::{ExtensionsBehaviorCallbackBox, MaxCertsCallbackBox},
        fs_storage::FsStorage,
    },
};
use rootcause::prelude::*;
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// FFI plumbing
// ---------------------------------------------------------------------------

/// `(ctx, params_json, out_buf, out_cap) -> bytes_written | -1 cancelled | -2 buffer too small`
pub type TwoFactorCallbackFn =
    extern "C" fn(*mut c_void, *const c_char, *mut c_char, usize) -> isize;

/// `(ctx, progress_0_to_1)`
pub type ProgressCallbackFn = extern "C" fn(*mut c_void, f32);

#[derive(Clone, Copy)]
struct FfiCtx {
    cb: extern "C" fn(*mut c_void, *const c_char, *mut c_char, usize) -> isize,
    ctx: *mut c_void,
}

// The raw context pointer is owned by the Swift caller and is only touched
// synchronously on the calling thread; the wrapper just makes the type
// `Send`/`Sync` so it can be captured by isideload's async closures.
unsafe impl Send for FfiCtx {}
unsafe impl Sync for FfiCtx {}

type SideloaderT = Sideloader<MaxCertsCallbackBox, ExtensionsBehaviorCallbackBox>;

struct Session {
    email: String,
    machine_name: String,
    storage_dir: PathBuf,
    sideloader: SideloaderT,
}

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static SESSIONS: OnceLock<Mutex<HashMap<u64, Session>>> = OnceLock::new();
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("buildbox-sideload: tokio runtime")
    })
}

fn sessions() -> &'static Mutex<HashMap<u64, Session>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(|s| s.to_string())
}

fn string_to_c(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn ok_json(value: Value) -> *mut c_char {
    let mut obj = json!({ "ok": true });
    if let Some(map) = obj.as_object_mut() {
        if let Value::Object(extra) = value {
            for (k, v) in extra {
                map.insert(k, v);
            }
        }
    }
    string_to_c(obj.to_string())
}

fn err_json(message: impl std::fmt::Display) -> *mut c_char {
    string_to_c(json!({ "ok": false, "error": message.to_string() }).to_string())
}


// ---------------------------------------------------------------------------
// 2FA bridge
// ---------------------------------------------------------------------------

async fn two_factor_ffi(
    c: FfiCtx,
    params: TwoFactorCallbackParams,
) -> Result<TwoFactorCallbackResponse, Report> {
    let params_json = serde_json::to_string(&params).context("serialize 2FA params")?;
    let params_c = CString::new(params_json).context("2FA params contain NUL")?;

    let mut out = vec![0u8; 8192];
    let written = (c.cb)(
        c.ctx,
        params_c.as_ptr(),
        out.as_mut_ptr() as *mut c_char,
        out.len() - 1,
    );
    if written < 0 {
        return Err(report!("two-factor authentication cancelled by user"));
    }
    let written = written as usize;
    if written >= out.len() {
        return Err(report!("two-factor response buffer too small"));
    }
    let response_json = unsafe { CStr::from_ptr(out.as_ptr() as *const c_char) }
        .to_string_lossy()
        .to_string();
    let value: Value = serde_json::from_str(&response_json).context("parse 2FA response")?;
    let kind = value.get("type").and_then(Value::as_str).unwrap_or("");
    match kind {
        "code" => {
            let code = value
                .get("code")
                .and_then(Value::as_str)
                .ok_or_else(|| report!("2FA response missing code"))?;
            Ok(TwoFactorCallbackResponse::SubmitCode(code.to_string()))
        }
        "sendSms" => {
            let id = value
                .get("id")
                .and_then(Value::as_u64)
                .ok_or_else(|| report!("2FA response missing sms id"))?;
            Ok(TwoFactorCallbackResponse::SendSms(id as u32))
        }
        "sendToDevices" => Ok(TwoFactorCallbackResponse::SendToDevices),
        "resend" => Ok(TwoFactorCallbackResponse::ResendCode),
        _ => Err(report!("unknown 2FA response type")),
    }
}

// ---------------------------------------------------------------------------
// Exported API
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn bbs_version() -> *mut c_char {
    string_to_c(format!("buildbox-sideload/{}", env!("CARGO_PKG_VERSION")))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bbs_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn bbs_init() -> i32 {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = isideload::init();
    0
}

/// Log in to an Apple ID and keep the developer session under a handle.
///
/// * `storage_dir` - writable directory (app Documents) for anisette state and
///   the development certificate. Must exist.
///
/// Returns JSON: `{"ok":true,"handle":N,"email":"..."}` or
/// `{"ok":false,"error":"..."}`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bbs_login(
    email: *const c_char,
    password: *const c_char,
    storage_dir: *const c_char,
    machine_name: *const c_char,
    two_factor_cb: Option<TwoFactorCallbackFn>,
    ctx: *mut c_void,
) -> *mut c_char {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let email = cstr_to_string(email).ok_or_else(|| "email is null".to_string())?;
        let password = cstr_to_string(password).ok_or_else(|| "password is null".to_string())?;
        let storage_dir =
            cstr_to_string(storage_dir).ok_or_else(|| "storage_dir is null".to_string())?;
        let machine_name = cstr_to_string(machine_name).unwrap_or_else(|| "BuildBox".to_string());
        let cb = two_factor_cb.ok_or_else(|| "two_factor_cb is null".to_string())?;

        let storage_path = PathBuf::from(&storage_dir);
        if !storage_path.exists() {
            std::fs::create_dir_all(&storage_path)
                .map_err(|e| format!("cannot create storage dir: {e}"))?;
        }

        let rt = runtime();
        let handle = rt.block_on(async {
            let provider = RemoteV3AnisetteProvider::default()
                .map_err(|e| format!("anisette provider: {e:?}"))?
                .set_storage(Box::new(FsStorage::new(storage_path.clone())))
                .set_serial_number("BuildBox-iPhone".to_string());

            let ffi = FfiCtx { cb, ctx };
            let mut account = AppleAccount::builder(&email)
                .anisette_provider(provider)
                .login(&password, move |params: TwoFactorCallbackParams| {
                    let ffi = ffi;
                    async move { two_factor_ffi(ffi, params).await }
                })
                .await
                .map_err(|e| format!("login: {e:?}"))?;

            let dev_session = DeveloperSession::from_account(&mut account)
                .await
                .map_err(|e| format!("developer session: {e:?}"))?;

            let sideloader = SideloaderBuilder::<MaxCertsCallbackBox, ExtensionsBehaviorCallbackBox>::new(
                dev_session,
                email.clone(),
            )
            .team_selection(TeamSelection::First)
            .max_certs_behavior(MaxCertsBehavior::Error)
            .storage(Box::new(FsStorage::new(storage_path.clone())))
            .machine_name(machine_name.clone())
            .extensions_behavior(ExtensionsBehaviorSelection::Fixed(
                ExtensionsBehavior::RegisterAll,
            ))
            .delete_app_after_install(true)
            .build();

            Ok::<SideloaderT, String>(sideloader)
        })?;

        let handle_id = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);
        sessions().lock().unwrap().insert(
            handle_id,
            Session {
                email: email.clone(),
                machine_name,
                storage_dir: storage_path,
                sideloader: handle,
            },
        );

        Ok::<Value, String>(json!({ "handle": handle_id, "email": email }))
    }));

    match result {
        Ok(Ok(value)) => ok_json(value),
        Ok(Err(message)) => err_json(message),
        Err(panic) => err_json(format!("panic in bbs_login: {panic:?}")),
    }
}

/// List the Apple developer teams of the signed-in account.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bbs_list_teams(handle: u64) -> *mut c_char {
    let result = std::panic::catch_unwind(|| -> Result<Value, String> {
        let mut guard = sessions().lock().unwrap();
        let session = guard
            .get_mut(&handle)
            .ok_or_else(|| "unknown session handle".to_string())?;
        let dev_session = session.sideloader.get_dev_session();
        let teams: Vec<DeveloperTeam> = runtime()
            .block_on(dev_session.list_teams())
            .map_err(|e| format!("list teams: {e:?}"))?;
        let teams_json: Vec<Value> = teams
            .into_iter()
            .map(|t| json!({ "id": t.team_id, "name": t.name }))
            .collect();
        Ok(json!({ "teams": teams_json }))
    });

    match result {
        Ok(Ok(value)) => ok_json(value),
        Ok(Err(message)) => err_json(message),
        Err(panic) => err_json(format!("panic in bbs_list_teams: {panic:?}")),
    }
}

/// Export a signing identity (development certificate + provisioning profile)
/// for `bundle_id` using the signed-in Apple ID.
///
/// Returns JSON:
/// `{"ok":true,"p12_path":"...","provision_path":"...","password":"...","team_id":"...","app_id":"..."}`
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bbs_export_identity(
    handle: u64,
    bundle_id: *const c_char,
    app_name: *const c_char,
    device_udid: *const c_char,
    device_name: *const c_char,
    out_dir: *const c_char,
    p12_password: *const c_char,
) -> *mut c_char {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Value, String> {
        let bundle_id = cstr_to_string(bundle_id).ok_or_else(|| "bundle_id is null".to_string())?;
        let app_name = cstr_to_string(app_name).unwrap_or_else(|| bundle_id.clone());
        let udid = cstr_to_string(device_udid).ok_or_else(|| "device_udid is null".to_string())?;
        let device_name =
            cstr_to_string(device_name).unwrap_or_else(|| "BuildBox device".to_string());
        let out_dir = cstr_to_string(out_dir).ok_or_else(|| "out_dir is null".to_string())?;
        let password = cstr_to_string(p12_password).unwrap_or_else(|| "buildbox".to_string());

        let storage_path = PathBuf::from(&out_dir);
        std::fs::create_dir_all(&storage_path).map_err(|e| format!("cannot create out dir: {e}"))?;

        let mut guard = sessions().lock().unwrap();
        let session = guard
            .get_mut(&handle)
            .ok_or_else(|| "unknown session handle".to_string())?;
        let email = session.email.clone();
        let machine_name = session.machine_name.clone();
        let engine_storage = FsStorage::new(session.storage_dir.clone());

        let rt = runtime();
        let team = rt
            .block_on(session.sideloader.get_team())
            .map_err(|e| format!("get team: {e:?}"))?;
        let dev_session = session.sideloader.get_dev_session();
        rt.block_on(dev_session.ensure_device_registered(&team, &device_name, &udid, None))
            .map_err(|e| format!("register device: {e:?}"))?;

        let behavior: MaxCertsBehavior<MaxCertsCallbackBox> = MaxCertsBehavior::Error;
        let identity = rt
            .block_on(CertificateIdentity::retrieve(
                &machine_name,
                &email,
                dev_session,
                &team,
                &engine_storage,
                &behavior,
            ))
            .map_err(|e| format!("certificate: {e:?}"))?;
        let p12 = rt
            .block_on(identity.as_p12(&password))
            .map_err(|e| format!("p12 export: {e:?}"))?;

        let app_id = {
            let list = rt
                .block_on(dev_session.list_app_ids(&team, None))
                .map_err(|e| format!("list app ids: {e:?}"))?;
            match list.app_ids.into_iter().find(|a| a.identifier == bundle_id) {
                Some(id) => id,
                None => rt
                    .block_on(dev_session.add_app_id(&team, &app_name, &bundle_id, None))
                    .map_err(|e| format!("add app id: {e:?}"))?,
            }
        };

        let profile = rt
            .block_on(dev_session.download_team_provisioning_profile(&team, &app_id, None))
            .map_err(|e| format!("provisioning profile: {e:?}"))?;

        let p12_path = storage_path.join("identity.p12");
        let profile_path = storage_path.join("identity.mobileprovision");
        std::fs::write(&p12_path, &p12).map_err(|e| format!("write p12: {e}"))?;
        std::fs::write(&profile_path, profile.encoded_profile.as_ref())
            .map_err(|e| format!("write profile: {e}"))?;

        Ok(json!({
            "p12_path": p12_path.to_string_lossy().to_string(),
            "provision_path": profile_path.to_string_lossy().to_string(),
            "password": password,
            "team_id": team.team_id,
            "app_id": app_id.identifier,
        }))
    }));

    match result {
        Ok(Ok(value)) => ok_json(value),
        Ok(Err(message)) => err_json(message),
        Err(panic) => err_json(format!("panic in bbs_export_identity: {panic:?}")),
    }
}

/// Sign an IPA for the given device (UDID must be registered in the team).
///
/// Returns JSON: `{"ok":true,"signed_app_path":"/..."}`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bbs_sign_ipa(
    handle: u64,
    ipa_path: *const c_char,
    device_udid: *const c_char,
    device_name: *const c_char,
    increased_memory_limit: bool,
    progress_cb: Option<ProgressCallbackFn>,
    ctx: *mut c_void,
) -> *mut c_char {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Value, String> {
        let ipa = cstr_to_string(ipa_path).ok_or_else(|| "ipa_path is null".to_string())?;
        if !PathBuf::from(&ipa).exists() {
            return Err(format!("IPA does not exist: {ipa}"));
        }
        let udid = cstr_to_string(device_udid).unwrap_or_default();
        if udid.is_empty() {
            return Err("device_udid is required".to_string());
        }
        let device_name = cstr_to_string(device_name).unwrap_or_else(|| "BuildBox device".to_string());

        let mut guard = sessions().lock().unwrap();
        let session = guard
            .get_mut(&handle)
            .ok_or_else(|| "unknown session handle".to_string())?;

        let rt = runtime();
        let team = rt
            .block_on(session.sideloader.get_team())
            .map_err(|e| format!("get team: {e:?}"))?;

        rt.block_on(
            session
                .sideloader
                .get_dev_session()
                .ensure_device_registered(&team, &device_name, &udid, None),
        )
        .map_err(|e| format!("register device: {e:?}"))?;

        let progress_ctx = ctx;
        let progress = move |p: f32| -> Ready<()> {
            if let Some(cb) = progress_cb {
                cb(progress_ctx, p);
            }
            std::future::ready(())
        };

        let (signed_app_path, _special): (PathBuf, Option<isideload::sideload::application::SpecialApp>) = rt
            .block_on(session.sideloader.sign_app(
                PathBuf::from(&ipa),
                Some(team),
                increased_memory_limit,
                Some(progress),
                None,
                Some(&udid),
            ))
            .map_err(|e| format!("sign: {e:?}"))?;

        Ok(json!({ "signed_app_path": signed_app_path.to_string_lossy().to_string() }))
    }));

    match result {
        Ok(Ok(value)) => ok_json(value),
        Ok(Err(message)) => err_json(message),
        Err(panic) => err_json(format!("panic in bbs_sign_ipa: {panic:?}")),
    }
}

/// Drop a session handle and its in-memory state.
#[unsafe(no_mangle)]
pub extern "C" fn bbs_logout(handle: u64) -> i32 {
    match sessions().lock() {
        Ok(mut guard) => {
            guard.remove(&handle);
            0
        }
        Err(_) => -1,
    }
}



