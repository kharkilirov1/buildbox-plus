//! `bb-install` — signs an IPA with a free Apple ID and installs it over USB.
//!
//! This is the PC fallback for BuildBox Plus: when the phone is connected to the
//! PC it can sign and install without the GUI iLoader application, reusing the
//! credentials and certificate that iLoader already stored in the Windows
//! Credential Manager (`service = "iloader"`).
//!
//! Usage:
//!   bb-install --ipa BuildBox-fork.ipa --apple-id user@example.com [--list-certs]
//!              [--machine-name "machine name from --list-certs"] [--device UDID]
//!
//! The Apple ID password is taken from `BB_APPLE_PASSWORD`, else from the saved
//! iLoader credential, else typed interactively. Two-factor codes are typed
//! interactively (the same prompts iLoader uses).

use std::future::Ready;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use idevice::usbmuxd::{UsbmuxdAddr, UsbmuxdConnection};
use isideload::{
    anisette::remote_v3::RemoteV3AnisetteProvider,
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::{
        certificates::CertificatesApi, developer_session::DeveloperSession, teams::TeamsApi,
    },
    sideload::{
        builder::{ExtensionsBehavior, ExtensionsBehaviorSelection, MaxCertsBehavior},
        SideloaderBuilder, TeamSelection,
    },
    util::{
        callbacks::{ExtensionsBehaviorCallbackBox, MaxCertsCallbackBox},
        keyring_storage::KeyringStorage,
        storage::SideloadingStorage,
    },
};
use rootcause::prelude::*;

fn print_help() {
    eprintln!(
        "bb-install — sign an IPA with a free Apple ID and install it over USB\n\n\
         USAGE:\n  bb-install --ipa <path> --apple-id <email> [options]\n\n\
         OPTIONS:\n\
         \x20 --ipa <path>             IPA to sign and install (required unless --list-certs)\n\
         \x20 --apple-id <email>       Apple ID e-mail (required)\n\
         \x20 --machine-name <name>    machine name used by the certificate (use --list-certs to see it)\n\
         \x20 --check-device           only list connected iOS devices (no Apple ID login)\n         \x20 --list-certs             only list developer certificates, then exit\n\
         \x20 --device <udid>          pick a specific connected device\n\
         \x20 --service <name>         Windows credential service (default: iloader)\n\
         \x20 --help                   show this help\n\n\
         ENV:\n  BB_APPLE_PASSWORD        Apple ID password (otherwise read from the saved credential)"
    );
}

fn read_line(prompt: &str) -> Result<String, Report> {
    eprint!("{prompt}");
    io::stderr().flush().ok();
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn prompt_password() -> Result<String, Report> {
    eprintln!("Apple ID password (input is visible — the saved credential was not found):");
    read_line("Password: ")
}

fn prompt_two_factor(params: TwoFactorCallbackParams) -> Result<TwoFactorCallbackResponse, Report> {
    let mut message = String::new();
    if let Some(last_error) = &params.last_error {
        message.push_str(&format!("Last attempt failed: {last_error}\n"));
    }
    message.push_str(if params.unknown {
        "Two-factor authentication: choose a method and enter the code\n"
    } else if params.sms {
        "Enter the SMS verification code\n"
    } else {
        "Enter the verification code sent to your Apple devices\n"
    });
    if !params.numbers.is_empty() {
        for number in &params.numbers {
            message.push_str(&format!(
                "  ID {}: {} (···{}){}\n",
                number.id,
                number.number_with_dial_code,
                number.last_two_digits,
                if Some(number.id) == params.selected_number_id { " [selected]" } else { "" }
            ));
        }
        message.push_str("  p<id> — send SMS to that number\n");
    }
    if params.unknown || params.sms {
        message.push_str("  d — send the code to my devices\n");
    }
    if !params.unknown {
        message.push_str("  r — resend the code\n");
    }
    eprintln!("{message}");

    loop {
        let input = read_line("Code: ")?;
        if input.is_empty() {
            continue;
        }
        if input == "d" {
            return Ok(TwoFactorCallbackResponse::SendToDevices);
        }
        if input == "r" && !params.unknown {
            return Ok(TwoFactorCallbackResponse::ResendCode);
        }
        if let Some(id) = input.strip_prefix('p').and_then(|value| value.parse::<u32>().ok()) {
            return Ok(TwoFactorCallbackResponse::SendSms(id));
        }
        return Ok(TwoFactorCallbackResponse::SubmitCode(input));
    }
}

async fn connected_devices() -> Result<Vec<idevice::usbmuxd::UsbmuxdDevice>, Report> {
    let mut connection = UsbmuxdConnection::default().await?;
    Ok(connection.get_devices().await?)
}
async fn run() -> Result<(), Report> {
    let mut ipa: Option<String> = None;
    let mut apple_id: Option<String> = None;
    let mut machine_name: Option<String> = None;
    let mut service = "iloader".to_string();
    let mut list_certs = false;
    let mut device_udid: Option<String> = None;
    let mut check_device_only = false;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--ipa" => ipa = args.next(),
            "--apple-id" => apple_id = args.next(),
            "--machine-name" => machine_name = args.next(),
            "--service" => service = args.next().unwrap_or(service),
            "--device" => device_udid = args.next(),
            "--list-certs" => list_certs = true,
            "--check-device" => check_device_only = true,
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            other => {
                print_help();
                return Err(report!("unknown argument: {other}"));
            }
        }
    }

    if check_device_only {
        let devices = connected_devices().await?;
        if devices.is_empty() {
            println!("no devices found via usbmuxd");
        } else {
            for device in devices {
                println!("udid={} usbmuxd_id={} connection={:?}", device.udid, device.device_id, device.connection_type);
            }
        }
        return Ok(());
    }

    // Fail before touching Apple services when no phone is connected.
    if !list_certs {
        let devices = connected_devices().await?;
        if devices.is_empty() {
            return Err(report!("no device found via usbmuxd — connect the iPhone and unlock it"));
        }
    }
    let apple_id = apple_id.ok_or_else(|| report!("--apple-id is required"))?;
    let storage = KeyringStorage::new(service.clone());

    let password = match std::env::var("BB_APPLE_PASSWORD") {
        Ok(value) if !value.is_empty() => value,
        _ => match storage.retrieve(&apple_id)? {
            Some(value) if !value.is_empty() => {
                eprintln!("Using the saved Apple ID password from the Windows Credential Manager ({service}).");
                value
            }
            _ => prompt_password()?,
        },
    };

    eprintln!("Signing in as {apple_id}…");
    let anisette = RemoteV3AnisetteProvider::default()?
        .set_storage(Box::new(KeyringStorage::new(service.clone())));
    let mut account = AppleAccount::builder(&apple_id)
        .anisette_provider(anisette)
        .login(&password, |params| async move { prompt_two_factor(params) })
        .await?;
    let mut dev_session = DeveloperSession::from_account(&mut account).await?;
    let teams = dev_session.list_teams().await?;
    let team = teams
        .into_iter()
        .next()
        .ok_or_else(|| report!("no developer teams for {apple_id}"))?;
    eprintln!(
        "Team: {} ({})",
        team.team_id,
        team.name.clone().unwrap_or_else(|| "<unnamed>".to_string())
    );

    if list_certs {
        let certs = dev_session.list_ios_certs(&team).await?;
        println!("certificates: {}", certs.len());
        for cert in certs {
            println!(
                "name={:?} machine_name={:?} machine_id={:?} serial={:?} status={:?} expires={:?}",
                cert.name,
                cert.machine_name,
                cert.machine_id,
                cert.serial_number,
                cert.status,
                cert.expiration_date
            );
        }
        return Ok(());
    }

    let ipa = ipa.ok_or_else(|| report!("--ipa is required"))?;
    if !PathBuf::from(&ipa).exists() {
        return Err(report!("IPA does not exist: {ipa}"));
    }
    let machine_name = machine_name.unwrap_or_else(|| "isideload".to_string());
    eprintln!("Signing with certificate machine name: {machine_name}");

    let mut sideloader =
        SideloaderBuilder::<MaxCertsCallbackBox, ExtensionsBehaviorCallbackBox>::new(
            dev_session,
            apple_id.clone(),
        )
        .team_selection(TeamSelection::First)
        .max_certs_behavior(MaxCertsBehavior::Error)
        .storage(Box::new(KeyringStorage::new(service)))
        .machine_name(machine_name)
        .extensions_behavior(ExtensionsBehaviorSelection::Fixed(
            ExtensionsBehavior::RegisterAll,
        ))
        .delete_app_after_install(true)
        .build();

    let mut usbmuxd = UsbmuxdConnection::default().await?;
    let devices = usbmuxd.get_devices().await?;
    if devices.is_empty() {
        return Err(report!(
            "no device found via usbmuxd — connect the iPhone and tap \"Trust\""
        ));
    }
    let device = match device_udid {
        Some(udid) => devices
            .into_iter()
            .find(|device| device.udid == udid)
            .ok_or_else(|| report!("device {udid} is not connected"))?,
        None => devices.into_iter().next().ok_or_else(|| report!("no device"))?,
    };
    eprintln!("Device: {} (usbmuxd id {})", device.udid, device.device_id);
    let provider = device.to_provider(UsbmuxdAddr::from_env_var()?, "buildbox-plus-pc");

    let progress = |value: f32| -> Ready<()> {
        eprintln!("sideload: {:.0}%", value * 100.0);
        std::future::ready(())
    };

    sideloader
        .install_app(&provider, PathBuf::from(&ipa), true, Some(progress), None)
        .await?;

    println!("installed: {ipa}");
    Ok(())
}

#[tokio::main]
async fn main() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = isideload::init();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    if let Err(error) = run().await {
        eprintln!("error: {error:?}");
        std::process::exit(1);
    }
}



