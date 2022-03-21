// - STD
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::process::exit;
use std::path::PathBuf;
use std::fs::{File};




// - modules
mod lib;

// - internal
use lib::fs::{version2::*, version1::*};
use zff::{
    header::*,
    ZffErrorKind,
};


use lib::constants::*;

// - external
use clap::{Parser, ArgEnum};
use signal_hook::{consts::{SIGINT, SIGHUP, SIGTERM}, iterator::Signals};
use log::{LevelFilter, info, error, warn};
use env_logger;
use fuser::{MountOption};





#[derive(Parser, Clone)]
#[clap(about, version, author)]
pub struct Cli {
    /// The input files. This should be your zff image files. You can use this option multiple times.
    #[clap(short='i', long="inputfiles", global=true, required=false)]
    inputfiles: Vec<String>,

    /// The output format.
    #[clap(short='m', long="mount-point")]
    mount_point: PathBuf,

    /// The password(s), if the file(s) are encrypted. You can use this option multiple times to enter different passwords for different objects.
    #[clap(short='p', long="decryption-password")]
    decryption_passwords: Vec<String>,

    /// The Loglevel
    #[clap(short='l', long="log-level", arg_enum, default_value="info")]
    log_level: LogLevel
}

#[derive(ArgEnum, Clone)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace
}

fn start_version1_fs(args: &Cli) {
    let inputfiles = &args.inputfiles.clone().into_iter().map(|i| PathBuf::from(i)).collect::<Vec<PathBuf>>();
    let mut files = Vec::new();
    for path in inputfiles {
        let f = match File::open(&path) {
            Ok(f) => f,
            Err(e) => {
                let path_name = &path.to_string_lossy();
                error!("Could not open file {path_name}: {e}");
                exit(EXIT_STATUS_ERROR);
            },
        };
        files.push(f);
    };
    let zff_fs = match ZffFS::new(files) {
        Ok(zff_fs) => zff_fs,
        Err(e) => match e.get_kind() {
            ZffErrorKind::MissingEncryptionKey => {
                if args.decryption_passwords.len() as u64 != 1 {
                    error!("{ERROR_MISSING_ENCRYPTION_KEY}");
                    exit(EXIT_STATUS_ERROR);

                }
                let password = &args.decryption_passwords[0];
                
                let mut files = Vec::new();
                for path in inputfiles {
                    let f = match File::open(&path) {
                        Ok(f) => f,
                        Err(e) => {
                            let path_name = &path.to_string_lossy();
                            error!("Could not open file {path_name}: {e}");
                            exit(EXIT_STATUS_ERROR);
                        },
                    };
                    files.push(f);
                };
                match ZffFS::new_encrypted(files, password) {
                    Ok(zff_fs) => zff_fs,
                    Err(e) => {
                        error!("{e}");
                        exit(EXIT_STATUS_ERROR);
                    }
                }
            },
            other @ _ => {
                error!("{other}");
                exit(EXIT_STATUS_ERROR);
            },
        }
    };
    let mountoptions = vec![MountOption::RO, MountOption::FSName(String::from(ZFF_VERSION1_IMAGE_FS_NAME))];
    let session = match fuser::spawn_mount2(zff_fs, &args.mount_point, &mountoptions) {
        Ok(session) => session,
        Err(e) => {
            error!("could not mount ZffFs filesystem: {e}");
            exit(EXIT_STATUS_ERROR);
        }
    };
    let mut signals = match Signals::new(&[SIGINT, SIGHUP, SIGTERM]) {
        Ok(signals) => signals,
        Err(e) => {
            error!("{ERROR_SETTING_SIGNAL_HANDLER}{e}");
            exit(EXIT_STATUS_ERROR);
        },
    };
    let running = Arc::new(AtomicBool::new(false));
    let r = Arc::clone(&running);
    thread::spawn(move || {
        for sig in signals.forever() {
            info!("Received shutdown signal {:?}. The filesystems will be unmounted, as soon as the resource is no longer busy.", sig);
            r.store(true, Ordering::SeqCst);
        }
    });

    loop {
        if running.load(Ordering::SeqCst) {
            session.join();
            exit(EXIT_STATUS_SUCCESS);
        }
    }

}

fn main() {
    let args = Cli::parse();

    //TODO: remove or use correctly
    let log_level = match args.log_level {
        LogLevel::Error => LevelFilter::Error,
        LogLevel::Warn => LevelFilter::Warn,
        LogLevel::Info => LevelFilter::Info,
        LogLevel::Debug => LevelFilter::Debug,
        LogLevel::Trace => LevelFilter::Trace,
    };
    env_logger::builder()
        .format_timestamp_nanos()
        .filter_level(log_level)
        .init();

    let inputfiles = &args.inputfiles.clone().into_iter().map(|i| PathBuf::from(i)).collect::<Vec<PathBuf>>();
    let overlay_fs = match ZffOverlayFs::new(inputfiles.to_owned(), &args.decryption_passwords) {
        Ok(overlay_fs) => {
            info!("could create overlay filesystem successfully");
            overlay_fs
        },
        Err(e) => {
            match e.get_kind() {
                ZffErrorKind::HeaderDecodeMismatchIdentifier => start_version1_fs(&args),
                _ => (),
            }
            error!("Could not build overlay filesystem: {e}");
            exit(EXIT_STATUS_ERROR);
        }
    };

    let mut object_fs_vec = Vec::new();
    for (object_number, object_type) in &overlay_fs.object_types_map {
        match object_type {
            ObjectType::Logical => {
                let mut files = Vec::new();
                for path in inputfiles {
                    let f = match File::open(&path) {
                        Ok(f) => f,
                        Err(e) => {
                            let path_name = &path.to_string_lossy();
                            error!("Could not open file {path_name}: {e}");
                            exit(EXIT_STATUS_ERROR);
                        },
                    };
                    files.push(f);
                };
                match ZffLogicalObjectFs::new(files, *object_number) {
                    Ok(fs) => {
                        if overlay_fs.undecryptable_objects.contains(object_number) {
                            warn!("object {object_number} is still encrypted and could not be mount!");
                        } else {
                            object_fs_vec.push(ZffObjectFs::Logical(fs));
                            info!("could create object filesystem for object {object_number} successfully");
                        }
                        info!("could create object filesystem for object {object_number} successfully");
                    },
                    Err(e) => {
                        error!("could not build object filesystem for object number {object_number}: {e}");
                        exit(EXIT_STATUS_ERROR);
                    },
                };
            },
            ObjectType::Physical => {
                let mut files = Vec::new();
                for path in inputfiles {
                    let f = match File::open(&path) {
                        Ok(f) => f,
                        Err(e) => {
                            let path_name = &path.to_string_lossy();
                            error!("Could not open file {path_name}: {e}");
                            exit(EXIT_STATUS_ERROR);
                        },
                    };
                    files.push(f);
                };
                match ZffPhysicalObjectFs::new(files, *object_number) {
                    Ok(fs) => {
                        if overlay_fs.undecryptable_objects.contains(object_number) {
                            warn!("object {object_number} is still encrypted and could not be mount!");
                        } else {
                            object_fs_vec.push(ZffObjectFs::Physical(fs));
                            info!("could create object filesystem for object {object_number} successfully");
                        }
                        info!("could create object filesystem for object {object_number} successfully");
                    },
                    Err(e) => {
                        error!("could not build object filesystem for object number {object_number}: {e}");
                        exit(EXIT_STATUS_ERROR);
                    },
                };
            },
        }
    }

    let mountpoint = PathBuf::from(&args.mount_point);
    let overlay_mountoptions = vec![MountOption::RW, MountOption::AllowOther, MountOption::FSName(String::from(ZFF_OVERLAY_FS_NAME))];
    let object_mountoptions = vec![MountOption::RO, MountOption::FSName(String::from(ZFF_OBJECT_FS_NAME))];

    let overlay_session = match fuser::spawn_mount2(overlay_fs, &mountpoint, &overlay_mountoptions) {
        Ok(session) => session,
        Err(e) => {
            error!("could not mount overlay filesystem: {e}");
            exit(EXIT_STATUS_ERROR);
        }
    };

    let mut object_fs_sessions = Vec::new();
    for object_fs in object_fs_vec {
        let mut inner_mountpoint = mountpoint.clone();
        match object_fs {
            ZffObjectFs::Physical(object_fs) => {
                let object_number = object_fs.object_number;
                inner_mountpoint.push(format!("{OBJECT_PREFIX}{object_number}"));
                let session = match fuser::spawn_mount2(object_fs, inner_mountpoint, &object_mountoptions) {
                    Ok(session) => session,
                    Err(e) => {
                        error!("could not mount object filesystem for object number {object_number}: {e}");
                        exit(EXIT_STATUS_ERROR);
                    },
                };
                object_fs_sessions.push(session);
            },
            ZffObjectFs::Logical(object_fs) => {
                let object_number = object_fs.object_number;
                inner_mountpoint.push(format!("{OBJECT_PREFIX}{object_number}"));
                let session = match fuser::spawn_mount2(object_fs, inner_mountpoint, &object_mountoptions) {
                    Ok(session) => session,
                    Err(e) => {
                        error!("could not mount object filesystem for object number {object_number}: {e}");
                        exit(EXIT_STATUS_ERROR);
                    },
                };
                object_fs_sessions.push(session);
            },
        }
        
    }

    let mut signals = match Signals::new(&[SIGINT, SIGHUP, SIGTERM]) {
        Ok(signals) => signals,
        Err(e) => {
            error!("{ERROR_SETTING_SIGNAL_HANDLER}{e}");
            exit(EXIT_STATUS_ERROR);
        },
    };
    let running = Arc::new(AtomicBool::new(false));
    let r = Arc::clone(&running);
    thread::spawn(move || {
        for sig in signals.forever() {
            info!("Received shutdown signal {:?}. The filesystems will be unmounted, as soon as the resource is no longer busy.", sig);
            r.store(true, Ordering::SeqCst);
        }
    });

    loop {
        if running.load(Ordering::SeqCst) {
            for session in object_fs_sessions {
                session.join();
            }
            overlay_session.join();
            exit(EXIT_STATUS_SUCCESS);
        }
    }
}