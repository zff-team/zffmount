// - STD
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::process::exit;
use std::path::PathBuf;
use std::fs::{File};




// - modules
mod fs;
mod constants;
mod addons;

// - internal
use fs::*;
use constants::*;
use addons::*;

use zff::{
    header::*,
};

// - external
use clap::{Parser, ArgEnum};
use signal_hook::{consts::{SIGINT, SIGHUP, SIGTERM}, iterator::Signals};
use log::{LevelFilter, info, error, warn};
use fuser::{MountOption};





#[derive(Parser, Clone)]
#[clap(about, version, author)]
pub struct Cli {
    /// The input files. This should be your zff image files. You can use this option multiple times.
    #[clap(short='i', long="inputfiles", global=true, required=false, multiple_values=true)]
    inputfiles: Vec<PathBuf>,

    /// The output format.
    #[clap(short='m', long="mount-point")]
    mount_point: PathBuf,

    /// The password(s), if the file(s) are encrypted. You can use this option multiple times to enter different passwords for different objects.
    #[clap(short='p', long="decryption-passwords", value_parser = parse_key_val::<String, String>)]
    decryption_passwords: Vec<(String, String)>,


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

fn open_files(args: &Cli) -> Vec<File> {
    let input_paths = &args.inputfiles.clone();
    let mut inputfiles = Vec::new();
    info!("Opening {} segment files.", inputfiles.len());
    for path in input_paths {
        let file = match File::open(path) {
            Ok(file) => file,
            Err(e) => {
                error!("{e}");
                exit(EXIT_STATUS_ERROR);
            },
        };
        inputfiles.push(file);
    }
    inputfiles
}

fn main() {
    let args = Cli::parse();

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

    let inputfiles = open_files(&args);
    let mut decryption_passwords = HashMap::new();
    for (obj_no, pw) in args.decryption_passwords {
        let obj_no = match obj_no.parse::<u64>() {
            Ok(no) => no,
            Err(e) => {
                error!("Could not parse object number {obj_no}: {e}");
                exit(EXIT_STATUS_ERROR);
            }
        };
        decryption_passwords.insert(obj_no, pw);
    }

    let overlay_fs = ZffFs::new(inputfiles, &decryption_passwords);

    /*
    let mut overlay_fs = match ZffOverlayFs::new(inputfiles.to_owned(), &args.decryption_passwords) {
        Ok(overlay_fs) => {
            info!("MOUNT: Overlay filesystem created successfully");
            overlay_fs
        },
        Err(e) => {
            error!("MOUNT: Could not create overlay filesystem: {e}");
            exit(EXIT_STATUS_ERROR);
        }
    };

    let mut object_fs_vec = Vec::new();
    for (object_number, object_type) in &overlay_fs.object_types_map {
        match object_type {
            ObjectType::Logical => {
                let mut files = Vec::new();
                for path in inputfiles {
                    let f = match File::open(path) {
                        Ok(f) => f,
                        Err(e) => {
                            let path_name = &path.to_string_lossy();
                            error!("MOUNT: Could not open file {path_name}: {e}");
                            exit(EXIT_STATUS_ERROR);
                        },
                    };
                    files.push(f);
                };
                match ZffLogicalObjectFs::new(files, *object_number, overlay_fs.passwords_per_object.get(object_number)) {
                    Ok(fs) => object_fs_vec.push(ZffObjectFs::Logical(fs)),
                    Err(e) => {
                        error!("MOUNT: could not create object filesystem for object number {object_number}: {e}");
                        exit(EXIT_STATUS_ERROR);
                    },
                };
            },
            ObjectType::Physical => {
                let mut files = Vec::new();
                for path in inputfiles {
                    let f = match File::open(path) {
                        Ok(f) => f,
                        Err(e) => {
                            let path_name = &path.to_string_lossy();
                            error!("MOUNT: Could not open file {path_name}: {e}");
                            exit(EXIT_STATUS_ERROR);
                        },
                    };
                    files.push(f);
                };
                match ZffPhysicalObjectFs::new(files, *object_number, overlay_fs.passwords_per_object.get(object_number)) {
                    Ok(fs) => object_fs_vec.push(ZffObjectFs::Physical(fs)),
                    Err(e) => {
                        error!("MOUNT: could not create object filesystem for object number {object_number}: {e}");
                        exit(EXIT_STATUS_ERROR);
                    },
                };
            },
        }
    }
    overlay_fs.remove_passwords();

    let mountpoint = PathBuf::from(&args.mount_point);
    let overlay_mountoptions = vec![MountOption::RW, MountOption::AllowOther, MountOption::FSName(String::from(ZFF_OVERLAY_FS_NAME))];
    let object_mountoptions = vec![MountOption::RO, MountOption::AllowOther, MountOption::FSName(String::from(ZFF_OBJECT_FS_NAME))];

    let undecryptable_objects = &overlay_fs.undecryptable_objects.clone();
    let overlay_session = match fuser::spawn_mount2(overlay_fs, &mountpoint, &overlay_mountoptions) {
        Ok(session) => session,
        Err(e) => {
            error!("MOUNT: could not mount overlay filesystem: {e}");
            exit(EXIT_STATUS_ERROR);
        }
    };
    for object_number in undecryptable_objects {
        warn!("MOUNT: object {object_number}: still encrypted and could not be mount! (Wrong or missing password?)"); 
    }

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
                        error!("MOUNT: could not mount object filesystem for object number {object_number}: {e}");
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
                        error!("MOUNT: could not mount object filesystem for object number {object_number}: {e}");
                        exit(EXIT_STATUS_ERROR);
                    },
                };
                object_fs_sessions.push(session);
            },
        }
        
    }

    let mut signals = match Signals::new([SIGINT, SIGHUP, SIGTERM]) {
        Ok(signals) => signals,
        Err(e) => {
            error!("MOUNT: {ERROR_SETTING_SIGNAL_HANDLER}{e}");
            exit(EXIT_STATUS_ERROR);
        },
    };
    let running = Arc::new(AtomicBool::new(false));
    let r = Arc::clone(&running);
    thread::spawn(move || {
        for sig in signals.forever() {
            warn!("UNMOUNT: Received shutdown signal {:?}. The filesystems will be unmounted, as soon as the resource is no longer busy.", sig);
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
    }*/
}