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

// - external
use clap::{Parser, ArgEnum};
use signal_hook::{consts::{SIGINT, SIGHUP, SIGTERM}, iterator::Signals};
use log::{LevelFilter, info, error, warn, debug};
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
    log_level: LogLevel,

    /// Preload the chunkmap (in memory or in redb database e.g. at a fast NVMe drive) to speed up the read operations.  
    /// None: saves memory but the read operations are slower (default)   
    /// In memory: needs 24 bytes per chunk (plus a lot of bytes for additional overhead) to store the chunkmap in memory. This is the fastest option, but you need to ensure that you have enough memory.  
    /// redb: use a fast redb database to cache the chunkmap. This could e.g. be useful, if your container is stored at a slow harddrive but the redb database can be cached at a fast nvme drive.  
    #[clap(short='c', long="preload-chunkmap", arg_enum, default_value="none")]
    preload_chunkmap: PreloadChunkmapValue,

    #[clap(short='r', long="redb-path", required_if_eq("preload-chunkmap", "redb"))]
    redb_path: Option<PathBuf>,
}

#[derive(ArgEnum, Clone, Debug)]
enum PreloadChunkmapValue {
    None,
    InMemory,
    Redb,
}

#[derive(ArgEnum, Clone, Debug, PartialEq)]
enum LogLevel {
    Error,
    Warn,
    Info,
    FullInfo, //TODO: It should be described in the help page, what "FullInfo" and "FullDebug" exactly do.
    Debug,
    FullDebug,
    Trace
}

fn open_files(args: &Cli) -> Vec<File> {
    let input_paths = &args.inputfiles.clone();
    let mut inputfiles = Vec::new();
    info!("Opening {} segment files.", input_paths.len());
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
        LogLevel::FullInfo => LevelFilter::Info,
        LogLevel::Debug => LevelFilter::Debug,
        LogLevel::FullDebug => LevelFilter::Debug,
        LogLevel::Trace => LevelFilter::Trace,
    };
    if args.log_level == LogLevel::FullInfo || args.log_level == LogLevel::FullDebug {
        env_logger::builder()
        .format_timestamp_nanos()
        .filter_level(log_level)
        .init();
    } else {
        env_logger::builder()
        .format_timestamp_nanos()
        .filter_module(env!("CARGO_PKG_NAME"), log_level)
        .init();
    };


    let inputfiles = open_files(&args);
    
    let preload_chunkmap = gen_preload_chunkmap(&args);

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

    let fs = ZffFs::new(inputfiles, &decryption_passwords, preload_chunkmap);
    let mountoptions = vec![MountOption::RO, MountOption::FSName(String::from(ZFF_OVERLAY_FS_NAME))];
    let session = match fuser::spawn_mount2(fs, &args.mount_point, &mountoptions) {
        Ok(session) => session,
        Err(e) => {
            error!("An error occurred while trying to mount the filesystem.");
            debug!("{e}");
            exit(EXIT_STATUS_ERROR);
        }
    };

    // setup signal handler to unmount by using CTRL+C (or sending SIGHUB/SIGTERM/SIGINT to process).
    let mut signals = match Signals::new([SIGINT, SIGHUP, SIGTERM]) {
        Ok(signals) => signals,
        Err(e) => {
            error!("an error occurred while trying to set the signal handler for graceful umounting: {e}");
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
            session.join();
            info!("Filesystem successfully unmounted. Session closed.");
            exit(EXIT_STATUS_SUCCESS);
        }
    }
}

fn gen_preload_chunkmap(args: &Cli) -> fs::PreloadChunkmap {
    match args.preload_chunkmap {
        PreloadChunkmapValue::None => fs::PreloadChunkmap::None,
        PreloadChunkmapValue::InMemory => fs::PreloadChunkmap::InMemory,
        PreloadChunkmapValue::Redb => {
            //unwrap should safe here, because it is a required argument defined by clap.
            let db = match redb::Database::create(args.redb_path.clone().unwrap()) {
                Ok(db) => db,
                Err(e) => {
                    error!("An error occurred while trying to create preload chunmap database.");
                    debug!("{e}");
                    exit(EXIT_STATUS_ERROR);
                }
            };
            fs::PreloadChunkmap::Redb(db)
        }
    }
}