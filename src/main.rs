// - STD
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, sleep};
use std::process::exit;
use std::path::PathBuf;
use std::fs::File;
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, UNIX_EPOCH};

// - modules
mod constants;
mod addons;
mod zff_core;
#[cfg(target_family = "unix")]
mod unix;
#[cfg(target_family = "windows")]
mod windows;

// - internal
use constants::*;
use addons::*;
use zff_core::*;

// - external
use clap::{Parser, ValueEnum};
use log::{LevelFilter, info, error, warn, debug};
use zff::{
    Result,
    FileMetadata,
    FileFooterMetadata,
    header::{FileType as ZffFileType, SpecialFileType as ZffSpecialFileType, MetadataExtendedValue as ZffMetadataExtendedValue},
    footer::ObjectFooter,
    ValueDecoder,
    io::zffreader::{ZffReader, ObjectType as ZffReaderObjectType},
    ZffError,
    ZffErrorKind,
};
use time::OffsetDateTime;
use dialoguer::{theme::ColorfulTheme, Password as PasswordDialog};


#[derive(Parser, Clone)]
#[clap(about, version, author)]
pub struct Cli {
    /// The input files. This should be your zff image files. You can use this option multiple times.
    #[clap(short='i', long="inputfiles", global=true, required=false, value_delimiter = ' ', num_args = 1..)]
    inputfiles: Vec<PathBuf>,

    /// The output format.
    #[clap(short='m', long="mount-point")]
    mount_point: PathBuf,

    /// The password(s), if the file(s) are encrypted. You can use this option multiple times to enter different passwords for different objects.
    /// If the password doesn't match or is not given, zffmount will ask interactively.
    #[clap(short='p', long="decryption-passwords", value_parser = parse_key_val::<String, String>)]
    decryption_passwords: Vec<(String, String)>,

    /// The Loglevel
    #[clap(short='l', long="log-level", value_enum, default_value="info")]
    log_level: LogLevel,

    /// Disables the kernel side DAC checks (all files of logical objects are accessable, even if they do not fit the
    /// right ownership).
    #[clap(short='O', long="ownership-overwrite")]
    ownership_overwrite: bool,

    /// Hide passive objects. If this option is used, they will be initialized, used by virtual objects, but not directly accessable via
    /// the fuse mount.
    #[clap(short='H', long="hide-passive-objects")]
    hide_passive_objects: bool,

    /// None: saves memory but the read operations are slower (default)  
    /// redb: use a fast redb database to cache (can be faster than none if using a fast NVMe drive)  
    /// in-memory: fastest option, but you need to ensure that you have enough memory.
    #[clap(short='M', long="preload-mode", value_enum, default_value="none", 
    required_if_eq_any=[("preload_chunk_header_map", "true"), ("preload_all_maps", "true")])]
    preload_mode: PreloadMode,

    /// Preload the chunk header map (in memory or in redb database e.g. at a fast NVMe drive) to speed up the read operations.
    /// In memory: needs 46 bytes per chunk (plus a lot of bytes for additional overhead) to store the chunkmap in memory. This is the fastest option, but you need to ensure that you have enough memory.  
    /// redb: use a fast redb database to cache the chunk offset map. This could e.g. be useful, if your container is stored at a slow harddrive but the redb database can be cached at a fast nvme drive.  
    #[clap(short='o', long="preload-chunk-map")]
    preload_chunk_header_map: bool,

    /// Preload the all chunks contains same bytes (e.g. only 0's) (in memory or in redb database e.g. at a fast NVMe drive) to speed up the read operations.
    /// In memory: needs 24 bytes per chunk (plus a lot of bytes for additional overhead) to store the chunkmap in memory. This is the fastest option, but you need to ensure that you have enough memory.  
    /// redb: use a fast redb database to cache the chunk size map. This could e.g. be useful, if your container is stored at a slow harddrive but the redb database can be cached at a fast nvme drive.  
    #[clap(short='S', long="preload-samebytes-map")]
    preload_chunk_samebytes_map: bool,

    /// Preload the all duplication chunks (in memory or in redb database e.g. at a fast NVMe drive) to speed up the read operations.
    /// In memory: needs 24 bytes per chunk (plus a lot of bytes for additional overhead) to store the chunkmap in memory. This is the fastest option, but you need to ensure that you have enough memory.  
    /// redb: use a fast redb database to cache the chunk size map. This could e.g. be useful, if your container is stored at a slow harddrive but the redb database can be cached at a fast nvme drive.  
    #[clap(short='d', long="preload-deduplication-map")]
    preload_chunk_deduplication_map: bool,

    /// preloads all chunkmaps (offset, size, flags) in memory or in redb database. 
    /// This is the fastest option (if using in-memory), but you need to ensure that you have enough memory.
    #[clap(short='a', long="preload-all-maps")]
    preload_all_maps: bool,

    #[clap(short='r', long="redb-path", required_if_eq("preload_mode", "redb"))]
    redb_path: Option<PathBuf>,
}

#[derive(ValueEnum, Clone, Debug)]
enum PreloadMode {
    None,
    InMemory,
    Redb,
}

#[derive(ValueEnum, Clone, PartialEq, Debug)]
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
        LogLevel::Debug => LevelFilter::Debug,
        LogLevel::Trace => LevelFilter::Trace,
    };
    env_logger::builder()
        .format_timestamp_nanos()
        .filter_level(log_level)
        .init();

    let inputfiles = open_files(&args);
    
    let preload_chunkmap = gen_preload_chunkmap(&args);

    let mut decryption_passwords = HashMap::new();
    for (obj_no, pw) in &args.decryption_passwords {
        let obj_no = match obj_no.parse::<u64>() {
            Ok(no) => no,
            Err(e) => {
                error!("Could not parse object number {obj_no}: {e}");
                exit(EXIT_STATUS_ERROR);
            }
        };
        decryption_passwords.insert(obj_no, pw.clone());
    }

    let fs = ZffFs::new(inputfiles, &decryption_passwords, preload_chunkmap, args.hide_passive_objects);

    fuse(fs, &args)
}

fn fuse<R: Read + Seek + Send + Sync + 'static>(fs: ZffFs<R>, args: &Cli) {
    #[cfg(target_family = "unix")]
    unix::fuse_unix(fs, args);
    #[cfg(target_family = "windows")]
    windows::fuse_windows(fs, args);
}