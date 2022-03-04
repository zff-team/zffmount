// - STD
use std::os::unix::ffi::OsStrExt;
use std::ffi::OsStr;
use std::process::exit;
use std::path::PathBuf;
use std::fs::{File,read_dir};
use std::time::{UNIX_EPOCH, SystemTime};
use std::io::{Read, Seek, SeekFrom};
use std::collections::HashMap;

// - modules
mod lib;

// - internal
use zff::{
    Result,
    header::*,
    HeaderCoding,
    ZffReader,
};

use lib::*;
use lib::constants::*;

// - external
use clap::{Parser, ArgEnum};
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};
use nix::unistd::{Uid, Gid};
use libc::ENOENT;
use time::{OffsetDateTime};
#[macro_use] use log::{debug, LevelFilter};
use env_logger;

#[derive(Parser)]
#[clap(about, version, author)]
pub struct Cli {
    /// The input files. This should be your zff image files. You can use this Option multiple times.
    #[clap(short='i', long="inputfiles", global=true, required=false)]
    inputfiles: Vec<String>,

    /// The output format.
    #[clap(short='m', long="mount-point")]
    mount_point: PathBuf,

    /// The password, if the file has an encrypted main header. However, it will interactively ask for the correct password if it is missing or incorrect (but needed).
    #[clap(short='p', long="decryption-password")]
    decryption_password: Option<String>,
}

#[derive(Debug)]
struct ZffOverlayFs {
    inputfiles: Vec<PathBuf>,
    objects: HashMap<u64, FileAttr>, // <object_number, File attributes>
    inode_attributes_map: HashMap<u64, FileAttr> //<inode, File attributes>
}

impl ZffOverlayFs {
    pub fn new(inputfiles: Vec<PathBuf>) -> Result<ZffOverlayFs> {
        //TODO: handle encrypted objects
        let mut files = Vec::new();
        for path in &inputfiles {
            let f = File::open(&path)?;
            files.push(f);
        };

        let zffreader = ZffReader::new(files, HashMap::new())?;
        let object_numbers = zffreader.object_numbers();

        let mut objects = HashMap::new();
        let mut inode_attributes_map = HashMap::new();

        let mut current_inode = 12;
        for object_number in object_numbers {
            let acquisition_start = match zffreader.object(object_number) {
                None => UNIX_EPOCH,
                Some(obj) => match OffsetDateTime::from_unix_timestamp(obj.acquisition_start() as i64) {
                    Ok(time) => time.into(),
                    Err(_) => UNIX_EPOCH,
                },
            };
            let acquisition_end = match zffreader.object(object_number) {
                None => UNIX_EPOCH,
                Some(obj) => match OffsetDateTime::from_unix_timestamp(obj.acquisition_end() as i64) {
                    Ok(time) => time.into(),
                    Err(_) => UNIX_EPOCH,
                }
            };
            let file_attr = FileAttr {
                ino: current_inode,
                size: 0,
                blocks: 0,
                atime: acquisition_end,
                mtime: acquisition_end,
                ctime: acquisition_end,
                crtime: acquisition_start,
                kind: FileType::Directory,
                perm: 0o755,
                nlink: 2,
                uid: Uid::effective().into(),
                gid: Gid::effective().into(),
                rdev: 0,
                flags: 0,
                blksize: 512,
            };

            objects.insert(object_number, file_attr);
            inode_attributes_map.insert(current_inode, file_attr);

            current_inode += 1;
        };

        let overlay_fs = Self {
            inputfiles: inputfiles,
            objects: objects,
            inode_attributes_map: inode_attributes_map,
        };

        Ok(overlay_fs)
    }
}

impl Filesystem for ZffOverlayFs {
    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != ZFF_OVERLAY_SPECIAL_INODE_ROOT_DIR {
            reply.error(ENOENT);
            return;
        }

        let mut entries = vec![
            (ZFF_OVERLAY_SPECIAL_INODE_ROOT_DIR, FileType::Directory, String::from(CURRENT_DIR)),
            (ZFF_OVERLAY_SPECIAL_INODE_ROOT_DIR, FileType::Directory, String::from(PARENT_DIR)),
        ];
        for (object_number, file_attr) in &self.objects {
            let entry = (file_attr.ino, FileType::Directory, format!("{OBJECT_PREFIX}{object_number}"));
            entries.push(entry);
        }
        for (index, entry) in entries.into_iter().skip(offset as usize).enumerate() {
            let (inode, file_type, name) = entry;
            if reply.add(inode, offset + index as i64 + 1, file_type.into(), name) {
                break;
            }
        }
        reply.ok();
    }

    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == ZFF_OVERLAY_SPECIAL_INODE_ROOT_DIR {
            let name = match name.to_str() {
                Some(name) => name,
                None => {
                    reply.error(ENOENT);
                    return;
                },
            };
            let mut split = name.rsplit(OBJECT_PREFIX);
            let object_number = match split.next() {
                None => {
                    reply.error(ENOENT);
                    return;
                },
                Some(unparsed_object_number) => match unparsed_object_number.parse::<u64>() {
                    Ok(object_number) => object_number,
                    Err(_) => {
                        reply.error(ENOENT);
                        return;
                    },
                },
            };
            let file_attr = match self.objects.get(&object_number) {
                None => {
                    reply.error(ENOENT);
                    return;
                },
                Some(file_attr) => file_attr,
            };
            reply.entry(&TTL, &file_attr, ZFF_OVERLAY_DEFAULT_ENTRY_GENERATION);
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match self.inode_attributes_map.get(&ino) {
            Some(file_attr) => reply.attr(&TTL, file_attr),
            None => if ino == ZFF_OVERLAY_SPECIAL_INODE_ROOT_DIR {
                reply.attr(&TTL, &ZFF_OVERLAY_ROOT_DIR_ATTR)
            } else {
                reply.error(ENOENT);
            },
        }
    }
}

/*
struct ZffObjectFs<R: Read + Seek> {
    zffreader: ZffReader<R>
}*/

fn main() {
    let args = Cli::parse();

    let inputfiles = &args.inputfiles.into_iter().map(|i| PathBuf::from(i)).collect::<Vec<PathBuf>>();
    let overlay_fs = match ZffOverlayFs::new(inputfiles.to_owned()) {
        Ok(overlay_fs) => overlay_fs,
        Err(e) => {
            eprintln!("{e}");
            exit(EXIT_STATUS_ERROR);
        }
    };
    //TODO: remove or use correctly
    let verbosity: u64 = 3;
    let log_level = match verbosity {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };
    env_logger::builder()
        .format_timestamp_nanos()
        .filter_level(log_level)
        .init();
    let mountpoint = PathBuf::from(&args.mount_point);
    let mountoptions = vec![MountOption::RO, MountOption::FSName(String::from(ZFF_OVERLAY_FS_NAME))];

    let overlay_fuse_session = {
        let session = match fuser::Session
    };

    fuser::mount2(overlay_fs, mountpoint, &mountoptions).unwrap();
}