// - STD
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

struct ZffOverlayFs {
    inputfiles: Vec<PathBuf>,
    objects: HashMap<u64, FileAttr>, // <object_number, File attributes>
}

impl ZffOverlayFs {
    pub fn new(inputfiles: Vec<PathBuf>) -> Result<ZffOverlayFs> {
        //TODO: handle encrypted objects
        let mut files = Vec::new();
        for path in &inputfiles {
            let f = File::open(&path)?;
            files.push(f);
        };

        let mut zffreader = ZffReader::new(files, HashMap::new())?;
        let object_numbers = zffreader.object_numbers();

        let mut objects = HashMap::new();

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

            current_inode += 1;
        };

        let overlay_fs = Self {
            inputfiles: inputfiles,
            objects: objects,
        };

        Ok(overlay_fs)
    }
}

struct ZffObjectFs<R: Read + Seek> {
    zffreader: ZffReader<R>
}