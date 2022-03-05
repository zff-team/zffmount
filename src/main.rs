// - STD
use std::collections::HashSet;
use std::path::Path;

use std::ffi::OsStr;
use std::process::exit;
use std::path::PathBuf;
use std::fs::{File};
use std::time::{UNIX_EPOCH};
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
    ZffError,
    ZffErrorKind,
    Object,
};


use lib::constants::*;

// - external
use clap::{Parser};
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request, BackgroundSession, Session,
};
use nix::unistd::{Uid, Gid};
use libc::ENOENT;
use time::{OffsetDateTime};
use log::{LevelFilter};
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
    objects: HashMap<u64, FileAttr>, // <object_number, File attributes>
    object_types_map: HashMap<u64, ObjectType>, // <object_number, object type>
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
        let mut object_types_map = HashMap::new();
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
        for obj_number in zffreader.physical_object_numbers() {
            object_types_map.insert(obj_number, ObjectType::Physical);
        }
        for obj_number in zffreader.logical_object_numbers() {
            object_types_map.insert(obj_number, ObjectType::Logical);
        }

        let overlay_fs = Self {
            objects: objects,
            object_types_map: object_types_map,
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
        if ino != SPECIAL_INODE_ROOT_DIR {
            reply.error(ENOENT);
            return;
        }

        let mut entries = vec![
            (SPECIAL_INODE_ROOT_DIR, FileType::Directory, String::from(CURRENT_DIR)),
            (SPECIAL_INODE_ROOT_DIR, FileType::Directory, String::from(PARENT_DIR)),
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
        if parent == SPECIAL_INODE_ROOT_DIR {
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
            None => if ino == SPECIAL_INODE_ROOT_DIR {
                reply.attr(&TTL, &ZFF_OVERLAY_ROOT_DIR_ATTR)
            } else {
                reply.error(ENOENT);
            },
        }
    }
}

struct ZffPhysicalObjectFs<R: Read + Seek> {
    object_number: u64,
    file_attr: FileAttr,
    object_file_attr: FileAttr,
    zffreader: ZffReader<R>
}

impl<R: Read + Seek> ZffPhysicalObjectFs<R> {
    pub fn new(segments: Vec<R>, object_number: u64) -> Result<ZffPhysicalObjectFs<R>> {
        //TODO: encrypted objects
        let mut zffreader = ZffReader::new(segments, HashMap::new())?;

        let object = match zffreader.object(object_number) {
            Some(obj) => obj.clone(),
            None => return Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string())),
        };
        let object_info = match object {
            Object::Physical(object_info) => object_info,
            Object::Logical(_) => return Err(ZffError::new(ZffErrorKind::MismatchObjectType, "")),
        };
        let _ = zffreader.set_reader_physical_object(object_number)?;
        let size = object_info.footer().length_of_data();
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
            ino: ZFF_OBJECT_FS_PHYSICAL_ATTR_INO,
            size: size,
            blocks: size / DEFAULT_BLOCKSIZE as u64 + 1,
            atime: acquisition_end,
            mtime: acquisition_end,
            ctime: acquisition_end,
            crtime: acquisition_start,
            kind: FileType::RegularFile,
            perm: ZFF_OBJECT_FS_PHYSICAL_ATTR_PERM,
            nlink: ZFF_OBJECT_FS_PHYSICAL_ATTR_NLINKS,
            blksize: DEFAULT_BLOCKSIZE,
            uid: Uid::effective().into(),
            gid: Gid::effective().into(),
            flags: 0,
            rdev: 0,
        };

        let object_file_attr = FileAttr {
            ino: SPECIAL_INODE_ROOT_DIR,
            size: 0,
            blocks: 0,
            atime: acquisition_end,
            mtime: acquisition_end,
            ctime: acquisition_end,
            crtime: acquisition_start,
            kind: FileType::Directory,
            perm: 0o777,
            nlink: ZFF_OBJECT_FS_PHYSICAL_ATTR_NLINKS,
            blksize: DEFAULT_BLOCKSIZE,
            uid: Uid::effective().into(),
            gid: Gid::effective().into(),
            flags: 0,
            rdev: 0,
        };

        Ok(Self {
            object_number: object_number,
            file_attr: file_attr,
            object_file_attr: object_file_attr,
            zffreader: zffreader
        })
    }
}

impl<R: Read + Seek> Filesystem for ZffPhysicalObjectFs<R> {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == SPECIAL_INODE_ROOT_DIR && name.to_str() == Some(ZFF_PHYSICAL_OBJECT_NAME) {     
            reply.entry(&TTL, &self.file_attr, ZFF_OVERLAY_DEFAULT_ENTRY_GENERATION);
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match ino {
            SPECIAL_INODE_ROOT_DIR => reply.attr(&TTL, &self.object_file_attr),
            ZFF_OBJECT_FS_PHYSICAL_ATTR_INO => reply.attr(&TTL, &self.file_attr),
            _ => reply.error(ENOENT),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != SPECIAL_INODE_ROOT_DIR {
            reply.error(ENOENT);
            return;
        }

        let entries = vec![
            (SPECIAL_INODE_ROOT_DIR, FileType::Directory, String::from(CURRENT_DIR)),
            (SPECIAL_INODE_ROOT_DIR, FileType::Directory, String::from(PARENT_DIR)),
            (ZFF_OBJECT_FS_PHYSICAL_ATTR_INO, FileType::RegularFile, String::from(ZFF_PHYSICAL_OBJECT_NAME)),
        ];

        for (index, entry) in entries.into_iter().skip(offset as usize).enumerate() {
            let (inode, file_type, name) = entry;
            if reply.add(inode, offset + index as i64 + 1, file_type.into(), name) {
                break;
            }
        }
        reply.ok();
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        if ino == ZFF_OBJECT_FS_PHYSICAL_ATTR_INO {
            let mut buffer = vec![0u8; size as usize];
            match self.zffreader.seek(SeekFrom::Start(offset as u64)) {
                Ok(_) => (),
                Err(e) => {
                    eprintln!("{e}"); //TODO
                    exit(EXIT_STATUS_ERROR); //TODO
                }
            };
            match self.zffreader.read(&mut buffer) {
                Ok(_) => (),
                Err(e) => eprintln!("{e}"), //TODO
            };
            reply.data(&buffer);
        } else {
            reply.error(ENOENT);
        }
    }

}

fn main() {
    let args = Cli::parse();

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

    let inputfiles = &args.inputfiles.into_iter().map(|i| PathBuf::from(i)).collect::<Vec<PathBuf>>();
    let overlay_fs = match ZffOverlayFs::new(inputfiles.to_owned()) {
        Ok(overlay_fs) => overlay_fs,
        Err(e) => {
            eprintln!("{e}");
            exit(EXIT_STATUS_ERROR);
        }
    };

    let mut object_fs_vec = Vec::new();
    for (object_number, object_type) in &overlay_fs.object_types_map {
        match object_type {
            ObjectType::Logical => unimplemented!(),
            ObjectType::Physical => {
                let mut files = Vec::new();
                for path in inputfiles {
                    let f = match File::open(&path) {
                        Ok(f) => f,
                        Err(e) => {
                            eprintln!("{e}"); //TODO
                            exit(EXIT_STATUS_ERROR);
                        },
                    };
                    files.push(f);
                };
                let object_fs = match ZffPhysicalObjectFs::new(files, *object_number) {
                    Ok(fs) => fs,
                    Err(e) => {
                        eprintln!("{e}"); //TODO
                        exit(EXIT_STATUS_ERROR);
                    },
                };
                object_fs_vec.push(object_fs);
            },
        }
    }

    let mountpoint = PathBuf::from(&args.mount_point);
    let overlay_mountoptions = vec![MountOption::RW, MountOption::AllowOther, MountOption::FSName(String::from(ZFF_OVERLAY_FS_NAME))];
    let object_mountoptions = vec![MountOption::RO, MountOption::AllowOther, MountOption::FSName(String::from(ZFF_OBJECT_FS_NAME))];

    let overlay_session = spawn_mount2(overlay_fs, &mountpoint, &overlay_mountoptions).unwrap(); //TODO

    let mut object_fs_sessions = Vec::new();
    for object_fs in object_fs_vec {
        let mut inner_mountpoint = mountpoint.clone();
        let object_number = object_fs.object_number;
        inner_mountpoint.push(format!("{OBJECT_PREFIX}{object_number}"));
        let session = spawn_mount2(object_fs, inner_mountpoint, &object_mountoptions).unwrap(); //TODO
        object_fs_sessions.push(session);
    }

    loop {}
}

pub fn spawn_mount2<'a, FS: Filesystem + Send + 'static + 'a, P: AsRef<Path>>(
    filesystem: FS,
    mountpoint: P,
    options: &[MountOption],
) -> std::io::Result<BackgroundSession> {
    check_option_conflicts(options)?;
    Session::new(filesystem, mountpoint.as_ref(), options).and_then(|se| se.spawn())
}

pub fn check_option_conflicts(options: &[MountOption]) -> std::io::Result<()> {
    let mut options_set = HashSet::new();
    options_set.extend(options.iter().cloned());
    let conflicting: HashSet<MountOption> = options.iter().map(conflicts_with).flatten().collect();
    let intersection: Vec<MountOption> = conflicting.intersection(&options_set).cloned().collect();
    if !intersection.is_empty() {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Conflicting mount options found: {:?}", intersection),
        ))
    } else {
        Ok(())
    }
}

fn conflicts_with(option: &MountOption) -> Vec<MountOption> {
    match option {
        MountOption::FSName(_) => vec![],
        MountOption::Subtype(_) => vec![],
        MountOption::CUSTOM(_) => vec![],
        MountOption::AllowOther => vec![MountOption::AllowRoot],
        MountOption::AllowRoot => vec![MountOption::AllowOther],
        MountOption::AutoUnmount => vec![],
        MountOption::DefaultPermissions => vec![],
        MountOption::Dev => vec![MountOption::NoDev],
        MountOption::NoDev => vec![MountOption::Dev],
        MountOption::Suid => vec![MountOption::NoSuid],
        MountOption::NoSuid => vec![MountOption::Suid],
        MountOption::RO => vec![MountOption::RW],
        MountOption::RW => vec![MountOption::RO],
        MountOption::Exec => vec![MountOption::NoExec],
        MountOption::NoExec => vec![MountOption::Exec],
        MountOption::Atime => vec![MountOption::NoAtime],
        MountOption::NoAtime => vec![MountOption::Atime],
        MountOption::DirSync => vec![],
        MountOption::Sync => vec![MountOption::Async],
        MountOption::Async => vec![MountOption::Sync],
    }
}