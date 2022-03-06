// - STD
use std::ffi::OsStr;
use std::path::PathBuf;
use std::fs::{File};
use std::time::{UNIX_EPOCH};
use std::io::{Read, Seek, SeekFrom};
use std::collections::HashMap;

// - internal
use zff::{
    Result,
    header::*,
    ZffReader,
    ZffError,
    ZffErrorKind,
    Object,
};


use crate::lib::constants::*;

// - external
use log::{error};

// - external
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};
use nix::unistd::{Uid, Gid};
use libc::ENOENT;
use time::{OffsetDateTime};

#[derive(Debug)]
pub struct ZffOverlayFs {
    pub objects: HashMap<u64, FileAttr>, // <object_number, File attributes>
    pub object_types_map: HashMap<u64, ObjectType>, // <object_number, object type>
    pub inode_attributes_map: HashMap<u64, FileAttr> //<inode, File attributes>
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
                    error!("LOOKUP: object prefix not in filename. This is an application bug. The filename is {name}");
                    reply.error(ENOENT);
                    return;
                },
                Some(unparsed_object_number) => match unparsed_object_number.parse::<u64>() {
                    Ok(object_number) => object_number,
                    Err(_) => {
                        error!("LOOKUP: error while trying to parse the object number: {unparsed_object_number}");
                        reply.error(ENOENT);
                        return;
                    },
                },
            };
            let file_attr = match self.objects.get(&object_number) {
                None => {
                    error!("LOOKUP: cannot find the appropriate file attributes for object number {object_number}");
                    reply.error(ENOENT);
                    return;
                },
                Some(file_attr) => file_attr,
            };
            reply.entry(&TTL, &file_attr, DEFAULT_ENTRY_GENERATION);
        } else {
            error!("LOOKUP: Parent ID {parent} not matching root inode dir {SPECIAL_INODE_ROOT_DIR}");
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match self.inode_attributes_map.get(&ino) {
            Some(file_attr) => reply.attr(&TTL, file_attr),
            None => if ino == SPECIAL_INODE_ROOT_DIR {
                reply.attr(&TTL, &DEFAULT_ROOT_DIR_ATTR)
            } else {
                error!("GETATTR: unknown inode number: {ino}");
                reply.error(ENOENT);
            },
        }
    }
}

pub struct ZffPhysicalObjectFs<R: Read + Seek> {
    pub object_number: u64,
    pub file_attr: FileAttr,
    pub object_file_attr: FileAttr,
    pub zffreader: ZffReader<R>
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
            reply.entry(&TTL, &self.file_attr, DEFAULT_ENTRY_GENERATION);
        } else {
            error!("LOOKUP: unknown parent ID / name combination. Parent ID: {parent}; name: {:?}", name.to_str());
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match ino {
            SPECIAL_INODE_ROOT_DIR => reply.attr(&TTL, &self.object_file_attr),
            ZFF_OBJECT_FS_PHYSICAL_ATTR_INO => reply.attr(&TTL, &self.file_attr),
            _ => {
                error!("GETATTR: unknown inode number: {ino}");
                reply.error(ENOENT)
            },
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
                Err(e) => error!("seek error: {e}"),
            };
            match self.zffreader.read(&mut buffer) {
                Ok(_) => (),
                Err(e) => error!("read error: {e}"),
            };
            reply.data(&buffer);
        } else {
            error!("inode number mismatch: {ino}");
            reply.error(ENOENT);
        }
    }

}