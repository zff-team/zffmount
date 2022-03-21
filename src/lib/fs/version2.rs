// - STD
use std::ffi::OsStr;
use std::path::PathBuf;
use std::fs::{File};
use std::time::{UNIX_EPOCH};
use std::io::{Read, Seek, SeekFrom, Cursor};
use std::collections::HashMap;

// - internal
use zff::{
    Result,
    header::{ObjectType, FileType as ZffFileType},
    ValueDecoder,
    ZffReader,
    ZffError,
    ZffErrorKind,
    Object,
};


use crate::lib::constants::*;

// - external
use log::{error, debug};

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
    pub undecryptable_objects: Vec<u64>, // <object number>,
    pub object_types_map: HashMap<u64, ObjectType>, // <object_number, object type>
    pub inode_attributes_map: HashMap<u64, FileAttr> //<inode, File attributes>
}

impl ZffOverlayFs {
    pub fn new(inputfiles: Vec<PathBuf>, decryption_passwords: &Vec<String>) -> Result<ZffOverlayFs> {
        //TODO: handle encrypted objects
        let mut files = Vec::new();
        for path in &inputfiles {
         let f = File::open(&path)?;
            files.push(f);
        };

        let temp_zffreader = ZffReader::new(files, HashMap::new())?;
        let object_numbers = temp_zffreader.object_numbers();

        //check encryption and try to decrypt
        let mut undecryptable = Vec::new();
        let mut passwords_per_object = HashMap::new();
        for object in temp_zffreader.objects() {
            let object_number = object.object_number();
            match object.encryption_header() {
                None => (),
                Some(_) => {
                    for password in decryption_passwords {
                        let mut files = Vec::new();
                        for path in &inputfiles {
                            let f = File::open(&path)?;
                            files.push(f);
                        };
                        let mut obj_decryption_password_map = HashMap::new();
                        obj_decryption_password_map.insert(object_number, password.clone());
                        let mut temp_zffreader = match ZffReader::new(files, obj_decryption_password_map) {
                            Ok(reader) => reader,
                            Err(e) => match e.get_kind() {
                                ZffErrorKind::HeaderDecodeEncryptedHeader => {
                                    continue;
                                },
                                ZffErrorKind::PKCS5CryptoError => {
                                    continue;
                                }
                                _ => return Err(e),
                            }
                        };
                        match temp_zffreader.check_decryption(object_number) {
                            Err(e) => return Err(e),
                            Ok(value) => if value { passwords_per_object.insert(object_number, password.clone()); },
                        };
                    }
                    if !passwords_per_object.contains_key(&object_number) {
                        undecryptable.push(object_number)
                    }
                }
            }
        }


        let mut files = Vec::new();
        for path in &inputfiles {
            let f = File::open(&path)?;
            files.push(f);
        };
        let zffreader = ZffReader::new(files, passwords_per_object)?;


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
            undecryptable_objects: undecryptable,
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

pub enum ZffObjectFs<R: Read + Seek> {
    Physical(ZffPhysicalObjectFs<R>),
    Logical(ZffLogicalObjectFs<R>)
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

pub struct ZffLogicalObjectFs<R: Read + Seek> {
    pub object_number: u64,
    pub object_file_attr: FileAttr,
    pub zffreader: ZffReader<R>
}

impl<R: Read + Seek> ZffLogicalObjectFs<R> {
    pub fn new(segments: Vec<R>, object_number: u64) -> Result<ZffLogicalObjectFs<R>> {
        //TODO: encrypted objects
        let mut zffreader = ZffReader::new(segments, HashMap::new())?;

        let object = match zffreader.object(object_number) {
            Some(obj) => obj.clone(),
            None => return Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string())),
        };
        
        let object_info = match &object {
            Object::Physical(_) => return Err(ZffError::new(ZffErrorKind::MismatchObjectType, "")),
            Object::Logical(object_info) => object_info,
        };

        let initial_file_number = match object_info.footer().root_dir_filenumbers().into_iter().next() {
            Some(filenumber) => filenumber,
            None => return Err(ZffError::new(ZffErrorKind::MissingFileNumber, "")),
        };

        match zffreader.set_reader_logical_object_file(object_number, *initial_file_number) {
            Ok(_) => (),
            Err(e) => return Err(e)
        }

        let acquisition_start = match OffsetDateTime::from_unix_timestamp(object.acquisition_start() as i64) {
            Ok(time) => time.into(),
            Err(_) => UNIX_EPOCH,
        };

        let acquisition_end = match OffsetDateTime::from_unix_timestamp(object.acquisition_end() as i64) {
            Ok(time) => time.into(),
            Err(_) => UNIX_EPOCH,
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
            object_file_attr: object_file_attr,
            zffreader: zffreader,
        })
    }

    fn file_attr(&mut self, filenumber: u64) -> Result<FileAttr> {
        self.zffreader.set_reader_logical_object_file(self.object_number, filenumber)?;
        let fileinformation = self.zffreader.file_information()?;
        let size = fileinformation.length_of_data();
        let acquisition_start = match OffsetDateTime::from_unix_timestamp(fileinformation.footer().acquisition_start() as i64) {
            Ok(time) => time.into(),
            Err(_) => UNIX_EPOCH,
        };

        let acquisition_end = match OffsetDateTime::from_unix_timestamp(fileinformation.footer().acquisition_end() as i64) {
            Ok(time) => time.into(),
            Err(_) => UNIX_EPOCH,
        };

        let filenumber = match fileinformation.header().file_type() {
            ZffFileType::Hardlink => {
                self.zffreader.rewind()?;
                let size = fileinformation.length_of_data();
                let mut buffer = vec![0u8; size as usize];
                self.zffreader.read(&mut buffer)?;
                let mut cursor = Cursor::new(buffer);
                u64::decode_directly(&mut cursor)?
            },
            _ => filenumber
        };
        let kind = match fileinformation.header().file_type() {
            ZffFileType::File => FileType::RegularFile,
            ZffFileType::Directory => FileType::Directory,
            ZffFileType::Symlink => FileType::Symlink,
            ZffFileType::Hardlink => FileType::RegularFile,
            _ => return Err(ZffError::new(ZffErrorKind::UnimplementedFileType, "")),
        };

        let file_attr = FileAttr {
            ino: filenumber+1, //TODO: handle hardlinks
            size: size,
            blocks: size / DEFAULT_BLOCKSIZE as u64 + 1,
            atime: acquisition_end,
            mtime: acquisition_end,
            ctime: acquisition_end,
            crtime: acquisition_start,
            kind: kind,
            perm: ZFF_OBJECT_FS_PHYSICAL_ATTR_PERM, //TODO: handle permissions
            nlink: ZFF_OBJECT_FS_PHYSICAL_ATTR_NLINKS, //TODO: handle hardlinks
            blksize: DEFAULT_BLOCKSIZE,
            uid: Uid::effective().into(), //TODO
            gid: Gid::effective().into(), //TODO
            flags: 0,
            rdev: 0,
        };

        Ok(file_attr)
    }
}

impl<R: Read + Seek> Filesystem for ZffLogicalObjectFs<R> {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let childs = if parent == SPECIAL_INODE_ROOT_DIR {
            match self.zffreader.object(self.object_number) {
                Some(Object::Logical(obj_info)) => obj_info.footer().root_dir_filenumbers().to_owned(),
                _ => {
                    reply.error(ENOENT);
                    return;
                },
            }
        } else {
            let fileinformation = match self.zffreader.set_reader_logical_object_file(self.object_number, parent-1) {
                Ok(_) => match self.zffreader.file_information() {
                    Ok(fileinformation) => fileinformation,
                    Err(_) => {
                        reply.error(ENOENT);
                        return;
                    }
                },
                Err(_) => {
                    reply.error(ENOENT);
                    return;
                }
            };
            // entries
            match self.zffreader.rewind() {
                Ok(_) => (),
                Err(_) => {
                    reply.error(ENOENT);
                    return;
                }
            }
            let size = fileinformation.length_of_data();
            let mut buffer = vec![0u8; size as usize];
            match self.zffreader.read(&mut buffer) {
                Ok(_) => (),
                Err(e) => {
                    error!("{e}");
                    reply.error(ENOENT);
                    return;
                },
            }
            let mut cursor = Cursor::new(buffer);
            let childs = match Vec::<u64>::decode_directly(&mut cursor) {
                    Ok(childs) => childs,
                    Err(e) => {
                        error!("Error: {e}");
                        reply.error(ENOENT);
                        return;
                },
            };
            childs
        };
        for filenumber in childs {
            match self.zffreader.set_reader_logical_object_file(self.object_number, filenumber) {
                Ok(_) => (),
                Err(_) => {
                    reply.error(ENOENT);
                    return;
                },
            }
            let fileinformation = match self.zffreader.file_information() {
                Ok(info) => info,
                Err(_) => {
                    reply.error(ENOENT);
                    return;
                },
            };
            if name.to_str() == Some(fileinformation.header().filename()) {
                let file_attr = match self.file_attr(filenumber) {
                    Ok(file_attr) => file_attr,
                    Err(_) => {
                        reply.error(ENOENT);
                        return;
                    }
                };
                reply.entry(&TTL, &file_attr, DEFAULT_ENTRY_GENERATION);
                return;
            }
            //reply.entry(&TTL, &self.file_attr, DEFAULT_ENTRY_GENERATION);
        }
        reply.error(ENOENT);
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        if ino == SPECIAL_INODE_ROOT_DIR {
            reply.attr(&TTL, &self.object_file_attr);
        } else {
            let file_attr = match self.file_attr(ino-1) {
                Ok(file_attr) => file_attr,
                Err(_) => {
                    reply.error(ENOENT);
                    return;
                }
            };
            reply.attr(&TTL, &file_attr);
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
        let mut entries = Vec::new();
        debug!("Start readdir");
        let childs = if ino == SPECIAL_INODE_ROOT_DIR {
            entries.push((SPECIAL_INODE_ROOT_DIR, FileType::Directory, String::from(CURRENT_DIR)));
            entries.push((SPECIAL_INODE_ROOT_DIR, FileType::Directory, String::from(PARENT_DIR)));
            let filenumbers = match self.zffreader.object(self.object_number).unwrap() {
                Object::Logical(obj_info) => obj_info.footer().root_dir_filenumbers().to_owned(),
                Object::Physical(_) => {
                    reply.error(ENOENT);
                    return;
                }
            };
            filenumbers

        } else {
            entries.push((ino, FileType::Directory, String::from(CURRENT_DIR)));
            // parent_dir
            let fileinformation = match self.zffreader.set_reader_logical_object_file(self.object_number, ino-1) {
                Ok(_) => match self.zffreader.file_information() {
                    Ok(fileinformation) => fileinformation,
                    Err(_) => {
                        reply.error(ENOENT);
                        return;
                    }
                },
                Err(_) => {
                    reply.error(ENOENT);
                    return;
                }
            };
            entries.push((fileinformation.parent()+1, FileType::Directory, String::from(PARENT_DIR)));

            // entries
            match self.zffreader.rewind() {
                Ok(_) => (),
                Err(_) => {
                    reply.error(ENOENT);
                    return;
                }
            }
            let size = fileinformation.length_of_data();
            let mut buffer = vec![0u8; size as usize];
            match self.zffreader.read(&mut buffer) {
                Ok(_) => (),
                Err(e) => {
                    error!("{e}");
                    reply.error(ENOENT);
                    return;
                },
            }
            let mut cursor = Cursor::new(buffer);
            let childs = match Vec::<u64>::decode_directly(&mut cursor) {
                    Ok(childs) => childs,
                    Err(e) => {
                        error!("Error: {e}");
                        reply.error(ENOENT);
                        return;
                },
            };
            childs
        };

        for child_filenumber in childs {
            let fileinformation = match self.zffreader.set_reader_logical_object_file(self.object_number, child_filenumber) {
                Ok(_) => match self.zffreader.file_information() {
                    Ok(fileinformation) => fileinformation,
                    Err(_) => {
                        reply.error(ENOENT);
                        return;
                    }
                },
                Err(_) => {
                    reply.error(ENOENT);
                    return;
                }
            };

            let kind = match fileinformation.header().file_type() {
                ZffFileType::File => FileType::RegularFile,
                ZffFileType::Directory => FileType::Directory,
                ZffFileType::Symlink => FileType::Symlink,
                ZffFileType::Hardlink => FileType::RegularFile,
                _ => {
                    reply.error(ENOENT);
                    return;
                },
            };
            let filename = fileinformation.header().filename();
            entries.push((child_filenumber+1, kind, String::from(filename)));
        }

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
        if !offset >= 0 {
            error!("READ: offset >= 0 -> offset = {offset}");
            reply.error(ENOENT);
            return;
        }
        let filenumber = ino - 1;
        let fileinformation = match self.zffreader.set_reader_logical_object_file(self.object_number, filenumber) {
            Ok(_) => match self.zffreader.file_information() {
                Ok(fileinformation) => fileinformation,
                Err(e) => {
                    error!("READ: {e}");
                    reply.error(ENOENT);
                    return;
                }
            },
            Err(e) => {
                error!("READ: {e}");
                reply.error(ENOENT);
                return;
            }
        };

        match fileinformation.header().file_type() {
            ZffFileType::Hardlink => {
                match self.zffreader.rewind() {
                    Ok(_) => (),
                    Err(_) => {
                        reply.error(ENOENT);
                        return;
                    }
                }
                let size = fileinformation.length_of_data();
                let mut buffer = vec![0u8; size as usize];
                match self.zffreader.read(&mut buffer) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("{e}");
                        reply.error(ENOENT);
                        return;
                    },
                }
                let mut cursor = Cursor::new(buffer);
                match u64::decode_directly(&mut cursor) {
                    Ok(filenumber) => match self.zffreader.set_reader_logical_object_file(self.object_number, filenumber) {
                        Ok(_) => (),
                        Err(e) => {
                            error!("READ: {e}");
                            reply.error(ENOENT);
                            return;
                        }
                    },
                    Err(e) => {
                        error!("READ: {e}");
                        reply.error(ENOENT);
                        return;
                    }
                }
            },
            _ => (),
        };
        
        match self.zffreader.seek(SeekFrom::Start(offset as u64)) {
            Ok(_) => (),
            Err(e) => {
                error!("READ: {e}");
                reply.error(ENOENT);
                return;
            }
        }
        let mut buffer = vec![0u8; size as usize];
        match self.zffreader.read(&mut buffer) {
            Ok(_) => (),
            Err(e) => {
                error!("READ: {e}");
                reply.error(ENOENT);
                return
            }
        }
        reply.data(&buffer);
    }
}