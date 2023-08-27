// - STD
use std::collections::BTreeMap;
use std::process::exit;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::fs::{File};
use std::time::{UNIX_EPOCH};
use std::io::{Read, Seek, SeekFrom, Cursor};
use std::collections::HashMap;

// - internal
use super::constants::*;
use zff::{
    Result,
    header::{ObjectType, FileType as ZffFileType, SpecialFileType as ZffSpecialFileType},
    footer::{ObjectFooter},
    ValueDecoder,
    io::zffreader::{ZffReader, ObjectType as ZffReaderObjectType, FileMetadata},
    ZffError,
    ZffErrorKind,
    Object,
};

// - external
use log::{error, debug, info, warn};

// - external
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};
use nix::unistd::{Uid, Gid};
use libc::ENOENT;
use time::{OffsetDateTime};
use dialoguer::{theme::ColorfulTheme, Password as PasswordDialog};

#[derive(Debug, Clone, Eq, PartialEq)]
struct ZffFsCache {
    pub object_list: BTreeMap<u64, ZffReaderObjectType>,
    pub inode_reverse_map: BTreeMap<u64, (u64, u64)>, //<Inode, (object number, file number)
}

impl ZffFsCache {
    fn with_data(
        object_list: BTreeMap<u64, ZffReaderObjectType>,
        inode_reverse_map: BTreeMap<u64, (u64, u64)>) -> Self 
    {
        Self {
            object_list,
            inode_reverse_map
        }
    }
}

#[derive(Debug)]
pub struct ZffFs<R: Read + Seek> {
    zffreader: ZffReader<R>,
    shift_value: u64,
    cache: ZffFsCache,
}

impl<R: Read + Seek> ZffFs<R> {
    pub fn new(inputfiles: Vec<R>, decryption_passwords: &HashMap<u64, String>) -> Self {
        info!("Reading segment files to create initial ZffReader.");
        let mut zffreader = match ZffReader::with_reader(inputfiles) {
            Ok(reader) => reader,
            Err(e) => {
                error!("An error occurred while trying to create the ZffReader: {e}");
                exit(EXIT_STATUS_ERROR);
            }
        };

        let object_list = match zffreader.list_objects() {
            Ok(list) => list,
            Err(e) => {
                error!("An error occurred while trying to get the ZffReader object list: {e}");
                exit(EXIT_STATUS_ERROR);
            }
        };
        let (phy, log, enc) = object_list.values().fold((0, 0, 0), |(phy, log, enc), val| {
            match val {
                ZffReaderObjectType::Physical => (phy + 1, log, enc),
                ZffReaderObjectType::Logical => (phy, log + 1, enc),
                ZffReaderObjectType::Encrypted => (phy, log, enc + 1),
            }
        });
        info!("ZffReader created successfully. Found {phy} physical, {log} logical and {enc} encrypted objects.");

        //initialize and decrypt objects
        for (object_number, obj_type) in &object_list {
            match zffreader.initialize_object(*object_number) {
                Ok(_) => info!("Successfully initialized {obj_type} object {object_number}"),
                Err(e) => error!("Could not inititalize object {object_number} due following error: {e}"),
            }

            if obj_type == &ZffReaderObjectType::Encrypted {
                let pw = match decryption_passwords.get(object_number) {
                    Some(pw) => pw.clone(),
                    None => match enter_password_dialog(*object_number)  {
                        Some(pw) => pw,
                        None => {
                            info!("No password entered for encrypted object {object_number}.");
                            String::new()
                        }
                    }
                };
                match zffreader.decrypt_object(*object_number, pw) {
                    Ok(o_type) => info!("Object {object_number} ({o_type} object) decrypted successfully"),
                    Err(e) => warn!("Could not decrypt object {object_number}: {e}"),
                }
            }
        }

        // set object inodes and shift value
        let numbers_of_decrypted_objects: Vec<u64> = object_list.iter().filter(|(_, v)| v != &&ZffReaderObjectType::Encrypted).map(|(&k, _)| k).collect();
        let shift_value = match numbers_of_decrypted_objects.iter().max() {
            Some(value) => *value + 1, // + 1 for root dir inode
            None => 1,
        };

        let mut inode_reverse_map = BTreeMap::new();
        //setup inode reverse map
        for (object_number, obj_type) in &object_list {
            if obj_type == &ZffReaderObjectType::Logical {
                match inode_reverse_map_add_object(&mut zffreader, &mut inode_reverse_map, *object_number, shift_value) {
                    Ok(noe) => debug!("{noe} entries for object {object_number} added to inode reverse map."),
                    Err(e) => {
                        error!("An error occurred while trying to fill the inode reverse map: {e}");
                        exit(EXIT_STATUS_ERROR);
                    }
                }
            }
        }

        let cache = ZffFsCache::with_data(object_list, inode_reverse_map);

        Self {
            zffreader,
            shift_value,
            cache,
        }
    }
}

impl<R: Read + Seek> Filesystem for ZffFs<R> {
        fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let mut entries = Vec::new();
        debug!("READDIR: Start readdir of inode {ino}");

        // sets the . directory which is always = ino
        entries.push((ino, FileType::Directory, String::from(CURRENT_DIR)));
        
        // check if we are in root - directory and list objects
        if ino == SPECIAL_INODE_ROOT_DIR {
            // sets the parent directory
            entries.push((SPECIAL_INODE_ROOT_DIR, FileType::Directory, String::from(PARENT_DIR)));

            // append appropriate objects
            for obj_number in self.cache.object_list.iter().filter(|(_, v)| v != &&ZffReaderObjectType::Encrypted).map(|(&k, _)| k) {
                let object_inode = obj_number + 1; //+ 1 while inode 1 is the root dir
                let name = format!("{OBJECT_PATH_PREFIX}{obj_number}");
                entries.push((object_inode, FileType::Directory, name));
            }

        } else if ino <= self.shift_value { //checks if the inode is a object folder
            // sets the parent directory
            entries.push((SPECIAL_INODE_ROOT_DIR, FileType::Directory, String::from(PARENT_DIR)));

            // set active object reader to appropriate inode
            if let Err(e) = self.zffreader.set_active_object(ino-1) {
                error!("An error occured while trying to readdir for inode {ino}: {e}");
                reply.error(ENOENT);
                return;
            }
            //check object type and use the appropriate fn
            match self.cache.object_list.get(&(ino-1)) {
                Some(ZffReaderObjectType::Encrypted) | None => {
                    error!("Could not find undecrypted object reader for object {}", ino-1);
                    reply.error(ENOENT);
                    return;
                },
                Some(ZffReaderObjectType::Physical) => match readdir_physical_object_root(&mut self.zffreader, self.shift_value) {
                    Ok(mut content) => entries.append(&mut content),
                    Err(e) => {
                        error!("Error while trying to read content of object directory of object {}: {e}", ino-1);
                        reply.error(ENOENT);
                        return;
                    }
                },
                Some(ZffReaderObjectType::Logical) => match readdir_logical_object_root(&mut self.zffreader, self.shift_value) {
                    Ok(mut content) => entries.append(&mut content),
                    Err(e) => {
                        error!("Error while trying to read content of object directory of object {}: {e}", ino-1);
                        reply.error(ENOENT);
                        return;
                    },
                },
            }
        //the following should only affect logical objects.
        } else {
            // setup self ino file
            let (object_no, file_no) = match self.cache.inode_reverse_map.get(&ino) {
                Some(x) => x,
                None =>  {
                    error!("Could not find inode {ino} in inode reverse map.");
                    reply.error(ENOENT);
                    return;
                }
            };
            let filemetadata_ref = match prepare_zffreader_logical_file(&mut self.zffreader, *object_no, *file_no) {
                Ok(fm) => fm,
                Err(e) =>  {
                    error!("An error occurred while trying to prepare zffreader: {e}");
                    reply.error(ENOENT);
                    return;
                },
            };

            //set parent directory entry
            entries.push((filemetadata_ref.parent_file_number+self.shift_value, FileType::Directory, String::from(PARENT_DIR)));
            let children = {
                let mut buffer = Vec::new();
                if let Err(e) = self.zffreader.read_to_end(&mut buffer) {
                    error!("Error while trying to read children list of file {file_no} / object {object_no}.");
                    debug!("{e}");
                    reply.error(ENOENT);
                    return;
                };
                match Vec::<u64>::decode_directly(&mut buffer.as_slice()) {
                    Ok(vec) => vec,
                    Err(e) => {
                        error!("An error occurred while decoding list of files of file {file_no} / object {object_no}.");
                        debug!("{e}");
                        reply.error(ENOENT);
                        return;
                    }
                }
            };

            //set children entries.
            let mut children_entries = match readdir_entries_file(&mut self.zffreader, self.shift_value, &children) {
                Ok(entries) => entries,
                Err(e) => {
                    error!("An error occurred while reading directory of file {file_no} / object {object_no}.");
                    debug!("{e}");
                    reply.error(ENOENT);
                    return;
                }
            };
            entries.append(&mut children_entries);
        };

        for (index, entry) in entries.into_iter().skip(offset as usize).enumerate() {
            let (inode, file_type, name) = entry;
            if reply.add(inode, offset + index as i64 + 1, file_type, name) {
                break;
            }
        }
        reply.ok();
    }
}


/*
#[derive(Debug)]
pub struct ZffOverlayFs {
    pub objects: HashMap<u64, FileAttr>, // <object_number, File attributes>
    pub undecryptable_objects: Vec<u64>, // <object number>,
    pub passwords_per_object: HashMap<u64, String>,//<object number, password>,
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

        //check encryption and try to decrypt
        let mut passwords_per_object = HashMap::new();

        for object_number in temp_zffreader.undecryptable_objects() {
            info!("MOUNT: Trying to decrypt object {object_number} ...");
            let mut decryption_state = false;
            'inner:  for password in decryption_passwords {
                let mut temp_pw_map = HashMap::new();
                temp_pw_map.insert(*object_number, password.to_string());

                let mut files = Vec::new();
                for path in &inputfiles {
                    let f = File::open(&path)?;
                    files.push(f);
                };
                let inner_temp_zffreader = match ZffReader::new(files, temp_pw_map) {
                    Ok(zffreader) => zffreader,
                    Err(e) => match e.get_kind() {
                        ZffErrorKind::PKCS5CryptoError => continue,
                        _ => return Err(e)
                    },
                };
                if !inner_temp_zffreader.undecryptable_objects().contains(object_number) {
                    passwords_per_object.insert(*object_number, password.to_string());
                    decryption_state = true;
                    break 'inner;
                }
            }
            if decryption_state {
                info!("MOUNT: ... done. Decryption of object {object_number} was successful.");
            } else {
                warn!("MOUNT: ... failed. Could not decrypt object {object_number} successfully.");
            }
        }

        let mut files = Vec::new();
        for path in &inputfiles {
            let f = File::open(&path)?;
            files.push(f);
        };
        let zffreader = ZffReader::new(files, passwords_per_object.clone())?;
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
            objects,
            undecryptable_objects: zffreader.undecryptable_objects().to_vec(),
            passwords_per_object,
            object_types_map,
            inode_attributes_map,
        };
        Ok(overlay_fs)
    }

    pub fn remove_passwords(&mut self) {
        //TODO: check if real zeroize is possible
        self.passwords_per_object = HashMap::new()
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
            if reply.add(inode, offset + index as i64 + 1, file_type, name) {
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
                        //This is a workaround: Some Desktop environments trying to lookup for folders like ".Trash" or ".Trash-1000", but these do not exist.
                        if unparsed_object_number == DEFAULT_TRASHFOLDER_NAME || unparsed_object_number == format!("{DEFAULT_TRASHFOLDER_NAME}-{}", Uid::effective()) {
                            reply.error(ENOENT);
                            return;
                        }

                        debug!("LOOKUP: error while trying to parse the object: {unparsed_object_number}");
                        reply.error(ENOENT);
                        return;
                    },
                },
            };
            let file_attr = match self.objects.get(&object_number) {
                None => {
                    debug!("LOOKUP: cannot find the appropriate file attributes for object number {object_number}");
                    reply.error(ENOENT);
                    return;
                },
                Some(file_attr) => file_attr,
            };
            reply.entry(&TTL, file_attr, DEFAULT_ENTRY_GENERATION);
        } else {
            debug!("LOOKUP: Parent ID {parent} not matching root inode dir {SPECIAL_INODE_ROOT_DIR}");
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match self.inode_attributes_map.get(&ino) {
            Some(file_attr) => reply.attr(&TTL, file_attr),
            None => if ino == SPECIAL_INODE_ROOT_DIR {
                reply.attr(&TTL, &DEFAULT_ROOT_DIR_ATTR)
            } else {
                debug!("GETATTR: unknown inode number: {ino}");
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
    pub fn new(segments: Vec<R>, object_number: u64, decryption_password: Option<&String>) -> Result<ZffPhysicalObjectFs<R>> {
        let mut decryption_map = HashMap::new();
        if let Some(decryption_password) = decryption_password {
            decryption_map.insert(object_number, decryption_password.to_string());
        }
        let mut zffreader = ZffReader::new(segments, decryption_map)?;

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
            size,
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
            object_number,
            file_attr,
            object_file_attr,
            zffreader
        })
    }
}

impl<R: Read + Seek> Filesystem for ZffPhysicalObjectFs<R> {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == SPECIAL_INODE_ROOT_DIR && name.to_str() == Some(ZFF_PHYSICAL_OBJECT_NAME) {     
            reply.entry(&TTL, &self.file_attr, DEFAULT_ENTRY_GENERATION);
        } else {
            //This is a workaround: Some Desktop environments trying to lookup for folders like ".Trash" or ".Trash-1000", but these do not exist.
            if name.to_str() == Some(DEFAULT_TRASHFOLDER_NAME) || name.to_str() == Some(&format!("{DEFAULT_TRASHFOLDER_NAME}-{}", Uid::effective())) {
                reply.error(ENOENT);
                return;
            }
            debug!("LOOKUP: unknown parent ID / name combination. Parent ID: {parent}; name: {:?}", name.to_str());
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match ino {
            SPECIAL_INODE_ROOT_DIR => reply.attr(&TTL, &self.object_file_attr),
            ZFF_OBJECT_FS_PHYSICAL_ATTR_INO => reply.attr(&TTL, &self.file_attr),
            _ => {
                debug!("GETATTR: unknown inode number: {ino}");
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
            if reply.add(inode, offset + index as i64 + 1, file_type, name) {
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
    pub fn new(segments: Vec<R>, object_number: u64, decryption_password: Option<&String>) -> Result<ZffLogicalObjectFs<R>> {
        let mut decryption_map = HashMap::new();
        if let Some(decryption_password) = decryption_password {
            decryption_map.insert(object_number, decryption_password.to_string());
        }
        let mut zffreader = ZffReader::new(segments, decryption_map)?;

        let object = match zffreader.object(object_number) {
            Some(obj) => obj.clone(),
            None => return Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string())),
        };
        
        let object_info = match &object {
            Object::Physical(_) => return Err(ZffError::new(ZffErrorKind::MismatchObjectType, "")),
            Object::Logical(object_info) => object_info,
        };

        let initial_file_number = match object_info.footer().root_dir_filenumbers().iter().next() {
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
            object_number,
            object_file_attr,
            zffreader,
        })
    }

    fn file_attr(&mut self, filenumber: u64) -> Result<FileAttr> {
        let mut filenumber = filenumber;
        self.zffreader.set_reader_logical_object_file(self.object_number, filenumber)?;
        let fileinformation = self.zffreader.file_information()?;
        let mut size = fileinformation.length_of_data();
        let acquisition_start = match OffsetDateTime::from_unix_timestamp(fileinformation.footer().acquisition_start() as i64) {
            Ok(time) => time.into(),
            Err(_) => UNIX_EPOCH,
        };

        let acquisition_end = match OffsetDateTime::from_unix_timestamp(fileinformation.footer().acquisition_end() as i64) {
            Ok(time) => time.into(),
            Err(_) => UNIX_EPOCH,
        };

        if fileinformation.header().file_type() == ZffFileType::Hardlink {
            self.zffreader.rewind()?;
            let mut buffer = vec![0u8; size as usize];
            self.zffreader.read_exact(&mut buffer)?;
            let mut cursor = Cursor::new(buffer);
            filenumber = u64::decode_directly(&mut cursor)?;
            let linked_fileinformation = {
                self.zffreader.set_reader_logical_object_file(self.object_number, filenumber)?;
                self.zffreader.file_information()?
            };
            size = linked_fileinformation.length_of_data();
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
            size,
            blocks: size / DEFAULT_BLOCKSIZE as u64 + 1,
            atime: acquisition_end,
            mtime: acquisition_end,
            ctime: acquisition_end,
            crtime: acquisition_start,
            kind,
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
        let children = if parent == SPECIAL_INODE_ROOT_DIR {
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
                    error!("LOOKUP: Read error: {e}");
                    reply.error(ENOENT);
                    return;
                },
            }
            if buffer.is_empty() {
                Vec::new()
            } else {
                let mut cursor = Cursor::new(&buffer);
                let children = match Vec::<u64>::decode_directly(&mut cursor) {
                        Ok(children) => children,
                        Err(e) => {
                            error!("LOOKUP: {e}");
                            reply.error(ENOENT);
                            return;
                    },
                };
                children
            }
        };
        for filenumber in children {
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
        debug!("READDIR: Start readdir of inode {ino}");
        let children = if ino == SPECIAL_INODE_ROOT_DIR {
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
                    error!("READDIR: Read error: {e}");
                    reply.error(ENOENT);
                    return;
                },
            }
            if buffer.is_empty() {
                Vec::new()
            } else {
                let mut cursor = Cursor::new(&buffer);
                let children = match Vec::<u64>::decode_directly(&mut cursor) {
                        Ok(children) => children,
                        Err(e) => {
                            error!("READDIR: {e}");
                            reply.error(ENOENT);
                            return;
                    },
                };
                children
            }
        };
        debug!("READDIR: children in dir: {:?}", children);

        for child_filenumber in children {
            let fileinformation = match self.zffreader.set_reader_logical_object_file(self.object_number, child_filenumber) {
                Ok(_) => match self.zffreader.file_information() {
                    Ok(fileinformation) => fileinformation,
                    Err(e) => {
                        let object_number = self.object_number;
                        error!("READDIR: error while trying to read fileinformation(1) for file {child_filenumber} in object {object_number}. Internal error message: {e}");
                        reply.error(ENOENT);
                        return;
                    }
                },
                Err(e) => {
                    let object_number = self.object_number;
                    error!("READDIR: error while trying to read fileinformation(2) for file {child_filenumber} in object {object_number}. Internal error message: {e}");
                    reply.error(ENOENT);
                    return;
                }
            };

            let kind = match fileinformation.header().file_type() {
                ZffFileType::File => FileType::RegularFile,
                ZffFileType::Directory => FileType::Directory,
                ZffFileType::Symlink => FileType::Symlink,
                ZffFileType::Hardlink => FileType::RegularFile, //TODO: hardlink of a directory?
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
            if reply.add(inode, offset + index as i64 + 1, file_type, name) {
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
        if fileinformation.header().file_type() == ZffFileType::Hardlink {
            match self.zffreader.rewind() {
                Ok(_) => (),
                Err(_) => {
                    reply.error(ENOENT);
                    return;
                }
            }
            let link_size = fileinformation.length_of_data();
            let mut buffer = vec![0u8; link_size as usize];
            match self.zffreader.read(&mut buffer) {
                Ok(_) => (),
                Err(e) => {
                    error!("READ: error: {e}");
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

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
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
            ZffFileType::Symlink => (),
            _ => {
                reply.error(ENOENT);
                return;
            },
        };

        match self.zffreader.rewind() {
            Ok(_) => (),
            Err(e) => {
                error!("READ: {e}");
                reply.error(ENOENT);
                return;
            }
        }
        let mut string_buffer = Vec::new();
        match self.zffreader.read_to_end(&mut string_buffer) {
            Ok(_) => (),
            Err(e) => {
                error!("READ: {e}");
                reply.error(ENOENT);
                return;
            }
        }
        let mut cursor = Cursor::new(string_buffer);
        match String::decode_directly(&mut cursor) {
            Ok(path) => reply.data(path.as_bytes()),
            Err(e) => {
                error!("READ: DECODE LINK PATH: {e}");
                reply.error(ENOENT);   
            }
        };
    }
}*/

fn enter_password_dialog(obj_no: u64) -> Option<String> {
    match PasswordDialog::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("Enter the password for object {obj_no}"))
        .interact() {
            Ok(pw) => Some(pw),
            Err(_) => None
        }
}

fn readdir_physical_object_root<R: Read + Seek>(zffreader: &mut ZffReader<R>, shift_value: u64) -> Result<Vec<(u64, FileType, String)>> {
    let chunk_no = match zffreader.active_object_footer()? {
        ObjectFooter::Physical(footer) => footer.first_chunk_number,
        _ => return Err(ZffError::new(ZffErrorKind::MismatchObjectType, "logical")),
    };
    Ok(vec![(
        chunk_no+shift_value, 
        FileType::RegularFile, 
        ZFF_PHYSICAL_OBJECT_NAME.to_string()
        )])
}

fn readdir_logical_object_root<R: Read + Seek>(zffreader: &mut ZffReader<R>, shift_value: u64) -> Result<Vec<(u64, FileType, String)>> {
    if let ObjectFooter::Logical(footer) = zffreader.active_object_footer()? {
        readdir_entries_file(zffreader, shift_value, footer.root_dir_filenumbers())
    } else {
        Err(ZffError::new(ZffErrorKind::MismatchObjectType, "physical"))
    }
}

fn readdir_entries_file<R: Read + Seek>(zffreader: &mut ZffReader<R>, shift_value: u64, children: &Vec<u64>) -> Result<Vec<(u64, FileType, String)>> {
    let mut entries = Vec::new();
    for filenumber in children {
        zffreader.set_active_file(*filenumber)?;
        let mut filemetadata = zffreader.current_filemetadata()?.clone();
        let mut zff_filetype = match filemetadata.file_type {
            Some(ftype) => ftype,
            None => zffreader.current_fileheader()?.file_type
        };
        if zff_filetype == ZffFileType::Hardlink {
            let mut buffer = Vec::new();
            zffreader.read_to_end(&mut buffer)?;
            let original_filenumber = u64::decode_directly(&mut buffer.as_slice())?;
            zffreader.set_active_file(original_filenumber)?;
            filemetadata = zffreader.current_filemetadata()?.clone();
            zff_filetype = match filemetadata.file_type {
                Some(ftype) => ftype,
                None => zffreader.current_fileheader()?.file_type
            };
        }
        let inode = filemetadata.first_chunk_number + shift_value;
        let filetype = convert_filetype(&zff_filetype, zffreader)?;
        let filename = match filemetadata.filename {
            Some(ftype) => ftype,
            None => zffreader.current_fileheader()?.filename
        };
        entries.push((inode, filetype, filename.to_string()));
    }

    Ok(entries)
}

// hardlinks should be handled before calling this method.
fn convert_filetype<R: Read + Seek>(in_type: &ZffFileType, zffreader: &mut ZffReader<R>) -> Result<FileType> {
    let filetype = match in_type {
        ZffFileType::File => FileType::RegularFile,
        ZffFileType::Directory => FileType::Directory,
        ZffFileType::Symlink => FileType::Symlink,
        ZffFileType::Hardlink => unreachable!(),
        ZffFileType::SpecialFile => {
            let mut buffer = Vec::new();
            zffreader.read_to_end(&mut buffer)?;
            let filetype_flag = match buffer.last() {
                Some(byte) => ZffSpecialFileType::try_from(byte)?,
                None => return Err(ZffError::new(ZffErrorKind::UnknownFileType, format!("{:?}", buffer))),
            };
            match filetype_flag {
                ZffSpecialFileType::Fifo => FileType::NamedPipe,
                ZffSpecialFileType::Char => FileType::CharDevice,
                ZffSpecialFileType::Block => FileType::BlockDevice,
                _ => unimplemented!()
            }
        },
        _ => unimplemented!()
    };
    Ok(filetype)
}

// returns the number of entries which were added.
fn inode_reverse_map_add_object<R: Read + Seek>(
    zffreader: &mut ZffReader<R>,
    inode_reverse_map: &mut BTreeMap<u64, (u64, u64)>,
    object_number: u64,
    shift_value: u64) -> Result<u64> {
    zffreader.set_active_object(object_number)?;
    let mut counter = 0;
    let object_footer = match zffreader.active_object_footer()? {
        ObjectFooter::Logical(log) => log,
        ObjectFooter::Physical(phy) => return Err(ZffError::new(ZffErrorKind::MismatchObjectType, format!("{:?}", phy))),
    };
    for filenumber in object_footer.file_footer_segment_numbers().keys() {
        zffreader.set_active_file(*filenumber)?;
        let inode = zffreader.current_filemetadata()?.first_chunk_number + shift_value;
        inode_reverse_map.insert(inode, (object_number, *filenumber));
        counter += 1;
    }
    Ok(counter)
}

fn prepare_zffreader_logical_file<R: Read + Seek>(
    zffreader: &mut ZffReader<R>, 
    object_no: u64,
    file_no: u64) -> Result<&FileMetadata> {
    zffreader.set_active_object(object_no)?;
    zffreader.set_active_file(file_no)?;
    zffreader.current_filemetadata()
}