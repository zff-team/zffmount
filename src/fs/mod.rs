// - STD
use std::collections::BTreeMap;
use std::process::exit;
use std::ffi::OsStr;


use std::time::UNIX_EPOCH;
use std::io::{Read, Seek, SeekFrom};
use std::collections::HashMap;

// - internal
use super::constants::*;
use zff::{
    Result,
    header::{FileType as ZffFileType, SpecialFileType as ZffSpecialFileType},
    footer::ObjectFooter,
    ValueDecoder,
    io::zffreader::{ZffReader, ObjectType as ZffReaderObjectType, FileMetadata},
    ZffError,
    ZffErrorKind,
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
use time::OffsetDateTime;
use dialoguer::{theme::ColorfulTheme, Password as PasswordDialog};

#[derive(Debug)]
pub enum PreloadChunkmapsMode {
    None,
    InMemory,
    Redb(redb::Database)
}

#[derive(Debug)]
pub struct PreloadChunkmaps {
    pub headers: bool,
    pub samebytes: bool,
    pub deduplication: bool,
    pub mode: PreloadChunkmapsMode
}


#[derive(Debug, Clone, Eq, PartialEq)]
struct ZffFsCache {
    pub object_list: BTreeMap<u64, ZffReaderObjectType>,
    pub inode_reverse_map: BTreeMap<u64, (u64, u64)>, //<Inode, (object number, file number)
    pub filename_lookup_table: BTreeMap<String, Vec<(u64, u64)>>, //<Filename, Vec<Parent-Inode, Self-Inode>>
    pub inode_attributes_map: BTreeMap<u64, FileAttr>,
}

impl ZffFsCache {
    fn with_data(
        object_list: BTreeMap<u64, ZffReaderObjectType>,
        inode_reverse_map: BTreeMap<u64, (u64, u64)>,
        filename_lookup_table: BTreeMap<String, Vec<(u64, u64)>>,
        inode_attributes_map: BTreeMap<u64, FileAttr>) -> Self 
    {
        Self {
            object_list,
            inode_reverse_map,
            filename_lookup_table,
            inode_attributes_map,
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
    pub fn new(
        inputfiles: Vec<R>, 
        decryption_passwords: &HashMap<u64, String>, 
        preload_chunkmaps: PreloadChunkmaps) -> Self {
        info!("Reading segment files to create initial ZffReader.");
        let mut zffreader = match ZffReader::with_reader(inputfiles) {
            Ok(reader) => reader,
            Err(e) => {
                error!("An error occurred while trying to create the ZffReader: {e}");
                exit(EXIT_STATUS_ERROR);
            }
        };

        let mut object_list = match zffreader.list_objects() {
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
                ZffReaderObjectType::Virtual => todo!(), //TODO
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

        // from here, we can work with unencrypted/decrypted objects.
        object_list = zffreader.list_decrypted_objects();

        // set object inodes and shift value
        let numbers_of_decrypted_objects: Vec<u64> = object_list.iter().map(|(&k, _)| k).collect();
        let shift_value = match numbers_of_decrypted_objects.iter().max() {
            Some(value) => *value + 1, // + 1 for root dir inode
            None => 1,
        };

        let mut inode_reverse_map = BTreeMap::new();
        let mut filename_lookup_table = BTreeMap::new();
        let mut inode_attributes_map = BTreeMap::new();

        for (object_number, obj_type) in &object_list {
            //setup inode reverse map
            match inode_reverse_map_add_object(&mut zffreader, &mut inode_reverse_map, *object_number, shift_value) {
                Ok(noe) => debug!("{noe} entries for object {object_number} added to inode reverse map."),
                Err(e) => {
                    error!("An error occurred while trying to fill the inode reverse map.");
                    debug!("{e}");
                    exit(EXIT_STATUS_ERROR);
                }
            };  

            //setup inode attributes map
            match inode_attributes_map_add_object(&mut zffreader, &mut inode_attributes_map, *object_number, shift_value) {
                Ok(noe) => debug!("{noe} entries for object {object_number} added to inode attributes map."),
                Err(e) => {
                    error!("An error occurred while trying to fill the inode attributes map.");
                    debug!("{e}");
                    exit(EXIT_STATUS_ERROR);
                }
            };

            // only for logical objects
            if obj_type == &ZffReaderObjectType::Logical {
                //setup lookup table
                match filename_lookup_table_add_object(&mut zffreader, &mut filename_lookup_table, *object_number, shift_value) {
                    Ok(noe) => debug!("{noe} entries for object {object_number} added to lookup table."),
                    Err(e) => {
                        error!("An error occurred while trying to fill the lookup table.");
                        debug!("{e}");
                        exit(EXIT_STATUS_ERROR);
                    }
                };
            }
        }
        let cache = ZffFsCache::with_data(object_list, inode_reverse_map, filename_lookup_table, inode_attributes_map);

        // setup mode
        match preload_chunkmaps.mode {
            PreloadChunkmapsMode::None => (),
            PreloadChunkmapsMode::InMemory => {
                info!("Set preload chunkmap mode to in-memory ...");
                if let Err(e) = zffreader.set_preload_chunkmaps_mode_in_memory() {
                    error!("An error occurred while trying to create the in memory preload chunkmap.");
                    debug!("{e}");
                    exit(EXIT_STATUS_ERROR);
                };
            }
            PreloadChunkmapsMode::Redb(db) => {
                info!("Set preload chunkmap mode to redb ...");
                if let Err(e) = zffreader.set_preload_chunkmap_mode_redb(db) {
                    error!("An error occurred while trying to create the redb preload chunkmap.");
                    debug!("{e}");
                    exit(EXIT_STATUS_ERROR);
                };
            }
        }

        // preload appropriate chunkmaps
        if preload_chunkmaps.headers {
            info!("Preload chunk header map ...");
            if let Err(e) = zffreader.preload_chunk_header_map_full() {
                error!("An error occurred while trying to preload chunkmap.");
                debug!("{e}");
                exit(EXIT_STATUS_ERROR);
            };
            info!("Chunk header map successfully preloaded ...");
        }

        if preload_chunkmaps.samebytes {
            info!("Preload chunkmap samebytes ...");
            if let Err(e) = zffreader.preload_chunk_samebytes_map_full() {
                error!("An error occurred while trying to preload chunkmap.");
                debug!("{e}");
                exit(EXIT_STATUS_ERROR);
            };
            info!("Chunkmap samebytes successfully preloaded ...");
        }

        if preload_chunkmaps.deduplication {
            info!("Preload chunkmap deduplication ...");
            if let Err(e) = zffreader.preload_chunk_deduplication_map_full() {
                error!("An error occurred while trying to preload chunkmap.");
                debug!("{e}");
                exit(EXIT_STATUS_ERROR);
            };
            info!("Chunkmap deduplication successfully preloaded ...");
        }

        info!("ZffFs successfully initialized and can be used now.");

        Self {
            zffreader,
            shift_value,
            cache,
        }
    }
}

impl<R: Read + Seek> Filesystem for ZffFs<R> {
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
        if offset < 0 {
            error!("READ: offset >= 0 -> offset = {offset}");
            reply.error(ENOENT);
            return;
        }
        if ino < self.shift_value {
            unreachable!()
        } else {
            let (object_no, file_no) = match self.cache.inode_reverse_map.get(&ino) {
                Some(data) => data,
                None => {
                    error!("Error while trying to read data from inode {ino}: Inode not found in inode reverse map.");
                    reply.error(ENOENT);
                    return;
                }
            };

            //check if this is a physical object.
            // we've stored inodes to physical objects in inode map by using the file number 0 as placeholder earlier.
            if *file_no == 0 {
                if let Err(e) = self.zffreader.set_active_object(*object_no) {
                    error!("An error occurred while trying to set object {object_no} as active.");
                    debug!("{e}");
                    reply.error(ENOENT);
                    return;
                }
            } else {
                // if the object is a logical object, we have to do some more stuff.
                // sets the appropriate object and file active and returns the appropriate file-  
                // metadata (which is not needed at this point).
                let _ = match prepare_zffreader_logical_file(&mut self.zffreader, *object_no, *file_no) {
                    Err(e) => {
                        error!("Error while trying to set file {file_no} of object {object_no} active.");
                        debug!("{e}");
                        reply.error(ENOENT);
                        return;
                    },
                    Ok(metadata) => metadata
                };
            }
            
            match self.zffreader.seek(SeekFrom::Start(offset as u64)) {
                Ok(_) => (),
                Err(e) => {
                    error!("read error 0x1 for inode {ino}.");
                    debug!("{e}");
                    reply.error(ENOENT);
                    return;
                }
            }
            let mut buffer = vec![0u8; size as usize];
            debug!("Fill buffer by reading data at offset {offset} with buffer size of {size}.");
            match self.zffreader.read(&mut buffer) {
                Ok(_) => (),
                Err(e) => {
                    error!("read error 0x2 for inode {ino}.");
                    debug!("{e}");
                    reply.error(ENOENT);
                    return
                }
            }
            reply.data(&buffer);
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
                Some(ZffReaderObjectType::Virtual) => todo!(), //TODO
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
                //seeks the reader to start position to read all content of the directory (again)
                if let Err(e) = self.zffreader.rewind() {
                    error!("Error while trying to seek the children-list of file {file_no} / object {object_no}.");
                    debug!("{e}");
                    reply.error(ENOENT);
                    return;
                }
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
            debug!("READDIR entry added: inode: {inode}, index: {}, file_type: {:?}, name: {name}", offset + index as i64 + 1, file_type);
            if reply.add(inode, offset + index as i64 + 1, file_type, name) {
                break;
            }
        }
        reply.ok();
    }

    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        debug!("Starting LOOKUP request: parent inode: \"{parent}\"; name: {:?}.", name);
        let name = match name.to_str() {
            Some(name) => name,
            None => {
                error!("LOOKUP: Error while trying to convert name: {:?}", name);
                reply.error(ENOENT);
                return;
            }
        };
        //handle root directory with the "object_" directories.
        if parent == SPECIAL_INODE_ROOT_DIR {
            let mut split = name.rsplit(OBJECT_PREFIX);
            let object_number = match split.next() {
                None => {
                    error!("LOOKUP: object prefix not in filename. This is an application bug. The filename is {name}");
                    reply.error(ENOENT);
                    return;
                },
                Some(unparsed_object_number) => match unparsed_object_number.parse::<u64>() {
                    Ok(object_number) => object_number,
                    Err(e) => {
                        //This is a workaround: Some Desktop environments trying to lookup for folders like ".Trash" or ".Trash-1000", but these do not exist.
                        if  unparsed_object_number == DEFAULT_TRASHFOLDER_NAME || unparsed_object_number == format!("{DEFAULT_TRASHFOLDER_NAME}-{}", Uid::effective()) {
                            debug!("Cannot access trashfolders.");
                            reply.error(ENOENT);
                            return;
                        }
                        //this is only a debuggable error, as the bash/zsh completition could generate a huge number of those messages.
                        debug!("LOOKUP: Error while trying to parse the object: \"{unparsed_object_number}\" for original name: {name}; {e}");
                        reply.error(ENOENT);
                        return;
                    },
                },
            };

            // get the appropriate attributes of the object directory - by using object number +1 shift value.
            let file_attr = match self.cache.inode_attributes_map.get(&(object_number+1)) {
                Some(file_attr) => file_attr,
                None => {
                    debug!("GETATTR: unknown inode number: {}", object_number+1);
                    reply.error(ENOENT);
                    return;
                },
            };
            debug!("LOOKUP: returned entry attr(1): {:?}", &file_attr);
            reply.entry(&TTL, file_attr, DEFAULT_ENTRY_GENERATION);

        } else if parent <= self.shift_value { //checks if the parent is a object folder
            // set active object reader to appropriate parent
            if let Err(e) = self.zffreader.set_active_object(parent-1) {
                error!("LOOKUP: An error occured while trying to lookup for inode {parent}.");
                debug!("{e}");
                reply.error(ENOENT);
                return;
            }
            //check object type and use the appropriate fn
            match self.cache.object_list.get(&(parent-1)) {
                Some(ZffReaderObjectType::Encrypted) | None => {
                    error!("LOOKUP: Could not find undecrypted object reader for object {}", parent-1);
                    reply.error(ENOENT);
                    return;
                },
                Some(ZffReaderObjectType::Physical) => if name == ZFF_PHYSICAL_OBJECT_NAME {
                    let object_footer = match self.zffreader.active_object_footer() {
                        Ok(footer) => match footer { ObjectFooter::Physical(phy) => phy, _ => unreachable!() },
                        Err(e) => {
                            error!("LOOKUP: cannot find the object footer of object {}", parent-1);
                            debug!("{e}");
                            reply.error(ENOENT);
                            return;
                        }
                    };
                    let ino = object_footer.first_chunk_number + self.shift_value;
                    // get the appropriate attributes of the object data file.
                    let file_attr = match self.cache.inode_attributes_map.get(&ino) {
                        Some(file_attr) => file_attr,
                        None => {
                            debug!("GETATTR: unknown inode number: {}", ino);
                            reply.error(ENOENT);
                            return;
                        },
                    };
                    debug!("LOOKUP: returned entry attr(2): {:?}", &file_attr);
                    reply.entry(&TTL, file_attr, DEFAULT_ENTRY_GENERATION);
                } else {
                    debug!("Error while trying to lookup for {name} in object {}", parent-1);
                    reply.error(ENOENT);
                    return;
                },
                Some(ZffReaderObjectType::Logical) => if let Some(lookup_table_entries) = self.cache.filename_lookup_table.get(name) {
                    for (parent_inode, inode) in lookup_table_entries {
                        if parent == *parent_inode {
                            match self.cache.inode_attributes_map.get(inode) {
                                Some(attr) => {
                                    debug!("LOOKUP: returned entry attr(3): {:?}", &attr);
                                    reply.entry(&TTL, attr, DEFAULT_ENTRY_GENERATION);
                                    return;
                                },
                                None => {
                                    error!("An error occurred while trying to get file attributes of inode {inode}.");
                                    reply.error(ENOENT);
                                    return;
                                }
                            }
                        }
                    }
                } else {
                    debug!("Error while trying to lookup for {name} in object {}", parent-1);
                    reply.error(ENOENT);
                    return;
                }
                Some(ZffReaderObjectType::Virtual) => todo!(), //TODO
            }
        } else if let Some(lookup_table_entries) = self.cache.filename_lookup_table.get(name) {
            for (parent_inode, inode) in lookup_table_entries {
                if parent == *parent_inode {
                    match self.cache.inode_attributes_map.get(inode) {
                        Some(attr) => {
                            debug!("LOOKUP: returned entry-attr(4): {:?}.", attr);
                            reply.entry(&TTL, attr, DEFAULT_ENTRY_GENERATION);
                            return;
                        },
                        None => {
                            error!("An error occurred while trying to get file attributes of inode {inode}.");
                            reply.error(ENOENT);
                            return;
                        }
                    }
                }
            }
        } else {
            debug!("Error while trying to lookup for {name} in object {}", parent-1);
            reply.error(ENOENT);
            return;
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        if ino < self.shift_value {
            error!("Inode {ino} is not a link.");
           reply.error(ENOENT);
        } else {
            let (object_no, file_no) = match self.cache.inode_reverse_map.get(&ino) {
                Some(data) => data,
                None => {
                    error!("Error while trying to read data from inode {ino}: Inode not found in inode reverse map.");
                    reply.error(ENOENT);
                    return;
                }
            };

            //check if this is a physical object.
            // we've stored inodes to physical objects in inode map by using the file number 0 as placeholder earlier.
            if *file_no == 0 {
               error!("Inode {ino} is not a link.");
               reply.error(ENOENT);
            } else {
                // if the object is a logical object, we have to do some more stuff.
                // sets the appropriate object and file active and returns the appropriate filemetadata
                let filemetadata = match prepare_zffreader_logical_file(&mut self.zffreader, *object_no, *file_no) {
                    Err(e) => {
                        error!("Error while trying to set file {file_no} of object {object_no} active.");
                        debug!("{e}");
                        reply.error(ENOENT);
                        return;
                    },
                    Ok(metadata) => metadata
                };

                if filemetadata.file_type != ZffFileType::Symlink {
                    error!("File {file_no} is not a link.");
                    debug!("{:?}", filemetadata);
                    reply.error(ENOENT);
                    return;
                }
                
                match self.zffreader.seek(SeekFrom::Start(0)) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("read error 0x3 for inode {ino}.");
                        debug!("{e}");
                        reply.error(ENOENT);
                        return;
                    }
                }
                let mut buffer = Vec::new();
                match self.zffreader.read_to_end(&mut buffer) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("read error 0x4 for inode {ino}.");
                        debug!("{e}");
                        reply.error(ENOENT);
                        return
                    }
                }
                reply.data(&buffer);
            }
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match self.cache.inode_attributes_map.get(&ino) {
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
        _ => return Err(ZffError::new(ZffErrorKind::Invalid, ERR_INVALID_OBJECT_TYPE)),
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
        Err(ZffError::new(ZffErrorKind::Invalid, ERR_INVALID_OBJECT_TYPE))
    }
}

fn readdir_entries_file<R: Read + Seek>(zffreader: &mut ZffReader<R>, shift_value: u64, children: &Vec<u64>) -> Result<Vec<(u64, FileType, String)>> {
    let mut entries = Vec::new();
    for filenumber in children {
        zffreader.set_active_file(*filenumber)?;
        let mut filemetadata = zffreader.current_filemetadata()?.clone();
        let mut zff_filetype = filemetadata.file_type;
        if zff_filetype == ZffFileType::Hardlink {
            let mut buffer = Vec::new();
            zffreader.rewind()?;
            zffreader.read_to_end(&mut buffer)?;
            let original_filenumber = u64::decode_directly(&mut buffer.as_slice())?;
            zffreader.set_active_file(original_filenumber)?;
            filemetadata = zffreader.current_filemetadata()?.clone();
            zff_filetype = filemetadata.file_type;
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
                None => return Err(ZffError::new(ZffErrorKind::Unsupported, format!("{:?}", buffer))),
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
    match zffreader.active_object_footer()? {
        ObjectFooter::Logical(object_footer) => {
            for filenumber in object_footer.file_footer_segment_numbers().keys() {
                zffreader.set_active_file(*filenumber)?;

                let filemetadata = zffreader.current_filemetadata()?;
                let mut inode = filemetadata.first_chunk_number + shift_value;
                
                // checks if the file is a hardlink. In that case, the original file hould be added
                if filemetadata.file_type == ZffFileType::Hardlink {
                    let mut buffer = Vec::new();
                    zffreader.read_to_end(&mut buffer)?;
                    let original_filenumber = u64::decode_directly(&mut buffer.as_slice())?;
                    zffreader.set_active_file(original_filenumber)?;
                    let filemetadata = zffreader.current_filemetadata()?.clone();
                    inode = filemetadata.first_chunk_number + shift_value;
                }
                inode_reverse_map.insert(inode, (object_number, *filenumber));
                counter += 1;
            }
        },
        ObjectFooter::Physical(object_footer) => {
            let inode = object_footer.first_chunk_number + shift_value;
            inode_reverse_map.insert(inode, (object_number, 0)); //0 is not a valid file number in zff, so we can use this as a placeholder
            counter += 1;
        },
        ObjectFooter::Virtual(_) => todo!(), //TODO
    };
    
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

fn filename_lookup_table_add_object<R: Read + Seek>(
    zffreader: &mut ZffReader<R>, 
    lookup_table: &mut BTreeMap<String, Vec<(u64, u64)>>, //<Filename, Vec<Parent-Inode, Self-Inode>>
    object_number: u64, 
    shift_value: u64) -> Result<u64> {
    zffreader.set_active_object(object_number)?;
    let mut counter = 0;


    let object_footer = match zffreader.active_object_footer()? {
        ObjectFooter::Logical(log) => log,
        ObjectFooter::Physical(phy) => return Err(ZffError::new(ZffErrorKind::Invalid, format!("{:?}", phy))),
        ObjectFooter::Virtual(_) => todo!(), //TODO
    };
    for filenumber in object_footer.file_footer_segment_numbers().keys() {
        zffreader.set_active_file(*filenumber)?;
        
        let filemetadata = zffreader.current_filemetadata()?.clone();
        let mut inode = filemetadata.first_chunk_number + shift_value;

        // checks if the file is a hardlink. In that case, the original file hould be added
        if filemetadata.file_type == ZffFileType::Hardlink {
            let mut buffer = Vec::new();
            zffreader.read_to_end(&mut buffer)?;
            let original_filenumber = u64::decode_directly(&mut buffer.as_slice())?;
            zffreader.set_active_file(original_filenumber)?;
            let filemetadata = zffreader.current_filemetadata()?.clone();
            inode = filemetadata.first_chunk_number + shift_value;
        }
        //reset the to the hardlink to get the filename of the hardlink.
        zffreader.set_active_file(*filenumber)?;

        let filename = match filemetadata.filename {
            Some(fname) => fname,
            None => zffreader.current_fileheader()?.filename
        };
        let parent_file_number = filemetadata.parent_file_number;
        let parent_inode = if parent_file_number>0 {
            zffreader.set_active_file(parent_file_number)?;
            zffreader.current_filemetadata()?.first_chunk_number + shift_value
        } else {
            object_number + 1 //if the file sits in root directory.
        };

        match lookup_table.get_mut(&filename) {
            Some(inner_vec) => inner_vec.push((parent_inode, inode)),
            None => { let inner_vec = vec![(parent_inode, inode)]; lookup_table.insert(filename, inner_vec); },
        };
        counter += 1;
    }

    Ok(counter)
}


fn file_attr_of_file<R: Read + Seek>(mut filemetadata: FileMetadata, zffreader: &mut ZffReader<R>, shift_value: u64) -> Result<FileAttr> {
    let mut zff_filetype = filemetadata.file_type;
    if zff_filetype == ZffFileType::Hardlink {
        let mut buffer = Vec::new();
        zffreader.read_to_end(&mut buffer)?;
        let original_filenumber = u64::decode_directly(&mut buffer.as_slice())?;
        zffreader.set_active_file(original_filenumber)?;
        filemetadata = zffreader.current_filemetadata()?.clone();
        zff_filetype = filemetadata.file_type;
    }
    let filetype = convert_filetype(&zff_filetype, zffreader)?;

    let atime = match filemetadata.metadata_ext.get(ATIME) {
        Some(atime) => if let Some(atime) = atime.as_any().downcast_ref::<u64>() {
            *atime as i64
        } else {
            0
        },
        None => match zffreader.current_fileheader()?.metadata_ext.get(ATIME) {
            Some(atime) => if let Some(atime) = atime.as_any().downcast_ref::<u64>() {
                *atime as i64
            } else {
                0
            },
            None => 0
        }
    };
    let atime = match OffsetDateTime::from_unix_timestamp(atime) {
        Ok(atime) => atime.into(),
        Err(_) => UNIX_EPOCH,
    };

    let mtime = match filemetadata.metadata_ext.get(MTIME) {
        Some(mtime) => if let Some(mtime) = mtime.as_any().downcast_ref::<u64>() {
            *mtime as i64
        } else {
            0
        },
        None => match zffreader.current_fileheader()?.metadata_ext.get(MTIME) {
            Some(mtime) => if let Some(mtime) = mtime.as_any().downcast_ref::<u64>() {
                *mtime as i64
            } else {
                0
            },
            None => 0
        }
    };
    let mtime = match OffsetDateTime::from_unix_timestamp(mtime) {
        Ok(mtime) => mtime.into(),
        Err(_) => UNIX_EPOCH,
    };

    let ctime = match filemetadata.metadata_ext.get(CTIME) {
        Some(ctime) => if let Some(ctime) = ctime.as_any().downcast_ref::<u64>() {
            *ctime as i64
        } else {
            0
        },
        None => match zffreader.current_fileheader()?.metadata_ext.get(CTIME) {
            Some(ctime) => if let Some(ctime) = ctime.as_any().downcast_ref::<u64>() {
                *ctime as i64
            } else {
                0
            },
            None => 0
        }
    };
    let ctime = match OffsetDateTime::from_unix_timestamp(ctime) {
        Ok(ctime) => ctime.into(),
        Err(_) => UNIX_EPOCH,
    };

    let btime = match filemetadata.metadata_ext.get(BTIME) {
        Some(btime) => if let Some(btime) = btime.as_any().downcast_ref::<u64>() {
            *btime as i64
        } else {
            0
        },
        None => match zffreader.current_fileheader()?.metadata_ext.get(BTIME) {
            Some(btime) => if let Some(btime) = btime.as_any().downcast_ref::<u64>() {
                *btime as i64
            } else {
                0
            },
            None => 0
        }
    };
    let btime = match OffsetDateTime::from_unix_timestamp(btime) {
        Ok(btime) => btime.into(),
        Err(_) => UNIX_EPOCH,
    };

    Ok(FileAttr {
        ino: filemetadata.first_chunk_number + shift_value,
        size: filemetadata.length_of_data,
        blocks: filemetadata.length_of_data / DEFAULT_BLOCKSIZE as u64 + 1,
        atime,
        mtime,
        ctime,
        crtime: btime,
        kind: filetype,
        perm: 0o755,
        nlink: 1,
        uid: Uid::effective().into(),
        gid: Gid::effective().into(),
        rdev: 0,
        flags: 0,
        blksize: DEFAULT_BLOCKSIZE,
    })
}

fn file_attr_of_object_footer(object_footer: &ObjectFooter) -> FileAttr {
    let acquisition_start = match OffsetDateTime::from_unix_timestamp(object_footer.acquisition_start() as i64) {
        Ok(time) => time.into(),
        Err(_) => UNIX_EPOCH
    };
    let acquisition_end = match OffsetDateTime::from_unix_timestamp(object_footer.acquisition_end() as i64) {
        Ok(time) => time.into(),
        Err(_) => UNIX_EPOCH
    };
    FileAttr {
        ino: object_footer.object_number() + 1, //+1 to shift
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
        blksize: DEFAULT_BLOCKSIZE,
    }
}

fn inode_attributes_map_add_object<R: Read + Seek>(
    zffreader: &mut ZffReader<R>, 
    inode_attributes_map: &mut BTreeMap<u64, FileAttr>, 
    object_number: u64, 
    shift_value: u64) -> Result<u64> {
    zffreader.set_active_object(object_number)?;
    let mut counter = 0;

    let object_footer = zffreader.active_object_footer()?;
    inode_attributes_map.insert(object_number+1, file_attr_of_object_footer(&object_footer));
    match object_footer {
        ObjectFooter::Logical(log_footer) => {
            for filenumber in log_footer.file_footer_segment_numbers().keys() {
                zffreader.set_active_file(*filenumber)?;
                let metadata = zffreader.current_filemetadata()?.clone();
                let inode = metadata.first_chunk_number + shift_value;
                let file_attr = file_attr_of_file(metadata, zffreader, shift_value)?;
                inode_attributes_map.insert(inode, file_attr);
                counter += 1;
            }
        },
        ObjectFooter::Physical(ref phy_footer) => {
            let inode = phy_footer.first_chunk_number + shift_value;
            let mut file_attr = file_attr_of_object_footer(&object_footer);
            file_attr.ino = inode;
            file_attr.kind = FileType::RegularFile;
            file_attr.perm = 0o644;
            file_attr.size = phy_footer.length_of_data;
            file_attr.blocks = phy_footer.length_of_data / DEFAULT_BLOCKSIZE as u64 + 1;
            file_attr.nlink = 1;
            inode_attributes_map.insert(inode, file_attr); //0 is not a valid file number in zff, so we can use this as a placeholder
            counter += 1;
        },
        ObjectFooter::Virtual(_) => todo!(), //TODO
    };

    Ok(counter)
}