// - Parent
use super::*;

impl<R: Read + Seek> Filesystem for ZffFs<R> {
    #[cfg(target_os = "linux")]
    fn init(
        &mut self,
        _req: &Request,
        config: &mut KernelConfig,
    ) -> std::result::Result<(), c_int> {
        config.add_capabilities(FUSE_PASSTHROUGH).unwrap();
        config.set_max_stack_depth(2).unwrap();
        Ok(())
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

            let mut zffreader = self.zffreader.lock().unwrap();

            //check if this is a physical object.
            // we've stored inodes to physical objects in inode map by using the file number 0 as placeholder earlier.
            if *file_no == 0 {
                if let Err(e) = zffreader.set_active_object(*object_no) {
                    error!("An error occurred while trying to set object {object_no} as active.");
                    debug!("{e}");
                    reply.error(ENOENT);
                    return;
                }
            } else {
                // if the object is a logical object, we have to do some more stuff.
                // sets the appropriate object and file active and returns the appropriate file-
                // metadata (which is not needed at this point).
                let _ = match prepare_zffreader_logical_file(&mut zffreader, *object_no, *file_no) {
                    Err(e) => {
                        error!("Error while trying to set file {file_no} of object {object_no} active.");
                        debug!("{e}");
                        reply.error(ENOENT);
                        return;
                    },
                    Ok(metadata) => metadata
                };
            }

            match zffreader.seek(SeekFrom::Start(offset as u64)) {
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
            match zffreader.read(&mut buffer) {
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

        let mut zffreader = self.zffreader.lock().unwrap();

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
            if let Err(e) = zffreader.set_active_object(ino-1) {
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
                Some(ZffReaderObjectType::Physical) => match readdir_physical_object_root(&mut zffreader, self.shift_value) {
                    Ok(mut content) => entries.append(&mut content),
                    Err(e) => {
                        error!("Error while trying to read content of object directory of object {}: {e}", ino-1);
                        reply.error(ENOENT);
                        return;
                    }
                },
                Some(ZffReaderObjectType::Logical) => match readdir_logical_object_root(&mut zffreader, self.shift_value) {
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
            let filemetadata_ref = match prepare_zffreader_logical_file(&mut zffreader, *object_no, *file_no) {
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
                if let Err(e) = zffreader.rewind() {
                    error!("Error while trying to seek the children-list of file {file_no} / object {object_no}.");
                    debug!("{e}");
                    reply.error(ENOENT);
                    return;
                }
                if let Err(e) = zffreader.read_to_end(&mut buffer) {
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
            let mut children_entries = match readdir_entries_file(&mut zffreader, self.shift_value, &children) {
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
                Some(file_attr) => file_attr.attr(),
                None => {
                    debug!("GETATTR: unknown inode number: {}", object_number+1);
                    reply.error(ENOENT);
                    return;
                },
            };
            debug!("LOOKUP: returned entry attr(1): {:?}", &file_attr);
            reply.entry(&TTL, file_attr, DEFAULT_ENTRY_GENERATION);

        } else if parent <= self.shift_value { //checks if the parent is a object folder
            let mut zffreader = self.zffreader.lock().unwrap();
            // set active object reader to appropriate parent
            if let Err(e) = zffreader.set_active_object(parent-1) {
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
                    let object_footer = match zffreader.active_object_footer() {
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
                    reply.entry(&TTL, file_attr.attr(), DEFAULT_ENTRY_GENERATION);
                } else {
                    debug!("Error while trying to lookup for {name} in object {}", parent-1);
                    reply.error(ENOENT);
                    return;
                },
                Some(ZffReaderObjectType::Logical) => if let Some(lookup_table_entries) = self.cache.filename_lookup_table.get(name) {
                    for (parent_inode, inode) in lookup_table_entries {
                        if parent == *parent_inode {
                            match self.cache.inode_attributes_map.get(inode) {
                                Some(file_attr) => {
                                    debug!("LOOKUP: returned entry attr(3): {:?}", file_attr.attr());
                                    reply.entry(&TTL, file_attr.attr(), DEFAULT_ENTRY_GENERATION);
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
                        Some(file_attr) => {
                            debug!("LOOKUP: returned entry-attr(4): {:?}.", file_attr.attr());
                            reply.entry(&TTL, file_attr.attr(), DEFAULT_ENTRY_GENERATION);
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

            let mut zffreader = self.zffreader.lock().unwrap();

            //check if this is a physical object.
            // we've stored inodes to physical objects in inode map by using the file number 0 as placeholder earlier.
            if *file_no == 0 {
               error!("Inode {ino} is not a link.");
               reply.error(ENOENT);
            } else {
                // if the object is a logical object, we have to do some more stuff.
                // sets the appropriate object and file active and returns the appropriate filemetadata
                let filemetadata = match prepare_zffreader_logical_file(&mut zffreader, *object_no, *file_no) {
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

                match zffreader.seek(SeekFrom::Start(0)) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("read error 0x3 for inode {ino}.");
                        debug!("{e}");
                        reply.error(ENOENT);
                        return;
                    }
                }
                let mut buffer = Vec::new();
                match zffreader.read_to_end(&mut buffer) {
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
            Some(file_attr) => reply.attr(&TTL, file_attr.attr()),
            None => if ino == SPECIAL_INODE_ROOT_DIR {
                reply.attr(&TTL, &DEFAULT_ROOT_DIR_ATTR)
            } else {
                debug!("GETATTR: unknown inode number: {ino}");
                reply.error(ENOENT);
            },
        }
    }
}
