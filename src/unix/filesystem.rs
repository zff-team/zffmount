use zff::PlatformString;

// - Parent
use super::*;

impl<R: Read + Seek + Send + Sync + 'static> Filesystem for ZffFs<R> {
    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: fuser::ReplyEmpty,
    )
    {
        // Flush operations will be ignored: We're operating on a 
        // RO filesystem. Writes will never be called.
        reply.ok();
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let ino = ino.0;
        debug!("READ from inode: {ino} at offeset {offset} for {size} bytes");
        if ino < self.shift_value {
            unreachable!()
        } else {
            let (object_no, file_no) = match self.cache.inode_reverse_map.get(&ino) {
                Some(data) => data,
                None => {
                    error!("Error while trying to read data from inode {ino}: Inode not found in inode reverse map.");
                    reply.error(Errno::ENOENT);
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
                    reply.error(Errno::ENOENT);
                    return;
                }
            } else {
                // if the object is a logical object, we have to do some more stuff.
                // sets the appropriate object and file active and returns the appropriate file-
                // metadata (which is not needed at this point).
                let _ = match prepare_zffreader_file(&mut zffreader, *object_no, *file_no) {
                    Err(e) => {
                        error!("Error while trying to set file {file_no} of object {object_no} active.");
                        debug!("{e}");
                        reply.error(Errno::ENOENT);
                        return;
                    },
                    Ok(metadata) => metadata
                };
            }

            match zffreader.seek(SeekFrom::Start(offset)) {
                Ok(_) => (),
                Err(e) => {
                    error!("read error 0x1 for inode {ino}.");
                    debug!("{e}");
                    reply.error(Errno::ENOENT);
                    return;
                }
            }
            let mut buffer = vec![0u8; size as usize];
            debug!("Fill buffer by reading data at offset {offset} with buffer size of {size}.");
            let bytes_read = match zffreader.read(&mut buffer) {
                Ok(bytes_read) => bytes_read,
                Err(e) => {
                    error!("read error 0x2 for inode {ino}.");
                    debug!("{e}");
                    reply.error(Errno::ENOENT);
                    return
                }
            };
            reply.data(&buffer[..bytes_read]);
        }
    }

    fn readdir(
    &self,
    _req: &Request,
    ino: INodeNo,
    _fh: FileHandle,
    offset: u64,
    mut reply: ReplyDirectory,
    ) {
        let mut entries = Vec::new();
        debug!("READDIR: Start readdir of inode {ino}");
        let ino = ino.0;

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
                reply.error(Errno::ENOENT);
                return;
            }
            //check object type and use the appropriate fn
            match self.cache.object_list.get(&(ino-1)) {
                None => {
                    warn!("READDIR: Trying to readdir in hidden passive object.");
                    reply.error(Errno::ENOENT);
                    return;
                },
                Some(ZffReaderObjectType::Encrypted) => {
                    error!("Could not find undecrypted object reader for object {}", ino-1);
                    reply.error(Errno::ENOENT);
                    return;
                },
                Some(ZffReaderObjectType::Physical) => match readdir_physical_object_root(&mut zffreader, self.shift_value) {
                    Ok(mut content) => entries.append(&mut content),
                    Err(e) => {
                        error!("Error while trying to read content of object directory of object {}: {e}", ino-1);
                        reply.error(Errno::ENOENT);
                        return;
                    }
                },
                Some(ZffReaderObjectType::Logical) => match readdir_logical_object_root(&self.cache, &mut zffreader) {
                    Ok(mut content) => entries.append(&mut content),
                    Err(e) => {
                        error!("Error while trying to read content of object directory of object {}: {e}", ino-1);
                        reply.error(Errno::ENOENT);
                        return;
                    },
                },
                Some(ZffReaderObjectType::Virtual) => match readdir_virtual_object_root(&self.cache, &mut zffreader) {
                    Ok(mut content) => entries.append(&mut content),
                    Err(e) => {
                        error!("Error while trying to read content of object directory of object {}: {e}", ino-1);
                        reply.error(Errno::ENOENT);
                        return;
                    },
                }
            }
        //the following should only affect logical and virtual objects.
        } else {
            // setup self ino file
            let (object_no, file_no) = match self.cache.inode_reverse_map.get(&ino) {
                Some(x) => x,
                None =>  {
                    error!("Could not find inode {ino} in inode reverse map.");
                    reply.error(Errno::ENOENT);
                    return;
                }
            };
            let filemetadata = match prepare_zffreader_file(&mut zffreader, *object_no, *file_no) {
                Ok(fm) => fm,
                Err(e) =>  {
                    error!("An error occurred while trying to prepare zffreader: {e}");
                    reply.error(Errno::ENOENT);
                    return;
                },
            };
            let parent_inode = match self.cache.inode_map.get(&(*object_no, *file_no)) {
                Some(ino) => ino,
                None => {
                    error!("Unable to setup parent inode for file {file_no} of object {object_no}");
                    reply.error(Errno::ENOENT);
                    return;
                }
            };

            //set parent directory entry
            entries.push((*parent_inode, FileType::Directory, String::from(PARENT_DIR)));
            let children = {
                match filemetadata.footer {
                    FileFooterMetadata::FileFooter(_) => {
                        let mut buffer = Vec::new();
                        //seeks the reader to start position to read all content of the directory (again)
                        if let Err(e) = zffreader.rewind() {
                            error!("Error while trying to seek the children-list of file {file_no} / object {object_no}.");
                            debug!("{e}");
                            reply.error(Errno::ENOENT);
                            return;
                        }
                        if let Err(e) = zffreader.read_to_end(&mut buffer) {
                            error!("Error while trying to read children list of file {file_no} / object {object_no}.");
                            debug!("{e}");
                            reply.error(Errno::ENOENT);
                            return;
                        };
                        match Vec::<u64>::decode_directly(&mut buffer.as_slice()) {
                            Ok(vec) => vec,
                            Err(e) => {
                                error!("An error occurred while decoding list of files of file {file_no} / object {object_no}.");
                                debug!("{e}");
                                reply.error(Errno::ENOENT);
                                return;
                            }
                        }
                    },
                    FileFooterMetadata::VirtualFileFooterMetadata(ref vffc) => {
                        match vffc.vfc {
                            VirtualFileContent::Directory(ref children) => children.clone(),
                            _ => {
                                error!("Virtual file is not a directory!");
                                reply.error(Errno::ENOENT);
                                return;
                            }
                        }
                    }
                }
                
            };

            //set children entries.
            let mut children_entries = match readdir_entries_file(&self.cache, &mut zffreader, &children) {
                Ok(entries) => entries,
                Err(e) => {
                    error!("An error occurred while reading directory of file {file_no} / object {object_no}.");
                    debug!("{e}");
                    reply.error(Errno::ENOENT);
                    return;
                }
            };
            entries.append(&mut children_entries);
        };

        for (index, entry) in entries.into_iter().skip(offset as usize).enumerate() {
            let (inode, file_type, name) = entry;
            debug!("READDIR entry added: inode: {inode}, index: {}, file_type: {:?}, name: {name}", offset + index as u64 + 1, file_type);
            if reply.add(INodeNo(inode), offset + index as u64 + 1, file_type, name) {
                break;
            }
        }
        reply.ok();
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        debug!("Starting LOOKUP request: parent inode: \"{parent}\"; name: {:?}.", name);
        let parent = parent.0;
        let platformstring_name: PlatformString = name.into();
        let name = match name.to_str() {
            Some(name) => name,
            None => {
                error!("LOOKUP: Error while trying to convert name: {:?}", name);
                reply.error(Errno::ENOENT);
                return;
            }
        };
        //handle root directory with the "object_" directories.
        if parent == SPECIAL_INODE_ROOT_DIR {
            let mut split = name.rsplit(OBJECT_PATH_PREFIX);
            let object_number = match split.next() {
                None => {
                    error!("LOOKUP: object prefix not in filename. This is an application bug. The filename is {name}");
                    reply.error(Errno::ENOENT);
                    return;
                },
                Some(unparsed_object_number) => match unparsed_object_number.parse::<u64>() {
                    Ok(object_number) => object_number,
                    Err(e) => {
                        //This is a workaround: Some Desktop environments trying to lookup for folders like ".Trash" or ".Trash-1000", but these do not exist.
                        if  unparsed_object_number == DEFAULT_TRASHFOLDER_NAME || unparsed_object_number == format!("{DEFAULT_TRASHFOLDER_NAME}-{}", Uid::effective()) {
                            debug!("Cannot access trashfolders.");
                            reply.error(Errno::ENOENT);
                            return;
                        }
                        //this is only a debuggable error, as the bash/zsh completition could generate a huge number of those messages.
                        debug!("LOOKUP: Error while trying to parse the object: \"{unparsed_object_number}\" for original name: {name}; {e}");
                        reply.error(Errno::ENOENT);
                        return;
                    },
                },
            };

            // get the appropriate attributes of the object directory - by using object number +1 shift value.
            let file_attr = match self.cache.inode_attributes_map.get(&(object_number+1)) {
                Some(zff_fileattr) => zff_fileattr.fileattr,
                None => {
                    debug!("GETATTR: unknown inode number: {}", object_number+1);
                    reply.error(Errno::ENOENT);
                    return;
                },
            };
            debug!("LOOKUP: returned entry attr(1): {:?}", &file_attr);
            reply.entry(&TTL, &file_attr, Generation(DEFAULT_ENTRY_GENERATION));

        } else if parent <= self.shift_value { //checks if the parent is a object folder
            let mut zffreader = self.zffreader.lock().unwrap();
            // set active object reader to appropriate parent
            if let Err(e) = zffreader.set_active_object(parent-1) {
                error!("LOOKUP: An error occured while trying to lookup for inode {parent}.");
                debug!("{e}");
                reply.error(Errno::ENOENT);
                return;
            }
            //check object type and use the appropriate fn
            match self.cache.object_list.get(&(parent-1)) {
                None => {
                    warn!("LOOKUP: Trying to lookup for hidden passive object.");
                    reply.error(Errno::ENOENT);
                }
                Some(ZffReaderObjectType::Encrypted) => {
                    error!("LOOKUP: Could not find undecrypted object reader for object {}", parent-1);
                    reply.error(Errno::ENOENT);
                },
                Some(ZffReaderObjectType::Physical) => if name == ZFF_PHYSICAL_OBJECT_NAME {
                    let object_footer = match zffreader.active_object_footer() {
                        Ok(footer) => match footer { ObjectFooter::Physical(phy) => phy, _ => unreachable!() },
                        Err(e) => {
                            error!("LOOKUP: cannot find the object footer of object {}", parent-1);
                            debug!("{e}");
                            reply.error(Errno::ENOENT);
                            return;
                        }
                    };
                    let ino = object_footer.first_chunk_number + self.shift_value;
                    // get the appropriate attributes of the object data file.
                    let file_attr = match self.cache.inode_attributes_map.get(&ino) {
                        Some(zff_fileattr) => zff_fileattr.fileattr,
                        None => {
                            debug!("GETATTR: unknown inode number: {}", ino);
                            reply.error(Errno::ENOENT);
                            return;
                        },
                    };
                    debug!("LOOKUP: returned entry attr(2): {:?}", &file_attr);
                    reply.entry(&TTL, &file_attr, Generation(DEFAULT_ENTRY_GENERATION));
                } else {
                    debug!("Error while trying to lookup for {name} in object {}", parent-1);
                    reply.error(Errno::ENOENT);
                },
                Some(ZffReaderObjectType::Logical) | Some(ZffReaderObjectType::Virtual) => if let Some(lookup_table_entries) = self.cache.filename_lookup_table.get(&platformstring_name) {
                    for (parent_inode, inode) in lookup_table_entries {
                        if parent == *parent_inode {
                            match self.cache.inode_attributes_map.get(inode) {
                                Some(zff_fileattr) => {
                                    debug!("LOOKUP: returned entry attr(3): {:?}", zff_fileattr);
                                    reply.entry(&TTL, &zff_fileattr.fileattr, Generation(DEFAULT_ENTRY_GENERATION));
                                    return;
                                },
                                None => {
                                    error!("An error occurred while trying to get file attributes of inode {inode}.");
                                    reply.error(Errno::ENOENT);
                                    return;
                                }
                            }
                        }
                    }
                } else {
                    debug!("Error while trying to lookup for {name} in object {}", parent-1);
                    reply.error(Errno::ENOENT);
                }
            }
        } else if let Some(lookup_table_entries) = self.cache.filename_lookup_table.get(&platformstring_name) {
            for (parent_inode, inode) in lookup_table_entries {
                if parent == *parent_inode {
                    match self.cache.inode_attributes_map.get(inode) {
                        Some(zff_fileattr) => {
                            debug!("LOOKUP: returned entry-attr(4): {:?}.", zff_fileattr);
                            reply.entry(&TTL, &zff_fileattr.fileattr, Generation(DEFAULT_ENTRY_GENERATION));
                            return;
                        },
                        None => {
                            error!("An error occurred while trying to get file attributes of inode {inode}.");
                            reply.error(Errno::ENOENT);
                            return;
                        }
                    }
                }
            }
        } else {
            debug!("Error while trying to lookup for {name} in object {}", parent-1);
            reply.error(Errno::ENOENT);
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let ino = ino.0;
        if ino < self.shift_value {
            error!("Inode {ino} is not a link.");
           reply.error(Errno::ENOENT);
        } else {
            let (object_no, file_no) = match self.cache.inode_reverse_map.get(&ino) {
                Some(data) => data,
                None => {
                    error!("Error while trying to read data from inode {ino}: Inode not found in inode reverse map.");
                    reply.error(Errno::ENOENT);
                    return;
                }
            };

            let mut zffreader = self.zffreader.lock().unwrap();

            //check if this is a physical object.
            // we've stored inodes to physical objects in inode map by using the file number 0 as placeholder earlier.
            if *file_no == 0 {
               error!("Inode {ino} is not a link.");
               reply.error(Errno::ENOENT);
            } else {
                // if the object is a logical object, we have to do some more stuff.
                // sets the appropriate object and file active and returns the appropriate filemetadata
                let filemetadata = match prepare_zffreader_file(&mut zffreader, *object_no, *file_no) {
                    Err(e) => {
                        error!("Error while trying to set file {file_no} of object {object_no} active.");
                        debug!("{e}");
                        reply.error(Errno::ENOENT);
                        return;
                    },
                    Ok(metadata) => metadata
                };

                if filemetadata.header.file_type != ZffFileType::Symlink {
                    error!("File {file_no} is not a link.");
                    debug!("{:?}", filemetadata);
                    reply.error(Errno::ENOENT);
                    return;
                }

                match zffreader.seek(SeekFrom::Start(0)) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("read error 0x3 for inode {ino}.");
                        debug!("{e}");
                        reply.error(Errno::ENOENT);
                        return;
                    }
                }
                let mut buffer = Vec::new();
                match zffreader.read_to_end(&mut buffer) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("read error 0x4 for inode {ino}.");
                        debug!("{e}");
                        reply.error(Errno::ENOENT);
                        return
                    }
                }
                // we will only use the human readable lossy utf8 conversion of the platform string.
                let ps = match PlatformString::decode_directly(&mut buffer.as_slice()) {
                    Ok(ps) => ps.to_string_lossy(),
                    Err(e) => {
                        error!("read error 0x5 for inode {ino}.");
                        debug!("{e}");
                        reply.error(Errno::ENOENT);
                        return
                    }
                };
                reply.data(ps.as_bytes());
            }
        }
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        debug!("getattr for inode {ino}.");
        let ino = ino.0;
        match self.cache.inode_attributes_map.get(&ino) {
            Some(zff_fileattr) => reply.attr(&TTL, &zff_fileattr.fileattr),
            None => if ino == SPECIAL_INODE_ROOT_DIR {
                reply.attr(&TTL, &DEFAULT_ROOT_DIR_ATTR)
            } else {
                debug!("GETATTR: unknown inode number: {ino}");
                reply.error(Errno::ENOENT);
            },
        }
    }

    fn listxattr(&self, _req: &Request, ino: INodeNo, size: u32, reply: fuser::ReplyXattr) {
        debug!("listxattr for inode {ino}.");
        let ino = ino.0;
        let mut bytes = vec![];
        match self.cache.inode_attributes_map.get(&ino) {
            Some(zff_fileattr) => {
                for key in zff_fileattr.xattrs.keys() {
                    bytes.extend(key.as_bytes());
                    bytes.push(0);
                }
                if size == 0 {
                    debug!("reply.size({} as u32);", bytes.len());
                    reply.size(bytes.len() as u32);
                } else if bytes.len() <= size as usize {
                    reply.data(&bytes);
                } else {
                    debug!("Errno::ERANGE");
                    reply.error(Errno::ERANGE);
                }
            },
            None => if ino == SPECIAL_INODE_ROOT_DIR {
                reply.data(&bytes)
            } else {
                debug!("LISTXATTR: unknown inode number: {ino}");
                reply.error(Errno::ENOENT);
            },
        }
    }

    fn getxattr(&self, _req: &Request, ino: INodeNo, name: &OsStr, size: u32, reply: fuser::ReplyXattr) {
        let ino = ino.0;
        match self.cache.inode_attributes_map.get(&ino) {
            Some(zff_fileattr) => {
                let name = name.to_string_lossy().to_string();
                match zff_fileattr.xattrs.get(&name) {
                    Some(value) => {
                        match value.to_vec() {
                            Some(value) => {
                                if size == 0 {
                                    debug!("reply.size({} as u32);", value.len());
                                    reply.size(value.len() as u32);
                                } else if value.len() <= size as usize {
                                    reply.data(&value);
                                } else {
                                    debug!("Errno::ERANGE");
                                    reply.error(Errno::ERANGE);
                                }
                            },
                            None => {
                                debug!("Errno::ENODATA");
                                reply.error(Errno::ENODATA)
                            },
                        };
                    }
                    None => {
                        debug!("Errno::ENODATA");
                        reply.error(Errno::ENODATA)
                    },
                }
            },
            None => if ino == SPECIAL_INODE_ROOT_DIR {
                reply.data(&[])
            } else {
                debug!("GETXATTR: unknown inode number: {ino}");
                reply.error(Errno::ENOENT);
            },
        }
    }
    
}
