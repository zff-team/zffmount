// - Parent
use super::*;

// - Modules
mod filesystem;

// - external
use winfsp::filesystem::FileInfo;
use winfsp::host::FileSystemHost;

pub fn fuse_windows<R: Read + Seek + Send + Sync + 'static>(fs: ZffFs<R>, args: &Cli) {
    let mut host = match FileSystemHost::new(fs) {
        Ok(host) => host,
        Err(e) => {
            error!("An error occurred while trying to create the filesystem host.");
            debug!("{e}");
            exit(EXIT_STATUS_ERROR);
        }
    };

    if let Err(e) = host.mount(&args.mount_point) {
        error!("An error occurred while trying to mount the filesystem.");
        debug!("{e}");
        exit(EXIT_STATUS_ERROR);
    }

    if let Err(e) = host.start() {
        error!("An error occurred while trying to start the filesystem dispatcher.");
        debug!("{e}");
        exit(EXIT_STATUS_ERROR);
    }

    info!("Filesystem mounted successfully at {:?}. Press Ctrl+C to unmount.", &args.mount_point);

    // setup Ctrl+C handler for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = Arc::clone(&running);
    if let Err(e) = ctrlc::set_handler(move || {
        warn!("UNMOUNT: Received shutdown signal. The filesystem will be unmounted.");
        r.store(false, Ordering::SeqCst);
    }) {
        error!("An error occurred while trying to set the Ctrl+C handler: {e}");
        exit(EXIT_STATUS_ERROR);
    }

    while running.load(Ordering::SeqCst) {
        sleep(Duration::from_secs(1));
    }

    host.stop();
    host.unmount();
    info!("Filesystem successfully unmounted.");
    exit(EXIT_STATUS_SUCCESS);
}

fn file_info_of_file<R: Read + Seek>(
    mut filemetadata: FileMetadata,
    zffreader: &mut ZffReader<R>,
    shift_value: u64,
) -> Result<FileInfo> {
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

    // skip special file types on Windows
    let file_attributes = match zff_filetype {
        ZffFileType::File => FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NORMAL,
        ZffFileType::Directory => FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY,
        ZffFileType::Symlink | ZffFileType::SpecialFile => FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NORMAL,
        _ => FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NORMAL,
    };

    let atime = extract_timestamp(&filemetadata, zffreader, ATIME)?;
    let mtime = extract_timestamp(&filemetadata, zffreader, MTIME)?;
    let ctime = extract_timestamp(&filemetadata, zffreader, CTIME)?;
    let btime = extract_timestamp(&filemetadata, zffreader, BTIME)?;

    let mut info = FileInfo::default();
    info.file_attributes = file_attributes;
    info.file_size = filemetadata.length_of_data;
    info.allocation_size = (filemetadata.length_of_data / DEFAULT_BLOCKSIZE as u64 + 1) * DEFAULT_BLOCKSIZE as u64;
    info.creation_time = unix_timestamp_to_filetime(btime);
    info.last_access_time = unix_timestamp_to_filetime(atime);
    info.last_write_time = unix_timestamp_to_filetime(mtime);
    info.change_time = unix_timestamp_to_filetime(ctime);
    info.index_number = filemetadata.first_chunk_number + shift_value;

    Ok(info)
}

fn extract_timestamp<R: Read + Seek>(
    filemetadata: &FileMetadata,
    zffreader: &mut ZffReader<R>,
    key: &str,
) -> Result<i64> {
    let ts = match filemetadata.metadata_ext.get(key) {
        Some(val) => {
            if let Some(ts) = val.as_any().downcast_ref::<u64>() {
                *ts as i64
            } else {
                0
            }
        }
        None => match zffreader.current_fileheader()?.metadata_ext.get(key) {
            Some(val) => {
                if let Some(ts) = val.as_any().downcast_ref::<u64>() {
                    *ts as i64
                } else {
                    0
                }
            }
            None => 0,
        },
    };
    Ok(ts)
}

fn file_info_of_object_footer(object_footer: &ObjectFooter) -> ZffFileAttr {
    let acquisition_start = object_footer.acquisition_start() as i64;
    let acquisition_end = object_footer.acquisition_end() as i64;

    let mut info = FileInfo::default();
    info.file_attributes = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY;
    info.creation_time = unix_timestamp_to_filetime(acquisition_start);
    info.last_access_time = unix_timestamp_to_filetime(acquisition_end);
    info.last_write_time = unix_timestamp_to_filetime(acquisition_end);
    info.change_time = unix_timestamp_to_filetime(acquisition_end);
    info.index_number = object_footer.object_number() + 1;

    ZffFileAttr::from(info)
}

pub fn inode_attributes_map_add_object<R: Read + Seek>(
    zffreader: &mut ZffReader<R>,
    inode_attributes_map: &mut BTreeMap<u64, ZffFileAttr>,
    object_number: u64,
    shift_value: u64,
) -> Result<u64> {
    zffreader.set_active_object(object_number)?;
    let mut counter = 0;

    let object_footer = zffreader.active_object_footer()?;
    inode_attributes_map.insert(object_number + 1, file_info_of_object_footer(&object_footer));
    match object_footer {
        ObjectFooter::Logical(log_footer) => {
            for filenumber in log_footer.file_footer_segment_numbers().keys() {
                zffreader.set_active_file(*filenumber)?;
                let metadata = zffreader.current_filemetadata()?.clone();
                let inode = metadata.first_chunk_number + shift_value;
                let file_info = file_info_of_file(metadata, zffreader, shift_value)?;
                let file_attr = ZffFileAttr::from(file_info);
                inode_attributes_map.insert(inode, file_attr);
                counter += 1;
            }
        }
        ObjectFooter::Physical(ref phy_footer) => {
            let inode = phy_footer.first_chunk_number + shift_value;
            let mut file_attr = file_info_of_object_footer(&object_footer);
            let info = file_attr.info_mut();
            info.file_attributes = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NORMAL;
            info.file_size = phy_footer.length_of_data;
            info.allocation_size =
                (phy_footer.length_of_data / DEFAULT_BLOCKSIZE as u64 + 1) * DEFAULT_BLOCKSIZE as u64;
            info.index_number = inode;
            inode_attributes_map.insert(inode, file_attr);
            counter += 1;
        }
        ObjectFooter::Virtual(_) => todo!(), //TODO
    };

    Ok(counter)
}

/// Resolves a Windows-style path (e.g. `\object_1\somefile.txt`) to an inode
/// by walking the path components through the cache lookup tables.
pub fn resolve_path_to_inode(cache: &ZffFsCache, shift_value: u64, path: &str) -> Option<u64> {
    let path = path.replace('\\', "/");
    let path = path.trim_start_matches('/');

    if path.is_empty() {
        return Some(SPECIAL_INODE_ROOT_DIR);
    }

    let components: Vec<&str> = path.split('/').collect();
    let mut current_inode = SPECIAL_INODE_ROOT_DIR;

    for (i, component) in components.iter().enumerate() {
        if i == 0 {
            // First component should be an object directory like "object_1"
            let obj_number = component.strip_prefix(OBJECT_PREFIX)?.parse::<u64>().ok()?;
            // verify this object exists
            if !cache.object_list.contains_key(&obj_number) {
                return None;
            }
            current_inode = obj_number + 1; // object directory inode
        } else if i == 1 {
            // Second component: could be a physical object file or a logical object entry
            let obj_number = current_inode - 1;
            match cache.object_list.get(&obj_number)? {
                ZffReaderObjectType::Physical => {
                    if *component == ZFF_PHYSICAL_OBJECT_NAME {
                        // find the physical object's data inode from the attributes map
                        for (&ino, attr) in &cache.inode_attributes_map {
                            if ino > shift_value && cache.inode_reverse_map.get(&ino).is_some_and(|(_, f)| *f == 0) {
                                if let Some((obj, _)) = cache.inode_reverse_map.get(&ino) {
                                    if *obj == obj_number {
                                        current_inode = ino;
                                        break;
                                    }
                                }
                            }
                        }
                    } else {
                        return None;
                    }
                }
                ZffReaderObjectType::Logical => {
                    // lookup by filename with parent = current_inode
                    let entries = cache.filename_lookup_table.get(*component)?;
                    let mut found = false;
                    for (parent_inode, inode) in entries {
                        if *parent_inode == current_inode {
                            current_inode = *inode;
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        return None;
                    }
                }
                _ => return None,
            }
        } else {
            // Deeper path components: lookup by filename with parent = current_inode
            let entries = cache.filename_lookup_table.get(*component)?;
            let mut found = false;
            for (parent_inode, inode) in entries {
                if *parent_inode == current_inode {
                    current_inode = *inode;
                    found = true;
                    break;
                }
            }
            if !found {
                return None;
            }
        }
    }

    Some(current_inode)
}

/// Converts a Unix timestamp (seconds since 1970-01-01) to Windows FILETIME
/// (100-nanosecond intervals since 1601-01-01).
pub(crate) fn unix_timestamp_to_filetime(unix_ts: i64) -> u64 {
    ((unix_ts + UNIX_TO_WINDOWS_EPOCH_OFFSET) * FILETIME_INTERVALS_PER_SECOND) as u64
}
