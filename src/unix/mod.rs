// - Parent
use super::*;

// - STD
use std::ffi::OsStr;

// - Modules
mod filesystem;

// - internal
use zff::{VirtualFileContent, footer::ObjectFooterPhysical, header::MetadataExtendedValue};

// - external
pub use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request, MountOption, Errno, INodeNo, FileHandle, OpenFlags, LockOwner, Generation,
    Config,
};
pub use nix::unistd::{Uid, Gid};
pub use signal_hook::{consts::{SIGINT, SIGHUP, SIGTERM}, iterator::Signals};

pub fn fuse_unix<R: Read + Seek + Send + Sync + 'static>(fs: ZffFs<R>, args: &Cli) {
    let mut mountoptions = vec![
        MountOption::RO,
        MountOption::FSName(String::from(ZFF_OVERLAY_FS_NAME)),
    ];
    if !args.ownership_overwrite {
        mountoptions.push(MountOption::DefaultPermissions)
    }

    let mut config = Config::default();
    config.mount_options = mountoptions;

    let session = match fuser::spawn_mount2(fs, &args.mount_point, &config) {
        Ok(session) => session,
        Err(e) => {
            error!("An error occurred while trying to mount the filesystem.");
            debug!("{e}");
            exit(EXIT_STATUS_ERROR);
        }
    };

    // setup signal handler to unmount by using CTRL+C (or sending SIGHUB/SIGTERM/SIGINT to process).
    let mut signals = match Signals::new([SIGINT, SIGHUP, SIGTERM]) {
        Ok(signals) => signals,
        Err(e) => {
            error!("an error occurred while trying to set the signal handler for graceful umounting: {e}");
            exit(EXIT_STATUS_ERROR);
        },
    };
    let running = Arc::new(AtomicBool::new(false));
    let r = Arc::clone(&running);
    thread::spawn(move || {
        for sig in signals.forever() {
            if sig == SIGINT || sig == SIGHUP || sig == SIGTERM {
                warn!("UNMOUNT: Received shutdown signal {:?}. The filesystems will be unmounted, as soon as the resource is no longer busy.", sig);
                r.store(true, Ordering::SeqCst);
            }
        }
    });

    loop {
        sleep(Duration::from_secs(1)); // to reduce the CPU usage
        if running.load(Ordering::SeqCst) {
            if let Err(e) = session.umount_and_join() {
                error!("An error occurred while trying to umount the fuse filesystem: {e}");
                exit(EXIT_STATUS_ERROR);
            } else {
                info!("Filesystem successfully unmounted. Session closed.");
                exit(EXIT_STATUS_SUCCESS);
            };
        }
    }
}


fn get_filetype<R: Read + Seek>(filemetadata: &FileMetadata, zffreader: &mut ZffReader<R>) -> Result<FileType> {
    let filemetadata = absolute_filemetadata(filemetadata, zffreader)?;
    convert_filetype(filemetadata, zffreader)
}

// hardlinks should be handled before calling this method.
pub fn convert_filetype<R: Read + Seek>(filemetadata: FileMetadata, zffreader: &mut ZffReader<R>) -> Result<FileType> {
    let filetype = match filemetadata.footer {
        FileFooterMetadata::FileFooter(_) => {
            let in_type = filemetadata.filetype().clone();
            match in_type {
                ZffFileType::File => FileType::RegularFile,
                ZffFileType::Directory => FileType::Directory,
                ZffFileType::Symlink => FileType::Symlink,
                ZffFileType::Hardlink => unreachable!(), //even if unreachable: TODO: handle error
                ZffFileType::SpecialFile => {
                    let mut buffer = Vec::new();
                    zffreader.rewind()?;
                    zffreader.read_to_end(&mut buffer)?;
                    let filetype_flag = match buffer.last() {
                        Some(byte) => ZffSpecialFileType::try_from(byte)?,
                        None => return Err(ZffError::new(ZffErrorKind::Unsupported, format!("{:?}", buffer))),
                    };
                    match filetype_flag {
                        ZffSpecialFileType::Fifo => FileType::NamedPipe,
                        ZffSpecialFileType::Char => FileType::CharDevice,
                        ZffSpecialFileType::Block => FileType::BlockDevice,
                        ZffSpecialFileType::Socket => FileType::Socket,
                        _ => unimplemented!() //TODO: handle error
                    }
                },
                _ => unimplemented!() //TODO: handle error
            }
        },
        FileFooterMetadata::VirtualFileFooterMetadata(vffc) => {
            match vffc.vfc {
                VirtualFileContent::Directory(_) => FileType::Directory,
                VirtualFileContent::FileMap(_) | VirtualFileContent::FileMapPosition(_, _) => FileType::RegularFile,
                VirtualFileContent::Hardlink(_) => unreachable!(),
                VirtualFileContent::Symlink(_) => FileType::Symlink,
                VirtualFileContent::SpecialFile(_, stype) => {
                    match stype {
                        ZffSpecialFileType::Fifo => FileType::NamedPipe,
                        ZffSpecialFileType::Char => FileType::CharDevice,
                        ZffSpecialFileType::Block => FileType::BlockDevice,
                        ZffSpecialFileType::Socket => FileType::Socket,
                        _ => unimplemented!() //TODO: handle error
                    }
                }
            }
        },
    };
    Ok(filetype)
}

pub fn readdir_physical_object_root<R: Read + Seek>(zffreader: &mut ZffReader<R>, shift_value: u64) -> Result<Vec<(u64, FileType, String)>> {
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

pub fn readdir_logical_object_root<R: Read + Seek>(cache: &ZffFsCache, zffreader: &mut ZffReader<R>) -> Result<Vec<(u64, FileType, String)>> {
    if let ObjectFooter::Logical(footer) = zffreader.active_object_footer()? {
        readdir_entries_file(cache, zffreader, &footer.root_dir_filenumbers)
    } else {
        Err(ZffError::new(ZffErrorKind::Invalid, ERR_INVALID_OBJECT_TYPE))
    }
}

pub fn readdir_virtual_object_root<R: Read + Seek>(cache: &ZffFsCache, zffreader: &mut ZffReader<R>) -> Result<Vec<(u64, FileType, String)>> {
    if let ObjectFooter::Virtual(footer) = zffreader.active_object_footer()? {
        readdir_entries_file(cache, zffreader, &footer.root_dir_filenumbers)
    } else {
        Err(ZffError::new(ZffErrorKind::Invalid, ERR_INVALID_OBJECT_TYPE))
    }
}

pub fn readdir_entries_file<R: Read + Seek>(cache: &ZffFsCache, zffreader: &mut ZffReader<R>, children: &Vec<u64>) -> Result<Vec<(u64, FileType, String)>> {
    let mut entries = Vec::new();
    let object_number = zffreader.active_object_footer()?.object_number();
    for filenumber in children {
        let inode = cache.inode_map
        .get(&(object_number, *filenumber))
        .ok_or(ZffError::new(ZffErrorKind::Missing, "Missing filenumber in zff cache: {filenumber}"))?;
        let filetype = cache.inode_attributes_map
        .get(inode)
        .ok_or(ZffError::new(ZffErrorKind::Missing, "Missing filenumber in zff cache: {filenumber}"))?
        .fileattr.kind;
        zffreader.set_active_file(*filenumber)?;
        let filemetadata = zffreader.current_filemetadata()?.clone();
        let filename = filemetadata.header.filename.clone();
        entries.push((*inode, filetype, filename.to_string()));
    }

    Ok(entries)
}


pub(crate) fn file_attr_of_file<R: Read + Seek>(mut filemetadata: FileMetadata, zffreader: &mut ZffReader<R>, ino: u64) -> Result<ZffFileAttr> {
    let filetype = get_filetype(&filemetadata, zffreader)?;
    // removes the most stuff so we can then iterate over metadata_ext to obtain
    // all xattrs.
    let atime = match filemetadata.header.metadata_ext.remove(ATIME) {
        Some(atime) => if let Some(atime) = atime.as_any().downcast_ref::<u64>() {
            *atime as i64
        } else {
            0
        },
        // if the atime metadata where not read in the first step (e.g. by using the minimal FileMetada option)
        // We have to read them from file-header directly (more I/O expensive).
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

    let mtime = match filemetadata.header.metadata_ext.remove(MTIME) {
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

    let ctime = match filemetadata.header.metadata_ext.remove(CTIME) {
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

    let btime = match filemetadata.header.metadata_ext.remove(BTIME) {
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

    let uid = if let Some(MetadataExtendedValue::U32(uid)) = filemetadata.header.metadata_ext.get(UID) {
        *uid
    } else {
        Uid::effective().into()
    };
    let gid = if let Some(MetadataExtendedValue::U32(gid)) = filemetadata.header.metadata_ext.get(GID) {
        *gid
    } else {
        Gid::effective().into()
    };
    let perm = if let Some(MetadataExtendedValue::U32(mode)) = filemetadata.header.metadata_ext.get(PERM_MODE) {
        *mode as u16
    } else {
        0o755
    };

    let fileattr = FileAttr {
        ino: INodeNo(ino),
        size: filemetadata.length_of_data(),
        blocks: filemetadata.length_of_data() / DEFAULT_BLOCKSIZE as u64 + 1,
        atime,
        mtime,
        ctime,
        crtime: btime,
        kind: filetype,
        perm,
        nlink: 1,
        uid,
        gid,
        rdev: 0,
        flags: 0,
        blksize: DEFAULT_BLOCKSIZE,
    };

    let mut zff_file_attr = ZffFileAttr::from(fileattr);
    zff_file_attr.xattrs = filemetadata.header.metadata_ext;

    Ok(zff_file_attr)
}

pub(crate) fn file_attr_of_object_footer(object_footer: &ObjectFooter) -> ZffFileAttr {
    let acquisition_start = match OffsetDateTime::from_unix_timestamp(object_footer.acquisition_start() as i64) {
        Ok(time) => time.into(),
        Err(_) => UNIX_EPOCH
    };
    let acquisition_end = match OffsetDateTime::from_unix_timestamp(object_footer.acquisition_end() as i64) {
        Ok(time) => time.into(),
        Err(_) => UNIX_EPOCH
    };
    let file_attr = FileAttr {
        ino: INodeNo(object_footer.object_number() + 1), //+1 to shift
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
    };
    ZffFileAttr::from(file_attr)
}

pub(crate) fn file_attr_of_physical_obj(object_footer: &ObjectFooterPhysical, inode: u64) -> ZffFileAttr {
    let acquisition_start = match OffsetDateTime::from_unix_timestamp(object_footer.acquisition_start as i64) {
        Ok(time) => time.into(),
        Err(_) => UNIX_EPOCH
    };
    let acquisition_end = match OffsetDateTime::from_unix_timestamp(object_footer.acquisition_end as i64) {
        Ok(time) => time.into(),
        Err(_) => UNIX_EPOCH
    };
    let file_attr = FileAttr {
        ino: INodeNo(inode),
        size: object_footer.length_of_data,
        blocks: object_footer.length_of_data / DEFAULT_BLOCKSIZE as u64 + 1,
        atime: acquisition_end,
        mtime: acquisition_end,
        ctime: acquisition_end,
        crtime: acquisition_start,
        kind: FileType::RegularFile,
        perm: 0o644,
        nlink: 1,
        uid: Uid::effective().into(),
        gid: Gid::effective().into(),
        rdev: 0,
        flags: 0,
        blksize: DEFAULT_BLOCKSIZE,
    };
    ZffFileAttr::from(file_attr)
}