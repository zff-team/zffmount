// - Parent
use super::*;

// - STD
use std::ffi::OsStr;

// - Modules
mod filesystem;

// - external
pub use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request, MountOption
};
pub use libc::ENOENT;
pub use nix::unistd::{Uid, Gid};
pub use signal_hook::{consts::{SIGINT, SIGHUP, SIGTERM}, iterator::Signals};
// as far as I know, passthrough is not available for FUSE on MacOS systems.
#[cfg(target_os = "linux")]
pub use fuser::{
    KernelConfig, consts::FUSE_PASSTHROUGH,
};
#[cfg(target_os = "linux")]
pub use std::ffi::c_int;

pub fn fuse_unix<R: Read + Seek + Send + Sync + 'static>(fs: ZffFs<R>, args: &Cli) {
    let mountoptions = vec![
        MountOption::RO, 
        MountOption::FSName(String::from(ZFF_OVERLAY_FS_NAME)),
        MountOption::DefaultPermissions,
        ];
    let session = match fuser::spawn_mount2(fs, &args.mount_point, &mountoptions) {
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
            warn!("UNMOUNT: Received shutdown signal {:?}. The filesystems will be unmounted, as soon as the resource is no longer busy.", sig);
            r.store(true, Ordering::SeqCst);
        }
    });

    loop {
        sleep(Duration::from_secs(1)); // to reduce the CPU usage
        if running.load(Ordering::SeqCst) {
            session.join();
            info!("Filesystem successfully unmounted. Session closed.");
            exit(EXIT_STATUS_SUCCESS);
        }
    }
}


fn file_attr_of_file<R: Read + Seek>(mut filemetadata: FileMetadata, zffreader: &mut ZffReader<R>, shift_value: u64) -> Result<FileAttr> {
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

fn file_attr_of_object_footer(object_footer: &ObjectFooter) -> ZffFileAttr {
    let acquisition_start = match OffsetDateTime::from_unix_timestamp(object_footer.acquisition_start() as i64) {
        Ok(time) => time.into(),
        Err(_) => UNIX_EPOCH
    };
    let acquisition_end = match OffsetDateTime::from_unix_timestamp(object_footer.acquisition_end() as i64) {
        Ok(time) => time.into(),
        Err(_) => UNIX_EPOCH
    };
    let file_attr = FileAttr {
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
    };
    ZffFileAttr::from(file_attr)
}

pub fn inode_attributes_map_add_object<R: Read + Seek>(
    zffreader: &mut ZffReader<R>, 
    inode_attributes_map: &mut BTreeMap<u64, ZffFileAttr>, 
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
                let file_attr = ZffFileAttr::from(file_attr);
                inode_attributes_map.insert(inode, file_attr);
                counter += 1;
            }
        },
        ObjectFooter::Physical(ref phy_footer) => {
            let inode = phy_footer.first_chunk_number + shift_value;
            let mut file_attr = file_attr_of_object_footer(&object_footer);
            file_attr.attr_mut().ino = inode;
            file_attr.attr_mut().kind = FileType::RegularFile;
            file_attr.attr_mut().perm = 0o644;
            file_attr.attr_mut().size = phy_footer.length_of_data;
            file_attr.attr_mut().blocks = phy_footer.length_of_data / DEFAULT_BLOCKSIZE as u64 + 1;
            file_attr.attr_mut().nlink = 1;
            let file_attr = ZffFileAttr::from(file_attr);
            inode_attributes_map.insert(inode, file_attr); //0 is not a valid file number in zff, so we can use this as a placeholder
            counter += 1;
        },
        ObjectFooter::Virtual(_) => todo!(), //TODO
    };

    Ok(counter)
}

// hardlinks should be handled before calling this method.
pub fn convert_filetype<R: Read + Seek>(in_type: &ZffFileType, zffreader: &mut ZffReader<R>) -> Result<FileType> {
    let filetype = match in_type {
        ZffFileType::File => FileType::RegularFile,
        ZffFileType::Directory => FileType::Directory,
        ZffFileType::Symlink => FileType::Symlink,
        ZffFileType::Hardlink => unreachable!(),
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
                _ => unimplemented!()
            }
        },
        _ => unimplemented!()
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

pub fn readdir_logical_object_root<R: Read + Seek>(zffreader: &mut ZffReader<R>, shift_value: u64) -> Result<Vec<(u64, FileType, String)>> {
    if let ObjectFooter::Logical(footer) = zffreader.active_object_footer()? {
        readdir_entries_file(zffreader, shift_value, footer.root_dir_filenumbers())
    } else {
        Err(ZffError::new(ZffErrorKind::Invalid, ERR_INVALID_OBJECT_TYPE))
    }
}

pub fn readdir_entries_file<R: Read + Seek>(zffreader: &mut ZffReader<R>, shift_value: u64, children: &Vec<u64>) -> Result<Vec<(u64, FileType, String)>> {
    let mut entries = Vec::new();
    for filenumber in children {
        zffreader.set_active_file(*filenumber)?;
        let mut filemetadata = zffreader.current_filemetadata()?.clone();
        let filename = match filemetadata.filename {
            Some(ftype) => ftype,
            None => zffreader.current_fileheader()?.filename
        };
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
        entries.push((inode, filetype, filename.to_string()));
    }

    Ok(entries)
}
