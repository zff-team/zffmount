// - Parent
use super::*;

use winfsp::filesystem::{
    DirMarker, FileSecurity, FileSystemContext, OpenFileInfo,
};
use winfsp::util::SafeDropHandle;
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::Storage::FileSystem::FILE_ACCESS_RIGHTS;
use winfsp::U16CStr;

/// Represents an open file handle in the WinFSP filesystem.
#[derive(Debug)]
pub struct ZffFileContext {
    inode: u64,
    is_directory: bool,
}

impl<R: Read + Seek + Send + Sync + 'static> FileSystemContext for ZffFs<R> {
    type FileContext = ZffFileContext;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [std::ffi::c_void]>,
        _resolve_reparse_points: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let path = file_name.to_string_lossy();
        debug!("GET_SECURITY_BY_NAME: {}", path);

        let inode = match resolve_path_to_inode(&self.cache, self.shift_value, &path) {
            Some(ino) => ino,
            None => {
                debug!("GET_SECURITY_BY_NAME: path not found: {}", path);
                return Err(winfsp::FspError::NTSTATUS(
                    windows_sys::Win32::Foundation::STATUS_OBJECT_NAME_NOT_FOUND,
                ));
            }
        };

        let attributes = if inode == SPECIAL_INODE_ROOT_DIR {
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY
        } else {
            match self.cache.inode_attributes_map.get(&inode) {
                Some(attr) => attr.info().file_attributes,
                None => FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_NORMAL,
            }
        };

        // Write security descriptor to buffer if provided
        let sd_size = if let Some(sd_buf) = security_descriptor {
            let sddl = READ_ONLY_SECURITY_DESCRIPTOR_SDDL;
            let sddl_wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let mut sd_len: u32 = 0;

            unsafe {
                let result = windows_sys::Win32::Security::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl_wide.as_ptr(),
                    1, // SDDL_REVISION_1
                    &mut sd,
                    &mut sd_len,
                );
                if result != 0 && !sd.is_null() {
                    let copy_len = std::cmp::min(sd_len as usize, sd_buf.len());
                    std::ptr::copy_nonoverlapping(
                        sd as *const u8,
                        sd_buf.as_mut_ptr() as *mut u8,
                        copy_len,
                    );
                    windows_sys::Win32::System::Memory::LocalFree(sd as *mut std::ffi::c_void);
                    sd_len as u64
                } else {
                    0
                }
            }
        } else {
            0
        };

        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: sd_size,
            attributes,
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: FILE_ACCESS_RIGHTS,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let path = file_name.to_string_lossy();
        debug!("OPEN: {}", path);

        let inode = match resolve_path_to_inode(&self.cache, self.shift_value, &path) {
            Some(ino) => ino,
            None => {
                debug!("OPEN: path not found: {}", path);
                return Err(winfsp::FspError::NTSTATUS(
                    windows_sys::Win32::Foundation::STATUS_OBJECT_NAME_NOT_FOUND,
                ));
            }
        };

        let is_directory;
        if inode == SPECIAL_INODE_ROOT_DIR {
            let info = default_root_dir_file_info();
            *file_info.as_mut() = info;
            is_directory = true;
        } else {
            match self.cache.inode_attributes_map.get(&inode) {
                Some(attr) => {
                    *file_info.as_mut() = attr.info().clone();
                    is_directory = (attr.info().file_attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                }
                None => {
                    return Err(winfsp::FspError::NTSTATUS(
                        windows_sys::Win32::Foundation::STATUS_OBJECT_NAME_NOT_FOUND,
                    ));
                }
            }
        }

        Ok(ZffFileContext { inode, is_directory })
    }

    fn close(&self, _context: Self::FileContext) {
        // no-op: no resources to release
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        debug!("GET_FILE_INFO: inode {}", context.inode);

        if context.inode == SPECIAL_INODE_ROOT_DIR {
            *file_info = default_root_dir_file_info();
        } else {
            match self.cache.inode_attributes_map.get(&context.inode) {
                Some(attr) => *file_info = attr.info().clone(),
                None => {
                    return Err(winfsp::FspError::NTSTATUS(
                        windows_sys::Win32::Foundation::STATUS_OBJECT_NAME_NOT_FOUND,
                    ));
                }
            }
        }

        Ok(())
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        debug!("READ: inode {}, offset {}, size {}", context.inode, offset, buffer.len());

        let (object_no, file_no) = match self.cache.inode_reverse_map.get(&context.inode) {
            Some(data) => *data,
            None => {
                error!("READ: inode {} not found in reverse map.", context.inode);
                return Err(winfsp::FspError::NTSTATUS(
                    windows_sys::Win32::Foundation::STATUS_OBJECT_NAME_NOT_FOUND,
                ));
            }
        };

        let mut zffreader = self.zffreader.lock().unwrap();

        if file_no == 0 {
            // physical object
            if let Err(e) = zffreader.set_active_object(object_no) {
                error!("READ: error setting active object {object_no}: {e}");
                return Err(winfsp::FspError::NTSTATUS(
                    windows_sys::Win32::Foundation::STATUS_UNSUCCESSFUL,
                ));
            }
        } else {
            // logical object
            if let Err(e) = prepare_zffreader_logical_file(&mut zffreader, object_no, file_no) {
                error!("READ: error preparing file {file_no} of object {object_no}: {e}");
                return Err(winfsp::FspError::NTSTATUS(
                    windows_sys::Win32::Foundation::STATUS_UNSUCCESSFUL,
                ));
            }
        }

        if let Err(e) = zffreader.seek(SeekFrom::Start(offset)) {
            error!("READ: seek error for inode {}: {e}", context.inode);
            return Err(winfsp::FspError::NTSTATUS(
                windows_sys::Win32::Foundation::STATUS_UNSUCCESSFUL,
            ));
        }

        match zffreader.read(buffer) {
            Ok(bytes_read) => Ok(bytes_read as u32),
            Err(e) => {
                error!("READ: read error for inode {}: {e}", context.inode);
                Err(winfsp::FspError::NTSTATUS(
                    windows_sys::Win32::Foundation::STATUS_UNSUCCESSFUL,
                ))
            }
        }
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker<'_>,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        debug!("READ_DIRECTORY: inode {}", context.inode);

        let mut entries: Vec<(String, FileInfo)> = Vec::new();

        // Add "." entry
        let self_info = if context.inode == SPECIAL_INODE_ROOT_DIR {
            default_root_dir_file_info()
        } else {
            match self.cache.inode_attributes_map.get(&context.inode) {
                Some(attr) => attr.info().clone(),
                None => default_root_dir_file_info(),
            }
        };
        entries.push((CURRENT_DIR.to_string(), self_info));

        // Add ".." entry
        entries.push((PARENT_DIR.to_string(), default_root_dir_file_info()));

        if context.inode == SPECIAL_INODE_ROOT_DIR {
            // list object directories
            for (&obj_number, obj_type) in &self.cache.object_list {
                if obj_type == &ZffReaderObjectType::Encrypted {
                    continue;
                }
                let name = format!("{OBJECT_PATH_PREFIX}{obj_number}");
                let obj_inode = obj_number + 1;
                let info = match self.cache.inode_attributes_map.get(&obj_inode) {
                    Some(attr) => attr.info().clone(),
                    None => {
                        let mut info = FileInfo::default();
                        info.file_attributes = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY;
                        info.index_number = obj_inode;
                        info
                    }
                };
                entries.push((name, info));
            }
        } else if context.inode <= self.shift_value {
            // object directory — list its contents
            let obj_number = context.inode - 1;
            let mut zffreader = self.zffreader.lock().unwrap();
            if let Err(e) = zffreader.set_active_object(obj_number) {
                error!("READ_DIRECTORY: error setting active object {obj_number}: {e}");
                return Err(winfsp::FspError::NTSTATUS(
                    windows_sys::Win32::Foundation::STATUS_UNSUCCESSFUL,
                ));
            }
            match self.cache.object_list.get(&obj_number) {
                Some(ZffReaderObjectType::Physical) => {
                    let footer = match zffreader.active_object_footer() {
                        Ok(ObjectFooter::Physical(f)) => f,
                        _ => {
                            return Err(winfsp::FspError::NTSTATUS(
                                windows_sys::Win32::Foundation::STATUS_UNSUCCESSFUL,
                            ));
                        }
                    };
                    let ino = footer.first_chunk_number + self.shift_value;
                    let info = match self.cache.inode_attributes_map.get(&ino) {
                        Some(attr) => attr.info().clone(),
                        None => FileInfo::default(),
                    };
                    entries.push((ZFF_PHYSICAL_OBJECT_NAME.to_string(), info));
                }
                Some(ZffReaderObjectType::Logical) => {
                    let footer = match zffreader.active_object_footer() {
                        Ok(ObjectFooter::Logical(f)) => f,
                        _ => {
                            return Err(winfsp::FspError::NTSTATUS(
                                windows_sys::Win32::Foundation::STATUS_UNSUCCESSFUL,
                            ));
                        }
                    };
                    for filenumber in footer.root_dir_filenumbers() {
                        if let Some(entry) =
                            dir_entry_for_file(&mut zffreader, *filenumber, self.shift_value, &self.cache)
                        {
                            entries.push(entry);
                        }
                    }
                }
                _ => {}
            }
        } else {
            // subdirectory of a logical object
            let (object_no, file_no) = match self.cache.inode_reverse_map.get(&context.inode) {
                Some(data) => *data,
                None => {
                    return Err(winfsp::FspError::NTSTATUS(
                        windows_sys::Win32::Foundation::STATUS_OBJECT_NAME_NOT_FOUND,
                    ));
                }
            };
            let mut zffreader = self.zffreader.lock().unwrap();
            if let Err(e) = prepare_zffreader_logical_file(&mut zffreader, object_no, file_no) {
                error!("READ_DIRECTORY: error preparing file {file_no} of object {object_no}: {e}");
                return Err(winfsp::FspError::NTSTATUS(
                    windows_sys::Win32::Foundation::STATUS_UNSUCCESSFUL,
                ));
            }

            // read children list
            let mut buf = Vec::new();
            if let Err(e) = zffreader.rewind() {
                error!("READ_DIRECTORY: rewind error: {e}");
                return Err(winfsp::FspError::NTSTATUS(
                    windows_sys::Win32::Foundation::STATUS_UNSUCCESSFUL,
                ));
            }
            if let Err(e) = zffreader.read_to_end(&mut buf) {
                error!("READ_DIRECTORY: read_to_end error: {e}");
                return Err(winfsp::FspError::NTSTATUS(
                    windows_sys::Win32::Foundation::STATUS_UNSUCCESSFUL,
                ));
            }
            let children = match Vec::<u64>::decode_directly(&mut buf.as_slice()) {
                Ok(vec) => vec,
                Err(e) => {
                    error!("READ_DIRECTORY: decode error: {e}");
                    return Err(winfsp::FspError::NTSTATUS(
                        windows_sys::Win32::Foundation::STATUS_UNSUCCESSFUL,
                    ));
                }
            };

            for filenumber in &children {
                if let Some(entry) =
                    dir_entry_for_file(&mut zffreader, *filenumber, self.shift_value, &self.cache)
                {
                    entries.push(entry);
                }
            }
        }

        // Write entries to buffer, respecting the marker for pagination
        let mut bytes_written: u32 = 0;
        let mut past_marker = marker.is_none();

        for (name, info) in &entries {
            if !past_marker {
                if marker.is_current() && name == CURRENT_DIR {
                    past_marker = true;
                    continue;
                }
                if marker.is_parent() && name == PARENT_DIR {
                    past_marker = true;
                    continue;
                }
                if let Some(marker_name) = marker.inner() {
                    let marker_str = marker_name.to_string_lossy();
                    if name == &marker_str.as_ref() {
                        past_marker = true;
                        continue;
                    }
                }
                continue;
            }

            let name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            let entry_size = std::mem::size_of::<winfsp::filesystem::DirInfo>()
                + name_wide.len() * std::mem::size_of::<u16>();

            if bytes_written as usize + entry_size > buffer.len() {
                break;
            }

            // Write the entry using WinFSP's DirInfo structure
            let remaining = &mut buffer[bytes_written as usize..];
            if remaining.len() < entry_size {
                break;
            }

            // Construct DirInfo in the buffer
            let dir_info_ptr = remaining.as_mut_ptr() as *mut winfsp::filesystem::DirInfo;
            unsafe {
                (*dir_info_ptr).size = entry_size as u16;
                (*dir_info_ptr).file_info = info.clone();
                let name_dst = std::slice::from_raw_parts_mut(
                    (*dir_info_ptr).file_name.as_mut_ptr(),
                    name_wide.len(),
                );
                name_dst.copy_from_slice(&name_wide);
            }

            bytes_written += entry_size as u32;
        }

        Ok(bytes_written)
    }

    fn get_volume_info(&self, out_volume_info: &mut winfsp::filesystem::VolumeInfo) -> winfsp::Result<()> {
        out_volume_info.total_size = 0;
        out_volume_info.free_size = 0;

        let label: Vec<u16> = ZFF_OVERLAY_FS_NAME.encode_utf16().collect();
        let copy_len = std::cmp::min(label.len(), out_volume_info.volume_label.len());
        out_volume_info.volume_label[..copy_len].copy_from_slice(&label[..copy_len]);
        out_volume_info.volume_label_length = (copy_len * std::mem::size_of::<u16>()) as u16;

        Ok(())
    }
}

/// Creates a directory entry (name + FileInfo) for a given file number.
/// Returns None if the file is a special type that should be skipped on Windows.
fn dir_entry_for_file<R: Read + Seek>(
    zffreader: &mut ZffReader<R>,
    filenumber: u64,
    shift_value: u64,
    cache: &ZffFsCache,
) -> Option<(String, FileInfo)> {
    zffreader.set_active_file(filenumber).ok()?;
    let mut filemetadata = zffreader.current_filemetadata().ok()?.clone();
    let mut zff_filetype = filemetadata.file_type;

    if zff_filetype == ZffFileType::Hardlink {
        let mut buffer = Vec::new();
        zffreader.rewind().ok()?;
        zffreader.read_to_end(&mut buffer).ok()?;
        let original_filenumber = u64::decode_directly(&mut buffer.as_slice()).ok()?;
        zffreader.set_active_file(original_filenumber).ok()?;
        filemetadata = zffreader.current_filemetadata().ok()?.clone();
        zff_filetype = filemetadata.file_type;
    }

    // Skip special file types on Windows
    match zff_filetype {
        ZffFileType::File | ZffFileType::Directory => {}
        ZffFileType::Symlink => {} // expose as regular file
        _ => return None,          // skip FIFOs, char/block devices
    }

    let inode = filemetadata.first_chunk_number + shift_value;
    let filename = match &filemetadata.filename {
        Some(name) => name.clone(),
        None => zffreader.current_fileheader().ok()?.filename,
    };

    let info = match cache.inode_attributes_map.get(&inode) {
        Some(attr) => attr.info().clone(),
        None => FileInfo::default(),
    };

    Some((filename, info))
}
