// - STD
use std::time::{Duration, UNIX_EPOCH};

// - external
use fuser::{FileAttr, FileType};

// - errors
pub(crate) const ERROR_UNSUPPORTED_HEADER_VERSION: &str = "The current header version is unsupported by zffmount.";
pub(crate) const ERROR_PARSE_MAIN_HEADER: &str = "An error occurred while trying to parse the main header: ";
pub(crate) const ERROR_UNKNOWN_HEADER: &str = "Could not read header of this file. This file is not a well formatted zff file.";
pub(crate) const ERROR_PARSE_SEGMENT_HEADER: &str = "An error occurred while trying to parse the segment header: ";



pub(crate) const EXIT_STATUS_ERROR: i32 = 1;
pub(crate) const EXIT_STATUS_SUCCESS: i32 = 0;

pub(crate) const MOUNT_SUCCESSFUL: &str = "The image file(s) was/were mounted successfully to ";
pub(crate) const UNMOUNT_HINT: &str = "\nYou can unmount the file(s) by pressing CTRL+C - or unmount manually by typing umount";
pub(crate) const UNMOUNT_SUCCESSFUL: &str = "\nUnmount successful. Have a nice day.";


// Zff Overlay FS
pub(crate) const OBJECT_PREFIX: &str = "object_";
pub(crate) const ZFF_OVERLAY_SPECIAL_INODE_ROOT_DIR: u64 = 2;
pub(crate) const ZFF_OVERLAY_ROOT_DIR_ATTR: FileAttr = FileAttr {
    ino: 2,
    size: 0,
    blocks: 0,
    atime: UNIX_EPOCH, // 1970-01-01 00:00:00
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::Directory,
    perm: 0o755,
    nlink: 2,
    uid: 501,
    gid: 20,
    rdev: 0,
    flags: 0,
    blksize: 512,
};
pub(crate) const ZFF_OVERLAY_DEFAULT_ENTRY_GENERATION: u64 = 0;

// fuser constants
pub(crate) const TTL: Duration = Duration::from_secs(1); // 1 second

// special paths
pub(crate) const CURRENT_DIR: &str = ".";
pub(crate) const PARENT_DIR: &str = "..";