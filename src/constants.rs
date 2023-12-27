// - STD
use std::time::{Duration, UNIX_EPOCH};

// - external
use fuser::{FileAttr, FileType};

// - errors
pub(crate) const EXIT_STATUS_ERROR: i32 = 1;
pub(crate) const EXIT_STATUS_SUCCESS: i32 = 0;

// Zff Overlay FS
pub(crate) const ZFF_OVERLAY_FS_NAME: &str = "ZffOverlayFs";
pub(crate) const OBJECT_PREFIX: &str = "object_";
pub(crate) const DEFAULT_ROOT_DIR_ATTR: FileAttr = FileAttr {
    ino: SPECIAL_INODE_ROOT_DIR,
    size: 0,
    blocks: 0,
    atime: UNIX_EPOCH, // 1970-01-01 00:00:00
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::Directory,
    perm: 0o755,
    nlink: 2,
    uid: 0,
    gid: 0,
    rdev: 0,
    flags: 0,
    blksize: 512,
};
// other default values
pub(crate) const SPECIAL_INODE_ROOT_DIR: u64 = 1;
pub(crate) const DEFAULT_BLOCKSIZE: u32 = 512;
pub(crate) const ZFF_PHYSICAL_OBJECT_NAME: &str = "zff_image.dd";

pub(crate) const DEFAULT_TRASHFOLDER_NAME: &str = ".Trash";

pub(crate) const DEFAULT_ENTRY_GENERATION: u64 = 0;

// fuser constants
pub(crate) const TTL: Duration = Duration::from_secs(1); // 1 second

// special paths
pub(crate) const CURRENT_DIR: &str = ".";
pub(crate) const PARENT_DIR: &str = "..";

// prefix
pub(crate) const OBJECT_PATH_PREFIX: &str = "object_";

pub(crate) const ATIME: &str = "atime";
pub(crate) const MTIME: &str = "mtime";
pub(crate) const CTIME: &str = "ctime";
pub(crate) const BTIME: &str = "btime";
