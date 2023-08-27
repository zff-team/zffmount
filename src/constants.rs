// - STD
use std::time::{Duration, UNIX_EPOCH};

// - external
use fuser::{FileAttr, FileType};

// - errors
pub(crate) const ERROR_SETTING_SIGNAL_HANDLER: &str = "an error occurred while trying to set the signal handler for graceful umounting: ";
pub(crate) const ERROR_MISSING_ENCRYPTION_KEY: &str = "Zff file(s) are encrypted: You should enter the password by using the -p argument.";
pub(crate) const ERROR_SERIALIZE_METADATA: &str = "Could not serialize the metadata of the zff image.";

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

// Zff Object fs
pub(crate) const ZFF_OBJECT_FS_NAME: &str = "ZffObjectFs";
pub(crate) const ZFF_OBJECT_FS_PHYSICAL_ATTR_INO: u64 = 2;
pub(crate) const ZFF_OBJECT_FS_PHYSICAL_ATTR_PERM: u16 = DEFAULT_READONLY_PERMISSIONS_REGULAR_FILE;
pub(crate) const ZFF_OBJECT_FS_PHYSICAL_ATTR_NLINKS: u32 = 1;

// Zff version 1 image
pub(crate) const ZFF_VERSION1_IMAGE_FS_NAME: &str = "ZffFs";

// other default values
pub(crate) const SPECIAL_INODE_ROOT_DIR: u64 = 1;
pub(crate) const DEFAULT_BLOCKSIZE: u32 = 512;
pub(crate) const ZFF_PHYSICAL_OBJECT_NAME: &str = "zff_image.dd";

pub(crate) const DEFAULT_READONLY_PERMISSIONS_REGULAR_FILE: u16 = 0o555;

pub(crate) const DEFAULT_TRASHFOLDER_NAME: &str = ".Trash";

pub(crate) const DEFAULT_ENTRY_GENERATION: u64 = 0;

// fuser constants
pub(crate) const TTL: Duration = Duration::from_secs(1); // 1 second

// special paths
pub(crate) const CURRENT_DIR: &str = ".";
pub(crate) const PARENT_DIR: &str = "..";

// prefix
pub(crate) const OBJECT_PATH_PREFIX: &str = "object_";