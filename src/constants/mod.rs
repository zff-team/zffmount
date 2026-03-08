// - Parent
use super::*;

// - modules
#[cfg(target_family = "unix")]
mod unix;
#[cfg(target_family = "windows")]
mod windows;

// - re-exports
#[cfg(target_family = "unix")]
pub(crate) use unix::*;
#[cfg(target_family = "windows")]
pub(crate) use windows::*;

// - errors
pub(crate) const EXIT_STATUS_ERROR: i32 = 1;
pub(crate) const EXIT_STATUS_SUCCESS: i32 = 0;

// Zff Overlay FS
pub(crate) const ZFF_OVERLAY_FS_NAME: &str = "ZffOverlayFs";
pub(crate) const OBJECT_PREFIX: &str = "object_";

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

// - Error messages
pub(crate) const ERR_INVALID_OBJECT_TYPE: &str = "Invalid object type";