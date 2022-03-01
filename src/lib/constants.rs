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

// fuser constants
pub(crate) const TTL: Duration = Duration::from_secs(1); // 1 second
pub(crate) const DEFAULT_BLOCKSIZE: u32 = 512;
pub(crate) const FILESYSTEM_NAME: &str = "zff-fs";

pub(crate) const DEFAULT_DIR_INODE: u64 = 1;

// metadata file
pub(crate) const DEFAULT_METADATA_NAME: &'static str = "metadata.toml";
pub(crate) const DEFAULT_METADATA_INODE: u64 = 2;
pub(crate) const DEFAULT_METADATA_FILE_PERMISSION: u16 = 0o644;
pub(crate) const DEFAULT_METADATA_HARDLINKS: u32 = 1;

// zff image file
pub(crate) const DEFAULT_ZFF_IMAGE_NAME: &'static str = "zff_image.dd";
pub(crate) const DEFAULT_ZFF_IMAGE_INODE: u64 = 3;
pub(crate) const DEFAULT_ZFF_IMAGE_FILE_PERMISSION: u16 = 0o644;
pub(crate) const DEFAULT_ZFF_IMAGE_HARDLINKS: u32 = 1;


pub(crate) const DEFAULT_DIR_ATTR: FileAttr = FileAttr {
    ino: DEFAULT_DIR_INODE,
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
pub(crate) const DEFAULT_ENTRY_GENERATION: u64 = 0;

// special paths
pub(crate) const PWD: &'static str = ".";