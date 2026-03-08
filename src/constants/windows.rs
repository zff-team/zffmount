// - Parent
use super::*;

use winfsp::filesystem::FileInfo;

// Windows file attributes
pub(crate) const FILE_ATTRIBUTE_READONLY: u32 = 0x00000001;
pub(crate) const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;
pub(crate) const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;

// SDDL security descriptor granting Everyone read access
pub(crate) const READ_ONLY_SECURITY_DESCRIPTOR_SDDL: &str = "D:P(A;;FR;;;WD)";

// Offset in seconds between Unix epoch (1970-01-01) and Windows FILETIME epoch (1601-01-01)
pub(crate) const UNIX_TO_WINDOWS_EPOCH_OFFSET: i64 = 11_644_473_600;

// Number of 100-nanosecond intervals per second (FILETIME resolution)
pub(crate) const FILETIME_INTERVALS_PER_SECOND: i64 = 10_000_000;

pub(crate) fn default_root_dir_file_info() -> FileInfo {
    let mut info = FileInfo::default();
    info.file_attributes = FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY;
    info.index_number = SPECIAL_INODE_ROOT_DIR;
    info
}