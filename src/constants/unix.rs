// - Parent
use super::*;

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