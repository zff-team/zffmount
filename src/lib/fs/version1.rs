// - STD
use std::collections::HashMap;
use std::ffi::OsStr;
use std::time::{UNIX_EPOCH};
use std::io::{Read, Seek, SeekFrom};

use std::process::exit;

// - internal
use zff::{
    Result,
    header::version1::*,
    HeaderCoding,
    version1::ZffReader,
    ZffError,
    ZffErrorKind,
};


use crate::lib::constants::*;

// - external
use log::{error};

// - external
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};
use nix::unistd::{Uid, Gid};
use libc::ENOENT;
use time::{OffsetDateTime, format_description};
use serde::ser::{Serialize, Serializer, SerializeStruct};
use toml;
use hex::ToHex;

pub struct ZffInfo(MainHeader);

impl Serialize for ZffInfo {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ZffInfo", 1)?;
        state.serialize_field("zff_version", &self.0.version())?;
        if let Some(value) = &self.0.description_header().case_number() {
            state.serialize_field("case_number", &value)?;
        }
        if let Some(value) = &self.0.description_header().evidence_number() {
            state.serialize_field("evidence_number", &value)?;
        }
        if let Some(value) = &self.0.description_header().examiner_name() {
            state.serialize_field("examiner_name", &value)?;
        }
        if let Some(value) = &self.0.description_header().notes() {
            state.serialize_field("notes", &value)?;
        }
        //unwrap should be safe here, because the format string was tested.
        let format = format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second] UTC").unwrap();
        //acquisition start
        if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.0.description_header().acquisition_start() as i64) {
            if let Ok(formatted_dt) = dt.format(&format) {
                state.serialize_field("acquisition_start", &formatted_dt)?;
            } else {
                state.serialize_field("acquisition_start", &self.0.description_header().acquisition_start())?;
            }
        } else {
            state.serialize_field("acquisition_start", &self.0.description_header().acquisition_start())?;
        };
        if let Ok(dt) = OffsetDateTime::from_unix_timestamp(self.0.description_header().acquisition_end() as i64) {
            if let Ok(formatted_dt) = dt.format(&format) {
                state.serialize_field("acquisition_end", &formatted_dt)?;
            } else {
                state.serialize_field("acquisition_end", &self.0.description_header().acquisition_end())?;
            }
        } else {
            state.serialize_field("acquisition_end", &self.0.description_header().acquisition_end())?;
        };
        
        state.serialize_field("compression_algorithm", &self.0.compression_header().algorithm().to_string())?;
        state.serialize_field("compression_level", &self.0.compression_header().level())?;

        if let Some(_) = self.0.encryption_header() {
            state.serialize_field("encrypted", &true)?;
        } else {
            state.serialize_field("encrypted", &false)?;
        }

        let mut hashes = HashMap::new();
        for hash_value in self.0.hash_header().hash_values() {
            hashes.insert(hash_value.hash_type().to_string(), hash_value.hash().encode_hex::<String>());
        }
        state.serialize_field("hashes", &hashes)?;
        
        state.serialize_field("chunk_size", &self.0.chunk_size())?;
        state.serialize_field("ed25519 signed", &self.0.has_signature())?;
        state.serialize_field("length_of_data", &self.0.length_of_data())?;
        state.serialize_field("unique_identifier", &self.0.unique_identifier())?;
        state.serialize_field("segment_size", &self.0.segment_size().to_string())?;
        state.serialize_field("number_of_segments", &self.0.number_of_segments())?;

        state.end()
    }
}

pub struct ZffFS<R: 'static +  Read + Seek> {
    zff_reader: ZffReader<R>,
}

impl<R: Read + Seek> ZffFS<R> {
    pub fn new(mut data: Vec<R>) -> Result<ZffFS<R>> {
        let main_header = MainHeader::decode_directly(&mut data[0])?;
        if let Some(_) = main_header.encryption_header() {
            data[0].rewind()?;
            return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, ERROR_MISSING_ENCRYPTION_KEY));
        };
        let zff_reader = ZffReader::new(data, main_header)?;
        Ok(Self {
            zff_reader: zff_reader,
        })
    }

    pub fn new_encrypted<P: AsRef<[u8]>>(mut data: Vec<R>, password: P) -> Result<ZffFS<R>> {
        let main_header = match MainHeader::decode_directly(&mut data[0]) {
            Ok(header) => header,
            Err(e) => match e.get_kind() {
                ZffErrorKind::HeaderDecodeMismatchIdentifier => {
                    data[0].seek(SeekFrom::Start(0))?;
                    MainHeader::decode_encrypted_header_with_password(&mut data[0], &password)?
                },
                _ => return Err(e),
            },
        };
        let mut zff_reader = ZffReader::new(data, main_header)?;
        zff_reader.decrypt_encryption_key(password)?;
        Ok(Self {
            zff_reader: zff_reader,
        })
    }

    //TODO return Result<FileAttr>.
    fn metadata_fileattr(&self) -> FileAttr {
        let serialized_data = match toml::Value::try_from(&ZffInfo(self.zff_reader.main_header().clone())) {
            Ok(value) => value.to_string(),
            Err(_) => {
                error!("{ERROR_SERIALIZE_METADATA}");
                exit(EXIT_STATUS_ERROR);
            }
        };
        let attr = FileAttr {
            ino: DEFAULT_VERSION1_METADATA_INODE,
            size: serialized_data.len() as u64,
            blocks: serialized_data.len() as u64 / DEFAULT_BLOCKSIZE as u64 + 1,
            atime: UNIX_EPOCH, // 1970-01-01 00:00:00
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: DEFAULT_READONLY_PERMISSIONS_REGULAR_FILE,
            nlink: 1,
            uid: Uid::effective().into(),
            gid: Gid::effective().into(),
            rdev: 0,
            flags: 0,
            blksize: DEFAULT_BLOCKSIZE,
        };
        attr
    }

    fn zff_image_fileattr(&self) -> FileAttr {
        let size = self.zff_reader.main_header().length_of_data();
        let acquisition_start = match self.zff_reader.main_header().description_header().acquisition_start() {
            0 => UNIX_EPOCH,
            start @ _ => match OffsetDateTime::from_unix_timestamp(start as i64) {
                Ok(time) => time.into(),
                Err(_) => UNIX_EPOCH,
            },
        };
        let acquisition_end = match self.zff_reader.main_header().description_header().acquisition_end() {
            0 => UNIX_EPOCH,
            end @ _ => match OffsetDateTime::from_unix_timestamp(end as i64) {
                Ok(time) => time.into(),
                Err(_) => UNIX_EPOCH,
            },
        };
        let attr = FileAttr {
            ino: DEFAULT_VERSION1_ZFFIMAGE_INODE,
            size: size,
            blocks: size / DEFAULT_BLOCKSIZE as u64 + 1,
            atime: acquisition_end, // 1970-01-01 00:00:00
            mtime: acquisition_end,
            ctime: acquisition_end,
            crtime: acquisition_start,
            kind: FileType::RegularFile,
            perm: DEFAULT_READONLY_PERMISSIONS_REGULAR_FILE,
            nlink: 1,
            uid: Uid::effective().into(),
            gid: Gid::effective().into(),
            rdev: 0,
            flags: 0,
            blksize: DEFAULT_BLOCKSIZE,
        };
        attr
    }

    //TODO return Result<String>.
    fn serialize_metadata(&self) -> String {
        let serialized_data = match toml::Value::try_from(ZffInfo(self.zff_reader.main_header().clone())) {
            Ok(value) => value,
            Err(_) => {
                error!("{ERROR_SERIALIZE_METADATA}");
                exit(EXIT_STATUS_ERROR);
            }
        };
        serialized_data.to_string()
    }
}

impl<R: Read + Seek> Filesystem for ZffFS<R> {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == SPECIAL_INODE_ROOT_DIR && name.to_str() == Some(DEFAULT_VERSION1_METADATA_NAME) {
            reply.entry(&TTL, &self.metadata_fileattr(), DEFAULT_ENTRY_GENERATION);
        } else if parent == SPECIAL_INODE_ROOT_DIR && name.to_str() == Some(DEFAULT_VERSION1_ZFF_IMAGE_NAME) {
            reply.entry(&TTL, &self.zff_image_fileattr(), DEFAULT_ENTRY_GENERATION);
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match ino {
            SPECIAL_INODE_ROOT_DIR => reply.attr(&TTL, &DEFAULT_ROOT_DIR_ATTR),
            DEFAULT_VERSION1_METADATA_INODE => reply.attr(&TTL, &self.metadata_fileattr()),
            DEFAULT_VERSION1_ZFFIMAGE_INODE => reply.attr(&TTL, &self.zff_image_fileattr()),
            _ => reply.error(ENOENT),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        if ino == DEFAULT_VERSION1_METADATA_INODE {
            reply.data(&self.serialize_metadata().as_bytes()[offset as usize..]);
        } else if ino == DEFAULT_VERSION1_ZFFIMAGE_INODE {
            let mut buffer = vec![0u8; size as usize];
            match self.zff_reader.seek(SeekFrom::Start(offset as u64)) {
                Ok(_) => (),
                Err(e) => error!("seek error: {e}"),
            }
            match self.zff_reader.read(&mut buffer) {
                Ok(_) => (),
                Err(e) => error!("read error: {e}"),
            }
            reply.data(&buffer);
        } else {
            error!("inode number mismatch: {ino}");
            reply.error(ENOENT);
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != SPECIAL_INODE_ROOT_DIR {
            reply.error(ENOENT);
            return;
        }

        let entries = vec![
            (SPECIAL_INODE_ROOT_DIR, FileType::Directory, CURRENT_DIR),
            (SPECIAL_INODE_ROOT_DIR, FileType::Directory, PARENT_DIR),
            (DEFAULT_VERSION1_METADATA_INODE, FileType::RegularFile, DEFAULT_VERSION1_METADATA_NAME),
            (DEFAULT_VERSION1_ZFFIMAGE_INODE, FileType::RegularFile, DEFAULT_VERSION1_ZFF_IMAGE_NAME),
        ];

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            // i + 1 means the index of the next entry
            if reply.add(entry.0, (i + 1) as i64, entry.1, entry.2) {
                break;
            }
        }
        reply.ok();
    }
}