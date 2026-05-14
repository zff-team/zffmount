use zff::PlatformString;

// - Parent
use super::*;

// - STD
use std::sync::Mutex;

#[derive(Debug)]
pub enum PreloadChunkmapsMode {
    None,
    InMemory,
    Redb(redb::Database)
}

#[derive(Debug)]
pub struct PreloadChunkmaps {
    pub headers: bool,
    pub samebytes: bool,
    pub deduplication: bool,
    pub mode: PreloadChunkmapsMode
}

#[cfg(target_family = "unix")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZffFileAttr {
    pub fileattr: FileAttr,
    pub xattrs: HashMap<String, ZffMetadataExtendedValue>,
}

#[cfg(target_family = "unix")]
impl From<FileAttr> for ZffFileAttr {
    fn from(value: FileAttr) -> Self {
        Self {
            fileattr: value,
            xattrs: HashMap::new(),
        }
    }
}

impl From<ZffFileAttr> for FileAttr {
    fn from(value: ZffFileAttr) -> Self {
        value.fileattr
    }
}

impl From<ZffFileAttr> for HashMap<String, ZffMetadataExtendedValue> {
    fn from(value: ZffFileAttr) -> Self {
        value.xattrs
    }
}

#[cfg(target_family = "windows")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZffFileAttr(winfsp::filesystem::FileInfo);

#[cfg(target_family = "windows")]
impl ZffFileAttr {
    pub fn info(&self) -> &winfsp::filesystem::FileInfo {
        &self.0
    }

    pub fn info_mut(&mut self) -> &mut winfsp::filesystem::FileInfo {
        &mut self.0
    }
}

#[cfg(target_family = "windows")]
impl From<winfsp::filesystem::FileInfo> for ZffFileAttr {
    fn from(value: winfsp::filesystem::FileInfo) -> Self {
        Self(value)
    }
}


#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ZffFsCache {
    pub object_list: BTreeMap<u64, ZffReaderObjectType>,
    pub inode_reverse_map: BTreeMap<u64, (u64, u64)>, //<Inode, (object number, file number)
    pub filename_lookup_table: BTreeMap<PlatformString, Vec<(u64, u64)>>, //<Filename, Vec<Parent-Inode, Self-Inode>>
    pub inode_attributes_map: BTreeMap<u64, ZffFileAttr>,
}

impl ZffFsCache {
    fn with_data(
        object_list: BTreeMap<u64, ZffReaderObjectType>,
        inode_reverse_map: BTreeMap<u64, (u64, u64)>,
        filename_lookup_table: BTreeMap<PlatformString, Vec<(u64, u64)>>,
        inode_attributes_map: BTreeMap<u64, ZffFileAttr>) -> Self 
    {
        Self {
            object_list,
            inode_reverse_map,
            filename_lookup_table,
            inode_attributes_map,
        }
    }
}

#[derive(Debug)]
pub struct ZffFs<R: Read + Seek + Send + Sync> {
    pub zffreader: Mutex<ZffReader<R>>,
    pub shift_value: u64,
    pub cache: ZffFsCache,
}

impl<R: Read + Seek + Send + Sync> ZffFs<R> {
    pub fn new(
        inputfiles: Vec<R>, 
        decryption_passwords: &HashMap<u64, String>, 
        preload_chunkmaps: PreloadChunkmaps) -> Self {
        info!("Reading segment files to create initial ZffReader.");
        let mut zffreader = match ZffReader::with_reader(inputfiles) {
            Ok(reader) => reader,
            Err(e) => {
                error!("An error occurred while trying to create the ZffReader: {e}");
                exit(EXIT_STATUS_ERROR);
            }
        };

        let mut object_list = match zffreader.list_objects() {
            Ok(list) => list,
            Err(e) => {
                error!("An error occurred while trying to get the ZffReader object list: {e}");
                exit(EXIT_STATUS_ERROR);
            }
        };
        let (phy, log, enc) = object_list.values().fold((0, 0, 0), |(phy, log, enc), val| {
            match val {
                ZffReaderObjectType::Physical => (phy + 1, log, enc),
                ZffReaderObjectType::Logical => (phy, log + 1, enc),
                ZffReaderObjectType::Encrypted => (phy, log, enc + 1),
                ZffReaderObjectType::Virtual => todo!(), //TODO
            }
        });
        info!("ZffReader created successfully. Found {phy} physical, {log} logical and {enc} encrypted objects.");

        //initialize and decrypt objects
        for (object_number, obj_type) in &object_list {
            match zffreader.initialize_object(*object_number) {
                Ok(_) => info!("Successfully initialized {obj_type} object {object_number}"),
                Err(e) => error!("Could not inititalize object {object_number} due following error: {e}"),
            }

            if obj_type == &ZffReaderObjectType::Encrypted {
                let pw = match decryption_passwords.get(object_number) {
                    Some(pw) => pw.clone(),
                    None => match enter_password_dialog(*object_number)  {
                        Some(pw) => pw,
                        None => {
                            info!("No password entered for encrypted object {object_number}.");
                            String::new()
                        }
                    }
                };
                match zffreader.decrypt_object(*object_number, pw) {
                    Ok(o_type) => info!("Object {object_number} ({o_type} object) decrypted successfully"),
                    Err(e) => warn!("Could not decrypt object {object_number}: {e}"),
                }
            }
        }

        // from here, we can work with unencrypted/decrypted objects.
        object_list = zffreader.list_decrypted_objects();

        // set object inodes and shift value
        let numbers_of_decrypted_objects: Vec<u64> = object_list.iter().map(|(&k, _)| k).collect();
        let shift_value = match numbers_of_decrypted_objects.iter().max() {
            Some(value) => *value + 1, // + 1 for root dir inode
            None => 1,
        };

        let mut inode_reverse_map = BTreeMap::new();
        let mut filename_lookup_table = BTreeMap::new();
        let mut inode_attributes_map = BTreeMap::new();

        for (object_number, obj_type) in &object_list {
            //setup inode reverse map
            match inode_reverse_map_add_object(&mut zffreader, &mut inode_reverse_map, *object_number, shift_value) {
                Ok(noe) => debug!("{noe} entries for object {object_number} added to inode reverse map."),
                Err(e) => {
                    error!("An error occurred while trying to fill the inode reverse map.");
                    debug!("{e}");
                    exit(EXIT_STATUS_ERROR);
                }
            }; 
            
            //setup inode attributes map
            match inode_attributes_map_add_object(&mut zffreader, &mut inode_attributes_map, *object_number, shift_value) {
                Ok(noe) => debug!("{noe} entries for object {object_number} added to inode attributes map."),
                Err(e) => {
                    error!("An error occurred while trying to fill the inode attributes map.");
                    debug!("{e}");
                    exit(EXIT_STATUS_ERROR);
                }
            };

            // only for logical objects
            if obj_type == &ZffReaderObjectType::Logical {
                //setup lookup table
                match filename_lookup_table_add_object(&mut zffreader, &mut filename_lookup_table, *object_number, shift_value) {
                    Ok(noe) => debug!("{noe} entries for object {object_number} added to lookup table."),
                    Err(e) => {
                        error!("An error occurred while trying to fill the lookup table.");
                        debug!("{e}");
                        exit(EXIT_STATUS_ERROR);
                    }
                };
            }
        }
        let cache = ZffFsCache::with_data(object_list, inode_reverse_map, filename_lookup_table, inode_attributes_map);

        // setup mode
        match preload_chunkmaps.mode {
            PreloadChunkmapsMode::None => (),
            PreloadChunkmapsMode::InMemory => {
                info!("Set preload chunkmap mode to in-memory ...");
                if let Err(e) = zffreader.set_preload_chunkmaps_mode_in_memory() {
                    error!("An error occurred while trying to create the in memory preload chunkmap.");
                    debug!("{e}");
                    exit(EXIT_STATUS_ERROR);
                };
            }
            PreloadChunkmapsMode::Redb(db) => {
                info!("Set preload chunkmap mode to redb ...");
                if let Err(e) = zffreader.set_preload_chunkmap_mode_redb(db) {
                    error!("An error occurred while trying to create the redb preload chunkmap.");
                    debug!("{e}");
                    exit(EXIT_STATUS_ERROR);
                };
            }
        }

        // preload appropriate chunkmaps
        if preload_chunkmaps.headers {
            info!("Preload chunk header map ...");
            if let Err(e) = zffreader.preload_chunk_header_map_full() {
                error!("An error occurred while trying to preload chunkmap.");
                debug!("{e}");
                exit(EXIT_STATUS_ERROR);
            };
            info!("Chunk header map successfully preloaded ...");
        }

        if preload_chunkmaps.samebytes {
            info!("Preload chunkmap samebytes ...");
            if let Err(e) = zffreader.preload_chunk_samebytes_map_full() {
                error!("An error occurred while trying to preload chunkmap.");
                debug!("{e}");
                exit(EXIT_STATUS_ERROR);
            };
            info!("Chunkmap samebytes successfully preloaded ...");
        }

        if preload_chunkmaps.deduplication {
            info!("Preload chunkmap deduplication ...");
            if let Err(e) = zffreader.preload_chunk_deduplication_map_full() {
                error!("An error occurred while trying to preload chunkmap.");
                debug!("{e}");
                exit(EXIT_STATUS_ERROR);
            };
            info!("Chunkmap deduplication successfully preloaded ...");
        }

        info!("ZffFs successfully initialized and can be used now.");

        Self {
            zffreader: Mutex::new(zffreader),
            shift_value,
            cache,
        }
    }
}

pub fn enter_password_dialog(obj_no: u64) -> Option<String> {
    PasswordDialog::with_theme(&ColorfulTheme::default())
        .with_prompt(format!("Enter the password for object {obj_no}"))
        .interact().ok()
}

// returns the number of entries which were added.
pub fn inode_reverse_map_add_object<R: Read + Seek>(
    zffreader: &mut ZffReader<R>,
    inode_reverse_map: &mut BTreeMap<u64, (u64, u64)>,
    object_number: u64,
    shift_value: u64) -> Result<u64> {
    zffreader.set_active_object(object_number)?;
    let mut counter = 0;
    match zffreader.active_object_footer()? {
        ObjectFooter::Logical(object_footer) => {
            for filenumber in object_footer.file_footer_segment_numbers().keys() {
                let mut filenumber = *filenumber;
                zffreader.set_active_file(filenumber)?;

                let filemetadata = zffreader.current_filemetadata()?;
                let mut inode = get_inode(filemetadata, shift_value);
                
                // checks if the file is a hardlink. In that case, the original file hould be added
                if filemetadata.header.file_type == ZffFileType::Hardlink {
                    let mut buffer = Vec::new();
                    zffreader.rewind()?;
                    zffreader.read_to_end(&mut buffer)?;
                    let original_filenumber = u64::decode_directly(&mut buffer.as_slice())?;
                    zffreader.set_active_file(original_filenumber)?;
                    let filemetadata = zffreader.current_filemetadata()?.clone();
                    inode = get_inode(&filemetadata, shift_value);
                    filenumber = original_filenumber;
                }
                inode_reverse_map.insert(inode, (object_number, filenumber));
                counter += 1;
            }
        },
        ObjectFooter::Physical(object_footer) => {
            let inode = object_footer.first_chunk_number + shift_value;
            inode_reverse_map.insert(inode, (object_number, 0)); //0 is not a valid file number in zff, so we can use this as a placeholder
            counter += 1;
        },
        ObjectFooter::Virtual(_) => todo!(), //TODO
    };
    
    Ok(counter)
}

pub fn prepare_zffreader_logical_file<R: Read + Seek>(
    zffreader: &mut ZffReader<R>, 
    object_no: u64,
    file_no: u64) -> Result<&FileMetadata> {
    zffreader.set_active_object(object_no)?;
    zffreader.set_active_file(file_no)?;
    zffreader.current_filemetadata()
}

pub fn filename_lookup_table_add_object<R: Read + Seek>(
    zffreader: &mut ZffReader<R>, 
    lookup_table: &mut BTreeMap<PlatformString, Vec<(u64, u64)>>, //<Filename, Vec<Parent-Inode, Self-Inode>>
    object_number: u64, 
    shift_value: u64) -> Result<u64> {
    zffreader.set_active_object(object_number)?;
    let mut counter = 0;


    let object_footer = match zffreader.active_object_footer()? {
        ObjectFooter::Logical(log) => log,
        ObjectFooter::Physical(phy) => return Err(ZffError::new(ZffErrorKind::Invalid, format!("{:?}", phy))),
        ObjectFooter::Virtual(_) => todo!(), //TODO
    };
    for filenumber in object_footer.file_footer_segment_numbers().keys() {
        zffreader.set_active_file(*filenumber)?;
        
        let filemetadata = zffreader.current_filemetadata()?.clone();
        let mut inode = get_inode(&filemetadata, shift_value);

        // checks if the file is a hardlink. In that case, the original file should be added
        if filemetadata.header.file_type == ZffFileType::Hardlink {
            let mut buffer = Vec::new();
            zffreader.rewind()?;
            zffreader.read_to_end(&mut buffer)?;
            let original_filenumber = u64::decode_directly(&mut buffer.as_slice())?;
            zffreader.set_active_file(original_filenumber)?;
            let filemetadata = zffreader.current_filemetadata()?.clone();
            inode = get_inode(&filemetadata, shift_value);
        }
        //reset the to the hardlink to get the filename of the hardlink.
        zffreader.set_active_file(*filenumber)?;

        let filename = filemetadata.header.filename;
        let parent_file_number = filemetadata.header.parent_file_number;
        let parent_inode = if parent_file_number>0 {
            zffreader.set_active_file(parent_file_number)?;
            get_inode(zffreader.current_filemetadata()?, shift_value)
        } else {
            object_number + 1 //if the file sits in root directory.
        };

        match lookup_table.get_mut(&filename) {
            Some(inner_vec) => inner_vec.push((parent_inode, inode)),
            None => { let inner_vec = vec![(parent_inode, inode)]; lookup_table.insert(filename, inner_vec); },
        };
        counter += 1;
    }

    Ok(counter)
}

pub fn gen_preload_chunkmap(args: &Cli) -> PreloadChunkmaps {
    let mut headers = args.preload_chunk_header_map;
    let mut samebytes = args.preload_chunk_samebytes_map;
    let mut deduplication = args.preload_chunk_deduplication_map;

    if args.preload_all_chunkmaps {
        headers = true;
        samebytes = true;
        deduplication = true;
    }

    let mut preload_chunkmaps = PreloadChunkmaps {
        headers,
        samebytes,
        deduplication,
        mode: PreloadChunkmapsMode::None,
    };
    match args.preload_mode {
        PreloadMode::None => (),
        PreloadMode::InMemory => preload_chunkmaps.mode = PreloadChunkmapsMode::InMemory,
        PreloadMode::Redb => {
            //unwrap should safe here, because it is a required argument defined by clap.
            let db = match redb::Database::create(args.redb_path.clone().unwrap()) {
                Ok(db) => db,
                Err(e) => {
                    error!("An error occurred while trying to create preload chunmap database.");
                    debug!("{e}");
                    exit(EXIT_STATUS_ERROR);
                }
            };
            preload_chunkmaps.mode = PreloadChunkmapsMode::Redb(db)
        }
    }
    preload_chunkmaps
}

pub fn get_inode(filemetadata: &FileMetadata, shift_value: u64) -> u64 {
    match &filemetadata.footer {
        FileFooterMetadata::FileFooter(footer) => footer.first_chunk_number + shift_value,
        //TODO: check if hardlink stuff looks correct.
        FileFooterMetadata::VirtualFileFooterMetadata(_) => filemetadata.header.file_number + shift_value, 
    }
}