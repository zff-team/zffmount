// - Parent
use super::*;

// - STD
use std::sync::Mutex;

// - internal
use zff::{PlatformString, VirtualFileContent};

// - platform specific
#[cfg(target_family = "unix")]
use unix::{
    FileAttr,
    file_attr_of_object_footer,
    file_attr_of_file,
    file_attr_of_physical_obj,
};


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

impl From<&ObjectFooter> for ZffFileAttr {
    fn from(value: &ObjectFooter) -> Self {
        file_attr_of_object_footer(value)
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
    pub inode_map: BTreeMap<(u64, u64), u64>, //(object number, file number), Inode
    pub filename_lookup_table: BTreeMap<PlatformString, Vec<(u64, u64)>>, //<Filename, Vec<Parent-Inode, Self-Inode>>
    pub inode_attributes_map: BTreeMap<u64, ZffFileAttr>,
}

impl ZffFsCache {
    fn new<R: Read + Seek + Send + Sync>(
        shift_value: u64,
        zffreader: &mut ZffReader<R>) -> Result<Self> 
    {
        // set object inodes
        let mut inode_reverse_map = BTreeMap::new();
        let mut filename_lookup_table: BTreeMap<PlatformString, Vec<(u64, u64)>> = BTreeMap::new();
        let mut inode_attributes_map = BTreeMap::new();
        let mut inode_map = BTreeMap::new();

        let mut current_inode = shift_value + 1;

        let object_list = zffreader.list_decrypted_objects();
        for object_number in object_list.keys() {
            zffreader.set_active_object(*object_number)?;
            let object_footer = zffreader.active_object_footer()?;
            inode_attributes_map.insert(object_number+1, file_attr_of_object_footer(&object_footer));

            zffreader.set_active_object(*object_number)?;
            match zffreader.active_object_footer()? {
                ObjectFooter::Logical(object_footer) => {
                    for filenumber in object_footer.file_footer_segment_numbers.keys() {
                        let filenumber = *filenumber;
                        zffreader.set_active_file(filenumber)?;
                        let filemetadata = zffreader.current_filemetadata()?.clone();
                        if filemetadata.header.file_type != ZffFileType::Hardlink {
                            inode_reverse_map.insert(current_inode, (*object_number, filenumber));
                            inode_map.insert((*object_number, filenumber), current_inode);
                            let file_attr = file_attr_of_file(filemetadata, zffreader, current_inode)?;
                            inode_attributes_map.insert(current_inode, file_attr);
                            current_inode += 1;
                        }
                    }

                    for filenumber in object_footer.file_footer_segment_numbers.keys() {
                        zffreader.set_active_file(*filenumber)?;
                        let filemetadata = zffreader.current_filemetadata()?.clone();
                        if filemetadata.header.file_type == ZffFileType::Hardlink {
                            let abs_filemetadata = absolute_filemetadata(&filemetadata, zffreader)?;
                            let abs_filenumber = abs_filemetadata.header.file_number;
                            let original_inode = inode_map.get(&(*object_number, abs_filenumber)).unwrap();
                            inode_map.insert((*object_number, *filenumber), *original_inode);
                        }
                    }

                    for filenumber in object_footer.file_footer_segment_numbers.keys() {
                        zffreader.set_active_file(*filenumber)?;
                        
                        let filemetadata = zffreader.current_filemetadata()?.clone();
                        let abs_filemetadata = absolute_filemetadata(&filemetadata, zffreader)?; //To handle hardlinks
                        let abs_filenumber = abs_filemetadata.header.file_number;
                        // unwrap should be safe here: we've already traversed the current object.
                        let inode = *inode_map.get(&(*object_number, abs_filenumber)).unwrap();

                        //reset the to the hardlink to get the filename of the hardlink.
                        zffreader.set_active_file(*filenumber)?;

                        let filename = filemetadata.header.filename;
                        let parent_file_number = filemetadata.header.parent_file_number;
                        let parent_inode = if parent_file_number>0 {
                            zffreader.set_active_file(parent_file_number)?;
                            *inode_map.get(&(*object_number, parent_file_number)).unwrap()
                        } else {
                            object_number + 1 //if the file sits in root directory.
                        };
                        

                        match filename_lookup_table.get_mut(&filename) {
                            Some(inner_vec) => inner_vec.push((parent_inode, inode)),
                            None => { let inner_vec = vec![(parent_inode, inode)]; filename_lookup_table.insert(filename, inner_vec); },
                        };
                    }


                },
                ObjectFooter::Physical(physical_obj_footer) => {
                    //0 is not a valid file number in zff, so we can use this as a placeholder
                    inode_reverse_map.insert(current_inode, (*object_number, 0));
                    inode_map.insert((*object_number, 0), current_inode);
                    let zff_file_attr = file_attr_of_physical_obj(&physical_obj_footer, current_inode);
                    inode_attributes_map.insert(current_inode, zff_file_attr); //0 is not a valid file number in zff, so we can use this as a placeholder
                    current_inode += 1;
                },
                ObjectFooter::Virtual(object_footer) => {
                    for filenumber in object_footer.file_footer_segment_numbers.keys() {
                        let filenumber = *filenumber;
                        zffreader.set_active_file(filenumber)?;
                        let filemetadata = zffreader.current_filemetadata()?.clone();
                        if filemetadata.header.file_type != ZffFileType::Hardlink {
                            inode_reverse_map.insert(current_inode, (*object_number, filenumber));
                            inode_map.insert((*object_number, filenumber), current_inode);
                            let file_attr = file_attr_of_file(filemetadata, zffreader, current_inode)?;
                            inode_attributes_map.insert(current_inode, file_attr);
                            current_inode += 1;
                        }
                    }

                    for filenumber in object_footer.file_footer_segment_numbers.keys() {
                        zffreader.set_active_file(*filenumber)?;
                        let filemetadata = zffreader.current_filemetadata()?.clone();
                        if filemetadata.header.file_type == ZffFileType::Hardlink {
                            let abs_filemetadata = absolute_filemetadata(&filemetadata, zffreader)?;
                            let abs_filenumber = abs_filemetadata.header.file_number;
                            let original_inode = inode_map.get(&(*object_number, abs_filenumber)).unwrap();
                            inode_map.insert((*object_number, *filenumber), *original_inode);
                        }
                    }

                    for filenumber in object_footer.file_footer_segment_numbers.keys() {
                        zffreader.set_active_file(*filenumber)?;
                        
                        let filemetadata = zffreader.current_filemetadata()?.clone();
                        let abs_filemetadata = absolute_filemetadata(&filemetadata, zffreader)?; //To handle hardlinks
                        let abs_filenumber = abs_filemetadata.header.file_number;
                        // unwrap should be safe here: we've already traversed the current object.
                        let inode = *inode_map.get(&(*object_number, abs_filenumber)).unwrap();

                        //reset the to the hardlink to get the filename of the hardlink.
                        zffreader.set_active_file(*filenumber)?;

                        let filename = filemetadata.header.filename;
                        let parent_file_number = filemetadata.header.parent_file_number;
                        let parent_inode = if parent_file_number>0 {
                            zffreader.set_active_file(parent_file_number)?;
                            *inode_map.get(&(*object_number, parent_file_number)).unwrap()
                        } else {
                            object_number + 1 //if the file sits in root directory.
                        };
                        

                        match filename_lookup_table.get_mut(&filename) {
                            Some(inner_vec) => inner_vec.push((parent_inode, inode)),
                            None => { let inner_vec = vec![(parent_inode, inode)]; filename_lookup_table.insert(filename, inner_vec); },
                        };
                    }
                }
            };
        }

        

        Ok(Self {
            object_list,
            inode_reverse_map,
            inode_map,
            filename_lookup_table,
            inode_attributes_map,
        })
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

        let object_list = match zffreader.list_objects() {
            Ok(list) => list,
            Err(e) => {
                error!("An error occurred while trying to get the ZffReader object list: {e}");
                exit(EXIT_STATUS_ERROR);
            }
        };
        let (phy, log, virt, enc) = object_list.values().fold((0, 0, 0, 0), |(phy, log, virt, enc), val| {
            match val {
                ZffReaderObjectType::Physical => (phy + 1, log, virt, enc),
                ZffReaderObjectType::Logical => (phy, log + 1, virt, enc),
                ZffReaderObjectType::Encrypted => (phy, log, virt, enc + 1),
                ZffReaderObjectType::Virtual => (phy, log, virt + 1, enc),
            }
        });
        info!("ZffReader created successfully. Found {phy} physical, {log} logical, {virt} virtual and {enc} encrypted objects.");

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

        let numbers_of_decrypted_objects: Vec<u64> = zffreader.list_decrypted_objects().iter().map(|(&k, _)| k).collect();
        let shift_value = match numbers_of_decrypted_objects.iter().max() {
            Some(value) => *value + 1, // + 1 for root dir inode
            None => 1,
        };   

        let cache = match ZffFsCache::new(shift_value, &mut zffreader) {
            Ok(cache) => cache,
            Err(e) => {
                error!("An error occurred while trying to initialize zff cache: {e}");
                exit(EXIT_STATUS_ERROR)
            }
        };

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

pub fn prepare_zffreader_file<R: Read + Seek>(
    zffreader: &mut ZffReader<R>, 
    object_no: u64,
    file_no: u64) -> Result<&FileMetadata> {
    zffreader.set_active_object(object_no)?;
    zffreader.set_active_file(file_no)?;
    zffreader.current_filemetadata()
}

// Returns the "original filemetadata": in case of a hardlink,
// the filemetadata corresponding to the underlying filenumber,
// in case of all other filetypes the appropriate filemetadata.
// Note: this will modify the zffreader Read position.
pub fn absolute_filemetadata<R: Read + Seek>(filemetadata: &FileMetadata, zffreader: &mut ZffReader<R>) -> Result<FileMetadata> {
    let filemetadata = match filemetadata.footer {
        FileFooterMetadata::FileFooter(_) => {
            if filemetadata.header.file_type == ZffFileType::Hardlink {
                let mut buffer = Vec::new();
                zffreader.rewind()?;
                zffreader.read_to_end(&mut buffer)?;
                let original_filenumber = u64::decode_directly(&mut buffer.as_slice())?;
                zffreader.set_active_file(original_filenumber)?;
                zffreader.current_filemetadata()?.clone()
            } else {
                filemetadata.clone()
            }
        },
        FileFooterMetadata::VirtualFileFooterMetadata(ref vffc) => {
            if let VirtualFileContent::Hardlink(original_filenumber) = vffc.vfc {
                zffreader.set_active_file(original_filenumber)?;
                zffreader.current_filemetadata()?.clone()
            } else {
                filemetadata.clone()
            }
        },
    };
    Ok(filemetadata)
}

pub fn gen_preload_chunkmap(args: &Cli) -> PreloadChunkmaps {
    let mut headers = args.preload_chunk_header_map;
    let mut samebytes = args.preload_chunk_samebytes_map;
    let mut deduplication = args.preload_chunk_deduplication_map;

    if args.preload_all_maps {
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