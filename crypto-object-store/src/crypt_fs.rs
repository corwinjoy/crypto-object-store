use std::fmt::{Display, Formatter};
use std::ops::Range;
use std::sync::{Arc, Mutex};
use async_trait::async_trait;
use bytes::Bytes;
use deltalake::storage::object_store;
use object_store::{ObjectStore, local::LocalFileSystem, PutPayload, PutResult,
                                       PutOptions, MultipartUpload, PutMultipartOpts, GetResult,
                                       GetOptions, ListResult, Attributes};
use deltalake::{ObjectMeta, Path};
use cocoon;
use deltalake_core::storage::object_store::{GetResultPayload, UploadPart, memory::InMemory};
//use log::{info, trace, warn};
use log::{warn};
use show_bytes::show_bytes;
use futures::{StreamExt};
use cached::Cached;
use cached::stores::SizedCache;
use url::Url;

// A simple key management stub to associate path locations
// with cryptography keys
#[derive(Debug, Clone)]
pub struct KMS {
    /// Encryption key
    crypt_key: Vec<u8>, // TODO: A fancy key lookup here
}

impl Display for KMS {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "crypt_key: {}", show_bytes(self.crypt_key.clone()))
    }
}

impl KMS {
    pub fn new(crypt_key: &[u8]) -> Self {
        KMS { crypt_key: Vec::from(crypt_key) }
    }
    
    pub fn get_key(&self, location: &Path) -> Option<Vec<u8>> {
        // process the path location to get the associated encryption key
        // return None if there is no such associated key
        
        // As an example application, we leave the delta_log / metadata files unencrypted
        if location.prefix_matches(&Path::from("/_delta_log")) {
            return None;
        }
        
        Some(self.crypt_key.clone())
    }
}


#[derive(Debug, Clone)]
pub struct CryptFileSystem {
    /// The underlying object store
    os: Arc<dyn ObjectStore>,
    
    /// Class to associate path locations with encryption keys
    kms: KMS, 
    
    /// Cache for decrypted files
    decrypted_cache: Arc<Mutex<SizedCache<Path, Vec<u8>>>>
}

impl Display for CryptFileSystem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "os: {}, kms: {}", self.os, self.kms)
    }
}

impl CryptFileSystem {
    pub fn new(prefix_uri: impl AsRef<str>, kms: KMS) -> object_store::Result<Self> {
        let os = CryptFileSystem::object_store_from_uri(prefix_uri)?;
        Ok(Self { os , kms, 
            decrypted_cache: Arc::new(Mutex::new(SizedCache::with_size(8)))})
    }

    pub fn object_store_from_uri(prefix_uri: impl AsRef<str>) -> object_store::Result<Arc<dyn ObjectStore>>{
        let url = Url::parse(prefix_uri.as_ref());
        if url.is_err() {
            let msg = format!(
                "Invalid URI: \"{}\" ",
                prefix_uri.as_ref(),
            );
            return Err(object_store::Error::Generic {store: "CryptFileSystem", source: msg.into()});
        }

        let url = url.unwrap();

        match url.scheme(){
            "file" => {
                let path = url.to_file_path().map_err(|_| {
                    let msg = format!(
                        "URI Does not specify valid path \"{}\": ",
                        prefix_uri.as_ref(),
                    );
                    object_store::Error::Generic {store: "CryptFileSystem", source: msg.into()}
                })?;
                Ok(Arc::new(LocalFileSystem::new_with_prefix(path)?))
            },
            "memory" => {
                Ok(Arc::new(InMemory::new()))
            },
            _ => {
                let msg = format!(
                    "Unrecognized URI scheme \"{}\".",
                    url.scheme(),
                );
                Err(object_store::Error::Generic { store: "CryptFileSystem", source: msg.into() })
            }
        }

    }
    
    // Add decrypted data to cache
    fn set_cache(&self, location: &Path, data: Vec<u8>) {
        let mut dc = self.decrypted_cache.lock().unwrap();
        dc.cache_set(location.clone(), data);
    }
    
    // Check cache for decrypted data
    fn get_cache(&self, location: &Path) -> Option<Vec<u8>> {
        let mut dc = self.decrypted_cache.lock().unwrap();
        dc.cache_get(location).map(Vec::clone)
    }

    pub fn encrypt(&self, location: &Path, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key = self.kms.get_key(location);
        if key.is_none() {
            // No encryption
            return Ok(Vec::from(data));
        }
        let key = key.unwrap();
        let mut cocoon = cocoon::Cocoon::new(key.as_slice());
        let encrypted = cocoon.wrap(data)?;
        Ok(encrypted)
    }

    pub fn decrypt(&self, location: &Path, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key = self.kms.get_key(location);
        if key.is_none() {
            // No encryption
            return Ok(Vec::from(data));
        }
        let key = key.unwrap();
        let cocoon = cocoon::Cocoon::new(key.as_slice());
        let decrypted = cocoon.unwrap(data)?;
        Ok(decrypted)
    }

    async fn decrypted_bytes(&self, location: &Path, gr: GetResult) -> Result<Bytes, object_store::Error> {
        // Check cache
        let cache = self.get_cache(location);
        if cache.is_some() {
            return Ok(Bytes::from(cache.unwrap().clone()));
        }

        // Buffer the payload in memory
        let bytes = gr.bytes().await?;

        // Decrypt
        let decrypted = self.decrypt(location, &*bytes).unwrap();
        self.set_cache(location, decrypted.clone());
        
        // Convert to bytes
        let db = Bytes::from(decrypted);
        Ok(db)
    }

    async fn encrypted_payloads(&self, location: &Path, payloads: &Vec<PutPayload>) -> object_store::Result<PutPayload> {
        // Buffer the payload in memory
        // Eventually, we can maybe do this block-wise by using payload.to_iter()
        let ms = InMemory::new();
        let tmp = Path::from("tmp");
        for payload in payloads {
            ms.put(&tmp, payload.clone()).await?;
        }

        let result: GetResult = ms.get(&tmp).await?;
        let bytes = result.bytes().await?;
        
        // Cache unencrypted file
        self.set_cache(location, bytes.to_vec());

        // Encrypt
        let encrypted = self.encrypt(location, &*bytes).unwrap();
        let encrypted_payload = PutPayload::from(encrypted);
        Ok(encrypted_payload)
    }

    async fn encrypted_payload(&self, location: &Path, payload: PutPayload) -> object_store::Result<PutPayload> {
        let payloads = vec![payload];
        self.encrypted_payloads(location, &payloads).await
    }

    async fn decrypted_get_result(&self, location: &Path, gr: GetResult) -> object_store::Result<GetResult> {
        let meta = gr.meta.clone();
        let range = gr.range.clone();
        let attributes = gr.attributes.clone();

        let db = self.decrypted_bytes(location, gr).await?;
        let stream = futures::stream::once(futures::future::ready(Ok(db)));
        Ok(GetResult{
            payload: GetResultPayload::Stream(stream.boxed()),
            meta, range, attributes,
        })
    }
    
}

#[derive(Debug)]
pub struct CryptUpload {
    /// The final destination
    dest: Path,

    /// Associated encrypted store
    cfs: CryptFileSystem,

    /// Vector of payloads to write
    parts: Vec<PutPayload>,

    /// Write attributes
    attributes: Attributes,
}

impl CryptUpload{
    pub fn new(dest: Path, cfs: &CryptFileSystem) -> Self {
        Self { dest, cfs: cfs.clone(), parts: vec![], attributes: Attributes::new() }
    }

    pub fn new_with_attributes(dest: Path, cfs: &CryptFileSystem, attributes: Attributes) -> Self {
        Self { dest, cfs: cfs.clone(), parts: vec![], attributes }
    }
}

#[async_trait]
impl MultipartUpload for CryptUpload {
    fn put_part(&mut self, data: PutPayload) -> UploadPart {
        self.parts.push(data);
        Box::pin(futures::future::ready(Ok(())))
    }

    async fn complete(&mut self) -> object_store::Result<PutResult> {
        let encrypted_payload = self.cfs.encrypted_payloads(&self.dest, &self.parts).await?;

        if self.attributes.is_empty() {
            return self.cfs.os.put(&self.dest, encrypted_payload).await
        }

        let opts : PutOptions = self.attributes.clone().into();
        self.cfs.os.put_opts(&self.dest, encrypted_payload, opts).await
    }

    async fn abort(&mut self) -> object_store::Result<()> {
        Ok(())
    }
}


#[async_trait]
impl ObjectStore for CryptFileSystem {
    async fn put(&self, location: &Path, payload: PutPayload) -> object_store::Result<PutResult> {
        warn!("put: {location}");
        let encrypted_payload = self.encrypted_payload(location, payload).await?;
        self.os.put(location, encrypted_payload).await
    }
    
    async fn put_opts(&self, location: &Path, payload: PutPayload, opts: PutOptions) -> object_store::Result<PutResult> {
        warn!("put_opts: {location}");
        let encrypted_payload = self.encrypted_payload(location, payload).await?;
        self.os.put_opts(location, encrypted_payload, opts).await
    }

    async fn put_multipart(&self, location: &Path) -> object_store::Result<Box<dyn MultipartUpload>>{
        warn!("put_multipart: {location}");
        Ok(Box::new(CryptUpload::new(location.clone(), &self)))
    }

    async fn put_multipart_opts(&self, location: &Path, opts: PutMultipartOpts) -> object_store::Result<Box<dyn MultipartUpload>> {
        warn!("put_multipart_opts: {location}");
        Ok(Box::new(CryptUpload::new_with_attributes(location.clone(), &self, opts.attributes.clone())))
    }

    async fn get(&self, location: &Path) -> object_store::Result<GetResult> {
        warn!("get: {location}");
        let gr = self.os.get(location).await?;
        self.decrypted_get_result(location, gr).await
    }

    async fn get_opts(&self, location: &Path, options: GetOptions) -> object_store::Result<GetResult> {
        warn!("get_opts: {location}");
        let gr = self.os.get_opts(location, options).await?;
        self.decrypted_get_result(location, gr).await
    }

    async fn get_range(&self, location: &Path, range: Range<usize>) -> object_store::Result<Bytes> {
        warn!("get_range: {location}");
        let gr = self.os.get(location).await?;
        let db = self.decrypted_bytes(location, gr).await?;
        Ok(db.slice(range))
    }

    async fn get_ranges(&self, location: &Path, ranges: &[Range<usize>]) -> object_store::Result<Vec<Bytes>> {
        warn!("get_ranges: {location}");
        let gr = self.os.get(location).await?;
        let db = self.decrypted_bytes(location, gr).await?;
        let ranges = ranges.to_vec();
        ranges
            .into_iter()
            .map(|range| Ok(db.slice(range)))
            .collect()
    }

    ////////////////////////////////////////////////////////////////////////////////////
    // The rest of these functions operate at the file system level and should all
    // be just pass-through
    ////////////////////////////////////////////////////////////////////////////////////
    async fn head(&self, location: &Path) -> object_store::Result<ObjectMeta> {
        self.os.head(location).await
    }

    async fn delete(&self, location: &Path) -> object_store::Result<()> {
        self.os.delete(location).await
    }

    fn delete_stream<'a>(&'a self, locations: futures_core::stream::BoxStream<'a, object_store::Result<Path>>) 
      -> futures_core::stream::BoxStream<'a, object_store::Result<Path>> {
        self.os.delete_stream(locations)
    }

    fn list(&self, prefix: Option<&Path>) -> futures_core::stream::BoxStream<'_, object_store::Result<ObjectMeta>> {
        self.os.list(prefix)
    }

    fn list_with_offset(&self, prefix: Option<&Path>, offset: &Path) 
      -> futures_core::stream::BoxStream<'_, object_store::Result<ObjectMeta>> {
        self.os.list_with_offset(prefix, offset)
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> object_store::Result<ListResult> {
        self.os.list_with_delimiter(prefix).await
    }

    async fn copy(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.os.copy(from, to).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.os.rename(from, to).await
    }

    async fn copy_if_not_exists(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.os.copy_if_not_exists(from, to).await
    }

    async fn rename_if_not_exists(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.os.rename_if_not_exists(from, to).await
    }
}