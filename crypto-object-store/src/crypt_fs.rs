use async_trait::async_trait;
use bytes::Bytes;
use cocoon;
use deltalake::storage::object_store;
use deltalake::{ObjectMeta, Path};
use deltalake_core::storage::object_store::{GetResultPayload, UploadPart, memory::InMemory};
use object_store::{
    Attributes, GetOptions, GetResult, ListResult, MultipartUpload, ObjectStore, PutMultipartOpts,
    PutOptions, PutPayload, PutResult, local::LocalFileSystem,
};
use std::fmt::{Debug, Display, Formatter};
use std::ops::{Bound, Range, RangeBounds};
use std::sync::{Arc, Mutex};
//use log::{info, trace, warn};
use cached::Cached;
use cached::stores::SizedCache;
use cocoon::{Cocoon, Creation};
use futures::StreamExt;
use log::warn;
use object_store_std::GetRange;
use object_store_std::multipart::{MultipartStore, PartId};
use show_bytes::show_bytes;
use url::Url;

pub trait GetCryptKey: Display + Send + Sync + Debug {
    fn get_key(&self, location: &Path) -> Option<Vec<u8>>;
}

// A simple key management stub to associate path locations
// with cryptography keys
#[derive(Debug, Clone)]
pub struct KMS {
    /// Encryption key
    crypt_key: Vec<u8>, // TODO: A fancy key lookup here
}

impl KMS {
    pub fn new(crypt_key: &[u8]) -> Self {
        KMS {
            crypt_key: Vec::from(crypt_key),
        }
    }
}

impl Display for KMS {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "crypt_key: {}", show_bytes(self.crypt_key.clone()))
    }
}

impl GetCryptKey for KMS {
    fn get_key(&self, location: &Path) -> Option<Vec<u8>> {
        // process the path location to get the associated encryption key
        // return None if there is no such associated key

        // As an example application, we leave the delta_log / metadata files unencrypted
        if location.prefix_matches(&Path::from("/_delta_log")) {
            return None;
        }

        Some(self.crypt_key.clone())
    }
}

// A KMS that disables encryption for basic tests
#[derive(Debug, Clone)]
pub struct KmsNone {}

impl KmsNone {
    pub fn new() -> Self {
        KmsNone {}
    }
}

impl Display for KmsNone {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "KmsNone")
    }
}

impl GetCryptKey for KmsNone {
    fn get_key(&self, _location: &Path) -> Option<Vec<u8>> {
        return None;
    }
}

// Cached GetResult values
#[derive(Debug, Clone)]
pub struct GetResultCache {
    /// The [`GetResultPayload`]
    pub bytes: Bytes,
    /// The [`ObjectMeta`] for this object
    pub meta: ObjectMeta,
    /// Additional object attributes
    pub attributes: Attributes,
}

pub fn object_store_from_uri(
    prefix_uri: impl AsRef<str>,
) -> object_store::Result<Arc<dyn ObjectStore>> {
    let url = Url::parse(prefix_uri.as_ref());
    if url.is_err() {
        let msg = format!("Invalid URI: \"{}\" ", prefix_uri.as_ref(),);
        return Err(object_store::Error::Generic {
            store: "CryptFileSystem",
            source: msg.into(),
        });
    }

    let url = url.unwrap();

    match url.scheme() {
        "file" => {
            let path = url.to_file_path().map_err(|_| {
                let msg = format!(
                    "URI Does not specify valid path \"{}\": ",
                    prefix_uri.as_ref(),
                );
                object_store::Error::Generic {
                    store: "CryptFileSystem",
                    source: msg.into(),
                }
            })?;
            Ok(Arc::new(LocalFileSystem::new_with_prefix(path)?))
        }
        "memory" => Ok(Arc::new(InMemory::new())),
        _ => {
            let msg = format!("Unrecognized URI scheme \"{}\".", url.scheme(),);
            Err(object_store::Error::Generic {
                store: "CryptFileSystem",
                source: msg.into(),
            })
        }
    }
}

// Have to reimplement this because GetRange does not expose GetRange::as_range()
pub fn get_range_to_range(
    gr: Option<&GetRange>,
    len: usize,
) -> object_store_std::Result<Range<usize>, object_store::Error> {
    if gr.is_none() {
        return Ok(0..len);
    }
    let gr = gr.unwrap();
    match gr {
        GetRange::Bounded(r) => {
            if r.start >= len {
                let msg = format!(
                    "Range start {} must not be greater than buffer length {}",
                    r.start, len,
                );
                Err(object_store::Error::Generic {
                    store: "CryptFileSystem",
                    source: msg.into(),
                })
            } else if r.end > len {
                Ok(r.start..len)
            } else {
                Ok(r.clone())
            }
        }
        GetRange::Offset(o) => {
            if *o >= len {
                let msg = format!(
                    "Range start {} must not be greater than buffer length {}",
                    *o, len,
                );
                Err(object_store::Error::Generic {
                    store: "CryptFileSystem",
                    source: msg.into(),
                })
            } else {
                Ok(*o..len)
            }
        }
        GetRange::Suffix(n) => Ok(len.saturating_sub(*n)..len),
    }
}

pub fn check_bytes_slice(
    len: usize,
    range: impl RangeBounds<usize>,
) -> Result<(), object_store::Error> {
    use core::ops::Bound;

    let begin = match range.start_bound() {
        Bound::Included(&n) => n,
        Bound::Excluded(&n) => n.checked_add(1).expect("out of range"),
        Bound::Unbounded => 0,
    };

    let end = match range.end_bound() {
        Bound::Included(&n) => n.checked_add(1).expect("out of range"),
        Bound::Excluded(&n) => n,
        Bound::Unbounded => len,
    };

    if begin > end {
        let msg = format!(
            "Range start must not be greater than end: [{}..{}] ",
            begin, end,
        );
        return Err(object_store::Error::Generic {
            store: "CryptFileSystem",
            source: msg.into(),
        });
    }

    if end > len {
        let msg = format!("Range end out of bounds: [{}..{}] ", begin, end,);
        return Err(object_store::Error::Generic {
            store: "CryptFileSystem",
            source: msg.into(),
        });
    }

    Ok(())
}

#[derive(Debug, Clone)]
pub struct CryptFileSystem {
    /// The underlying object store
    os: Arc<dyn ObjectStore>,

    /// Class to associate path locations with encryption keys
    kms: Arc<dyn GetCryptKey>,

    /// Cache for decrypted GetResult values
    decrypted_cache: Arc<Mutex<SizedCache<Path, GetResultCache>>>,
}

impl Display for CryptFileSystem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "os: {}, kms: {}", self.os, self.kms)
    }
}

impl CryptFileSystem {
    pub fn new(
        prefix_uri: impl AsRef<str>,
        kms: Arc<dyn GetCryptKey>,
    ) -> object_store::Result<Self> {
        let os = object_store_from_uri(prefix_uri)?;
        Ok(Self {
            os,
            kms: kms.clone(),
            decrypted_cache: Arc::new(Mutex::new(SizedCache::with_size(8))),
        })
    }

    // Add decrypted data to cache
    fn set_cache(&self, location: &Path, gr: GetResultCache) {
        let mut dc = self.decrypted_cache.lock().unwrap();
        dc.cache_set(location.clone(), gr);
    }

    // Check cache for decrypted data
    fn get_cache(&self, location: &Path) -> Option<GetResultCache> {
        let mut dc = self.decrypted_cache.lock().unwrap();
        dc.cache_get(location).map(GetResultCache::clone)
    }

    fn get_cached_getresult(
        &self,
        location: &Path,
        options: Option<&GetOptions>,
    ) -> Result<Option<GetResult>, object_store::Error> {
        let cache = self.get_cache(location);
        if cache.is_none() {
            return Ok(None);
        }
        let cache: GetResultCache = cache.unwrap();

        let target_range = match options {
            Some(opts) => opts.range.as_ref(),
            None => None,
        };
        let range = get_range_to_range(target_range, cache.bytes.len())?;
        let bytes = cache.bytes.slice(range.clone());
        let stream = futures::stream::once(futures::future::ready(Ok(bytes)));
        Ok(Some(GetResult {
            payload: GetResultPayload::Stream(stream.boxed()),
            meta: cache.meta,
            range,
            attributes: cache.attributes,
        }))
    }

    fn clear_cache(&self) {
        let mut dc = self.decrypted_cache.lock().unwrap();
        dc.cache_clear();
    }


    fn get_cocoon(key: &Vec<u8>) -> Cocoon<Creation> {
        cocoon::Cocoon::new(key.as_slice()).with_cipher(cocoon::CocoonCipher::Aes256Gcm)
            .with_weak_kdf()  // Assuming the KMS returns a strong key, we can use fewer KDF iterations
    }
    
    pub fn encrypt(
        &self,
        location: &Path,
        data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key = self.kms.get_key(location);
        if key.is_none() {
            // No encryption
            return Ok(Vec::from(data));
        }
        let key = key.unwrap();
        let mut cocoon = Self::get_cocoon(&key);
        let encrypted = cocoon.wrap(data)?;
        Ok(encrypted)
    }

    pub fn decrypt(
        &self,
        location: &Path,
        data: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key = self.kms.get_key(location);
        if key.is_none() {
            // No encryption
            return Ok(Vec::from(data));
        }
        let key = key.unwrap();
        let cocoon = Self::get_cocoon(&key);
        let decrypted = cocoon.unwrap(data)?;
        Ok(decrypted)
    }

    async fn decrypted_bytes(
        &self,
        location: &Path,
        gr: GetResult,
    ) -> Result<Bytes, object_store::Error> {
        // Buffer the payload in memory
        let gr_range = gr.range.clone();
        let meta = gr.meta.clone();
        let attributes = gr.attributes.clone();
        let bytes = gr.bytes().await?;

        // Decrypt
        let decrypted = self.decrypt(location, &*bytes);
        if decrypted.is_err() {
            let msg = format!("Cocoon Decryption Error: {} ", decrypted.unwrap_err(),);
            return Err(object_store::Error::Generic {
                store: "CryptFileSystem",
                source: msg.into(),
            });
        };
        let decrypted = decrypted.unwrap();
        if gr_range.start_bound() == Bound::Unbounded && gr_range.end_bound() == Bound::Unbounded {
            // Only cache full get
            self.set_cache(
                location,
                GetResultCache {
                    bytes: Bytes::from(decrypted.clone()),
                    meta,
                    attributes,
                },
            );
        }

        // Convert to bytes
        let db = Bytes::from(decrypted);
        Ok(db)
    }

    async fn encrypted_payloads(
        &self,
        location: &Path,
        payloads: &Vec<PutPayload>,
    ) -> object_store::Result<PutPayload> {
        // Buffer the payload in memory
        // Eventually, we can maybe do this block-wise by using payload.to_iter()
        let ms = InMemory::new();
        let tmp = Path::from("tmp");
        let mid = ms.create_multipart(&tmp).await?;
        let mut parts: Vec<PartId> = Vec::new();
        for (idx, payload) in payloads.iter().enumerate() {
            let part_id: PartId = ms.put_part(&tmp, &mid, idx, payload.clone()).await?;
            parts.push(part_id);
        }
        ms.complete_multipart(&tmp, &mid, parts).await?;

        let result: GetResult = ms.get(&tmp).await?;
        let bytes = result.bytes().await?;

        // Only cache on get because write to underlying system may fail.
        // self.set_cache(location, bytes.to_vec());

        // Encrypt
        let encrypted = self.encrypt(location, &*bytes);
        if encrypted.is_err() {
            let msg = format!("Cocoon Encryption Error: {} ", encrypted.unwrap_err(),);
            return Err(object_store::Error::Generic {
                store: "CryptFileSystem",
                source: msg.into(),
            });
        };
        let encrypted = encrypted.unwrap();
        let encrypted_payload = PutPayload::from(encrypted);
        Ok(encrypted_payload)
    }

    async fn encrypted_payload(
        &self,
        location: &Path,
        payload: PutPayload,
    ) -> object_store::Result<PutPayload> {
        let payloads = vec![payload];
        self.encrypted_payloads(location, &payloads).await
    }

    async fn decrypted_get_result(
        &self,
        location: &Path,
        gr: GetResult,
    ) -> object_store::Result<GetResult> {
        let meta = gr.meta.clone();
        let range = gr.range.clone();
        let attributes = gr.attributes.clone();

        let db = self.decrypted_bytes(location, gr).await?;
        let stream = futures::stream::once(futures::future::ready(Ok(db)));
        Ok(GetResult {
            payload: GetResultPayload::Stream(stream.boxed()),
            meta,
            range,
            attributes,
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

impl CryptUpload {
    pub fn new(dest: Path, cfs: &CryptFileSystem) -> Self {
        Self {
            dest,
            cfs: cfs.clone(),
            parts: vec![],
            attributes: Attributes::new(),
        }
    }

    pub fn new_with_attributes(dest: Path, cfs: &CryptFileSystem, attributes: Attributes) -> Self {
        Self {
            dest,
            cfs: cfs.clone(),
            parts: vec![],
            attributes,
        }
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
            return self.cfs.os.put(&self.dest, encrypted_payload).await;
        }

        let opts: PutOptions = self.attributes.clone().into();
        self.cfs
            .os
            .put_opts(&self.dest, encrypted_payload, opts)
            .await
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

    async fn put_opts(
        &self,
        location: &Path,
        payload: PutPayload,
        opts: PutOptions,
    ) -> object_store::Result<PutResult> {
        warn!("put_opts: {location}");
        let encrypted_payload = self.encrypted_payload(location, payload).await?;
        self.os.put_opts(location, encrypted_payload, opts).await
    }

    async fn put_multipart(
        &self,
        location: &Path,
    ) -> object_store::Result<Box<dyn MultipartUpload>> {
        warn!("put_multipart: {location}");
        Ok(Box::new(CryptUpload::new(location.clone(), &self)))
    }

    async fn put_multipart_opts(
        &self,
        location: &Path,
        opts: PutMultipartOpts,
    ) -> object_store::Result<Box<dyn MultipartUpload>> {
        warn!("put_multipart_opts: {location}");
        Ok(Box::new(CryptUpload::new_with_attributes(
            location.clone(),
            &self,
            opts.attributes.clone(),
        )))
    }

    async fn get(&self, location: &Path) -> object_store::Result<GetResult> {
        warn!("get: {location}");
        let cache = self.get_cached_getresult(location, None)?;
        if cache.is_some() {
            return Ok(cache.unwrap());
        }
        let gr = self.os.get(location).await?;
        self.decrypted_get_result(location, gr).await
    }

    async fn get_opts(
        &self,
        location: &Path,
        options: GetOptions,
    ) -> object_store::Result<GetResult> {
        warn!("get_opts: {location}");
        let cache = self.get_cached_getresult(location, Some(&options))?;
        if cache.is_some() {
            return Ok(cache.unwrap());
        }
        let gr = self.os.get_opts(location, options).await?;
        self.decrypted_get_result(location, gr).await
    }

    async fn get_range(&self, location: &Path, range: Range<usize>) -> object_store::Result<Bytes> {
        warn!("get_range: {location}");
        let cache = self.get_cache(location);
        let db = match cache {
            Some(cache) => cache.bytes,
            None => {
                let gr = self.os.get(location).await?;
                self.decrypted_bytes(location, gr).await?
            }
        };
        check_bytes_slice(db.len(), range.clone())?;
        Ok(db.slice(range))
    }

    async fn get_ranges(
        &self,
        location: &Path,
        ranges: &[Range<usize>],
    ) -> object_store::Result<Vec<Bytes>> {
        warn!("get_ranges: {location}");
        let cache = self.get_cache(location);
        let db = match cache {
            Some(cache) => cache.bytes,
            None => {
                let gr = self.os.get(location).await?;
                self.decrypted_bytes(location, gr).await?
            }
        };
        let ranges = ranges.to_vec();
        ranges
            .into_iter()
            .map(|range| {
                check_bytes_slice(db.len(), range.clone())?;
                Ok(db.slice(range))
            })
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
        self.clear_cache();
        self.os.delete(location).await
    }

    fn delete_stream<'a>(
        &'a self,
        locations: futures_core::stream::BoxStream<'a, object_store::Result<Path>>,
    ) -> futures_core::stream::BoxStream<'a, object_store::Result<Path>> {
        self.clear_cache();
        self.os.delete_stream(locations)
    }

    fn list(
        &self,
        prefix: Option<&Path>,
    ) -> futures_core::stream::BoxStream<'_, object_store::Result<ObjectMeta>> {
        self.os.list(prefix)
    }

    fn list_with_offset(
        &self,
        prefix: Option<&Path>,
        offset: &Path,
    ) -> futures_core::stream::BoxStream<'_, object_store::Result<ObjectMeta>> {
        self.os.list_with_offset(prefix, offset)
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> object_store::Result<ListResult> {
        self.os.list_with_delimiter(prefix).await
    }

    async fn copy(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.clear_cache();
        self.os.copy(from, to).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.clear_cache();
        self.os.rename(from, to).await
    }

    async fn copy_if_not_exists(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.os.copy_if_not_exists(from, to).await
    }

    async fn rename_if_not_exists(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.clear_cache();
        self.os.rename_if_not_exists(from, to).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store_std::integration::*;
    use rand::{Rng, rng};

    /// Returns a chunk of length `chunk_length`
    fn get_chunk(chunk_length: usize) -> Bytes {
        let mut data = vec![0_u8; chunk_length];
        let mut rng = rng();
        // Set a random selection of bytes
        for _ in 0..1000 {
            data[rng.random_range(0..chunk_length)] = rng.random();
        }
        data.into()
    }

    /// Returns `num_chunks` of length `chunks`
    fn get_chunks(chunk_length: usize, num_chunks: usize) -> Vec<Bytes> {
        (0..num_chunks).map(|_| get_chunk(chunk_length)).collect()
    }

    #[tokio::test]
    async fn integration_test_no_encryption() {
        let kms = Arc::new(KmsNone::new());
        let integration: Box<dyn ObjectStore> =
            Box::new(CryptFileSystem::new("memory://", kms).unwrap());

        put_get_delete_list(&integration).await;
        get_opts(&integration).await;
        list_uses_directories_correctly(&integration).await;
        list_with_delimiter(&integration).await;
        rename_and_copy(&integration).await;
        copy_if_not_exists(&integration).await;
        stream_get(&integration).await;
        put_opts(&integration, true).await;
        put_get_attributes(&integration).await;
    }

    #[tokio::test]
    async fn put_get_test() {
        let kms = Arc::new(KMS::new(b"password"));
        let storage: Box<dyn ObjectStore> =
            Box::new(CryptFileSystem::new("memory://", kms).unwrap());

        let location = Path::from("test_dir/test_file.json");

        let data = Bytes::from("arbitrary data");
        storage.put(&location, data.clone().into()).await.unwrap();

        let read_data = storage.get(&location).await.unwrap().bytes().await.unwrap();
        assert_eq!(&*read_data, data);

        // Test range request
        let range = 3..7;
        let range_result = storage.get_range(&location, range.clone()).await;

        let bytes = range_result.unwrap();
        assert_eq!(bytes, data.slice(range.clone()));
    }

    #[tokio::test]
    async fn put_multipart_test() {
        let kms = Arc::new(KMS::new(b"password"));
        let storage: Box<dyn ObjectStore> =
            Box::new(CryptFileSystem::new("memory://", kms).unwrap());

        let location = Path::from("test_dir/test_upload_file.txt");

        // Can write to storage
        let data = get_chunks(5 * 1024 * 1024, 3);
        let bytes_expected = data.concat();
        let mut upload = storage.put_multipart(&location).await.unwrap();
        let uploads = data.into_iter().map(|x| upload.put_part(x.into()));
        futures::future::try_join_all(uploads).await.unwrap();

        upload.complete().await.unwrap();

        let bytes_written = storage.get(&location).await.unwrap().bytes().await.unwrap();
        assert_eq!(bytes_expected, bytes_written);
    }
}
