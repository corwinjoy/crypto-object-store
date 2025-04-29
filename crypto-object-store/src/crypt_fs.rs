use std::fmt::{Display, Formatter};
use std::ops::Range;
use async_trait::async_trait;
use bytes::Bytes;
use deltalake::storage::object_store;
use object_store::{ObjectStore, local::LocalFileSystem, PutPayload, PutResult,
                                       PutOptions, MultipartUpload, PutMultipartOpts, GetResult,
                                       GetOptions, ListResult};
use deltalake::{ObjectMeta, Path};
use cocoon;
use deltalake_core::storage::object_store::GetResultPayload;
use deltalake_core::storage::object_store::memory::InMemory;
//use log::{info, trace, warn};
use log::{warn};
use show_bytes::show_bytes;
use futures::{StreamExt};

// let mut cocoon = Cocoon::new(b"password");
#[derive(Debug)]
pub struct CryptFileSystem {
    fs: LocalFileSystem,
    crypt_key: Vec<u8>,
}

impl Display for CryptFileSystem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "fs: {}, crypt_key: {}", self.fs, show_bytes(self.crypt_key.clone()))
    }
}

impl CryptFileSystem {

    /*
    pub fn new() -> Self {
        Self { fs: LocalFileSystem::new() }
    }
     */

    pub fn new_with_prefix(prefix: impl AsRef<std::path::Path>, crypt_key: Vec<u8>) -> object_store::Result<Self> {
        Ok(Self { fs: LocalFileSystem::new_with_prefix(prefix)? , crypt_key})
    }

    pub fn encrypt(&self, _location: &Path, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut cocoon = cocoon::Cocoon::new(self.crypt_key.as_slice());
        let encrypted = cocoon.wrap(data);
        if encrypted.is_err() {
            return Err(format!("cocoon encryption error {:?}", encrypted).into())
        };
        Ok(encrypted.unwrap())
    }

    pub fn decrypt(&self, _location: &Path, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let cocoon = cocoon::Cocoon::new(self.crypt_key.as_slice());
        let decrypted = cocoon.unwrap(data);
        if decrypted.is_err() {
            return Err(format!("cocoon decryption error {:?}", decrypted).into())
        };
        Ok(decrypted.unwrap())
    }

    async fn encrypted_payload(&self, location: &Path, payload: PutPayload) -> object_store::Result<PutPayload> {
        // Eventually, we can hopefully do this block-wise by using payload.to_iter()

        // Buffer the payload in memory
        let ms = InMemory::new();
        let tmp = Path::from("tmp");
        ms.put(&tmp, payload).await?;
        let result: GetResult = ms.get(&tmp).await?;
        let bytes = result.bytes().await?;

        // Encrypt
        let encrypted = self.encrypt(location, &*bytes).unwrap();
        let encrypted_payload = PutPayload::from(encrypted);
        Ok(encrypted_payload)
    }

    async fn decrypted_get_result(&self, location: &Path, gr: GetResult) -> object_store::Result<GetResult> {
        // Eventually, we can hopefully do this block-wise by using payload.to_iter()

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

    async fn decrypted_bytes(&self, location: &Path, gr: GetResult) -> Result<Bytes, object_store::Error> {
        // Buffer the payload in memory
        let bytes = gr.bytes().await?;

        // Decrypt
        let decrypted = self.decrypt(location, &*bytes).unwrap();
        let db = Bytes::from(decrypted);
        Ok(db)
    }
}


#[async_trait]
impl ObjectStore for CryptFileSystem {
    async fn put(&self, location: &Path, payload: PutPayload) -> object_store::Result<PutResult> {
        warn!("put");
        let encrypted_payload = self.encrypted_payload(location, payload).await?;
        self.fs.put(location, encrypted_payload).await
    }
    
    async fn put_opts(&self, location: &Path, payload: PutPayload, opts: PutOptions) -> object_store::Result<PutResult> {
        warn!("put_opts");
        let encrypted_payload = self.encrypted_payload(location, payload).await?;
        self.fs.put_opts(location, encrypted_payload, opts).await
    }

    async fn put_multipart(&self, location: &Path) -> object_store::Result<Box<dyn MultipartUpload>> {
        warn!("put_multipart");
        self.fs.put_multipart(location).await
    }

    async fn put_multipart_opts(&self, location: &Path, opts: PutMultipartOpts) -> object_store::Result<Box<dyn MultipartUpload>> {
        warn!("put_multipart_opts");
        self.fs.put_multipart_opts(location, opts).await
    }

    async fn get(&self, location: &Path) -> object_store::Result<GetResult> {
        warn!("get");
        let gr = self.fs.get(location).await?;
        self.decrypted_get_result(location, gr).await
    }

    async fn get_opts(&self, location: &Path, options: GetOptions) -> object_store::Result<GetResult> {
        warn!("get_opts");
        let gr = self.fs.get_opts(location, options).await?;
        self.decrypted_get_result(location, gr).await
    }

    async fn get_range(&self, location: &Path, range: Range<usize>) -> object_store::Result<Bytes> {
        warn!("get_range");
        let gr = self.get(location).await?;
        let db = self.decrypted_bytes(location, gr).await?;
        Ok(db.slice(range))
    }

    async fn get_ranges(&self, location: &Path, ranges: &[Range<usize>]) -> object_store::Result<Vec<Bytes>> {
        warn!("get_ranges");
        let gr = self.get(location).await?;
        let db = self.decrypted_bytes(location, gr).await?;
        let ranges = ranges.to_vec();
        ranges
            .into_iter()
            .map(|range| Ok(db.slice(range)))
            .collect()
    }

    /*
     async fn get_ranges(&self, location: &Path, ranges: &[Range<usize>]) -> Result<Vec<Bytes>> {
        let path = self.path_to_filesystem(location)?;
        let ranges = ranges.to_vec();
        maybe_spawn_blocking(move || {
            // Vectored IO might be faster
            let (mut file, _) = open_file(&path)?;
            ranges
                .into_iter()
                .map(|r| read_range(&mut file, &path, r))
                .collect()
        })
        .await
    }

     async fn get_ranges(&self, location: &Path, ranges: &[Range<usize>]) -> Result<Vec<Bytes>> {
        let entry = self.entry(location).await?;
        ranges
            .iter()
            .map(|range| {
                let r = GetRange::Bounded(range.clone())
                    .as_range(entry.data.len())
                    .context(RangeSnafu)?;

                Ok(entry.data.slice(r))
            })
            .collect()
    }
     */

    ////////////////////////////////////////////////////////////////////////////////////
    // The rest of these functions operate at the file system level and should all
    // be just pass throughs
    ////////////////////////////////////////////////////////////////////////////////////
    async fn head(&self, location: &Path) -> object_store::Result<ObjectMeta> {
        self.fs.head(location).await
    }

    async fn delete(&self, location: &Path) -> object_store::Result<()> {
        self.fs.delete(location).await
    }

    fn delete_stream<'a>(&'a self, locations: futures_core::stream::BoxStream<'a, object_store::Result<Path>>) 
      -> futures_core::stream::BoxStream<'a, object_store::Result<Path>> {
        self.fs.delete_stream(locations)
    }

    fn list(&self, prefix: Option<&Path>) -> futures_core::stream::BoxStream<'_, object_store::Result<ObjectMeta>> {
        self.fs.list(prefix)
    }

    fn list_with_offset(&self, prefix: Option<&Path>, offset: &Path) 
      -> futures_core::stream::BoxStream<'_, object_store::Result<ObjectMeta>> {
        self.fs.list_with_offset(prefix, offset)
    }

    async fn list_with_delimiter(&self, prefix: Option<&Path>) -> object_store::Result<ListResult> {
        self.fs.list_with_delimiter(prefix).await
    }

    async fn copy(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.fs.copy(from, to).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.fs.rename(from, to).await
    }

    async fn copy_if_not_exists(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.fs.copy_if_not_exists(from, to).await
    }

    async fn rename_if_not_exists(&self, from: &Path, to: &Path) -> object_store::Result<()> {
        self.fs.rename_if_not_exists(from, to).await
    }
    
}