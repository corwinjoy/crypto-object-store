use std::fmt::{Display, Formatter};
use std::ops::Range;
use async_trait::async_trait;
use deltalake::storage::object_store;
use object_store::{ObjectStore, local::LocalFileSystem, PutPayload, PutResult, 
                                       PutOptions, MultipartUpload, PutMultipartOpts, GetResult, 
                                       GetOptions, ListResult};
use deltalake::{ObjectMeta, Path};

#[derive(Debug)]
pub struct CryptFileSystem {
    fs: LocalFileSystem,
}

impl CryptFileSystem {
    
    /*
    pub fn new() -> Self {
        Self { fs: LocalFileSystem::new() }
    }
     */

    pub fn new_with_prefix(prefix: impl AsRef<std::path::Path>) -> object_store::Result<Self> {
        Ok(Self { fs: LocalFileSystem::new_with_prefix(prefix)? })
    }
}

impl Display for CryptFileSystem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.fs.fmt(f)
    }
}

#[async_trait]
impl ObjectStore for CryptFileSystem {
    async fn put(&self, location: &Path, payload: PutPayload) -> object_store::Result<PutResult> {
        self.fs.put(location, payload).await
    }
    
    async fn put_opts(&self, location: &Path, payload: PutPayload, opts: PutOptions) -> object_store::Result<PutResult> {
        self.fs.put_opts(location, payload, opts).await
    }

    async fn put_multipart(&self, location: &Path) -> object_store::Result<Box<dyn MultipartUpload>> {
        self.fs.put_multipart(location).await
    }

    async fn put_multipart_opts(&self, location: &Path, opts: PutMultipartOpts) -> object_store::Result<Box<dyn MultipartUpload>> {
        self.fs.put_multipart_opts(location, opts).await
    }

    async fn get(&self, location: &Path) -> object_store::Result<GetResult> {
        self.fs.get(location).await
    }

    async fn get_opts(&self, location: &Path, options: GetOptions) -> object_store::Result<GetResult> {
        self.fs.get_opts(location, options).await 
    }

    async fn get_range(&self, location: &Path, range: Range<usize>) -> object_store::Result<bytes::Bytes> {
        self.fs.get_range(location, range).await
    }

    async fn get_ranges(&self, location: &Path, ranges: &[Range<usize>]) -> object_store::Result<Vec<bytes::Bytes>> {
        self.fs.get_ranges(location, ranges).await
    }

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