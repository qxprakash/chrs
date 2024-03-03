use crate::errors::{check, CubeError, FileIOError};
use crate::models::linked::*;
use crate::types::*;
use camino::Utf8Path;
use fs_err::tokio::{File, OpenOptions};
use futures::{Stream, TryStreamExt};
use serde::de::DeserializeOwned;
use tokio_util::io::StreamReader;

/// A CUBE resource which has `file_resource`, `fname`, and `fsize`.
pub trait Downloadable {
    fn file_resource_url(&self) -> &FileResourceUrl;
    fn fname(&self) -> &FileResourceFname;
    fn fsize(&self) -> u64;
}

impl<D: Downloadable + DeserializeOwned> LinkedModel<D> {
    /// Stream the bytes data of a file from _ChRIS_.
    /// Returns the bytestream and content-length.
    pub async fn stream(
        &self,
    ) -> Result<impl Stream<Item = Result<bytes::Bytes, reqwest::Error>>, CubeError> {
        let res = self
            .client
            .get(self.object.file_resource_url().as_str())
            .send()
            .await?;
        let stream = check(res).await?.bytes_stream();
        Ok(stream)
    }

    /// Download a file from _ChRIS_ to a local path.
    pub async fn download(&self, dst: &Utf8Path, clobber: bool) -> Result<(), FileIOError> {
        let mut file = if clobber {
            File::create(dst).await
        } else {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dst)
                .await
        }
        .map_err(FileIOError::IO)?;
        let stream = self
            .stream()
            .await?
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionAborted, e));
        let mut reader = StreamReader::new(stream);
        tokio::io::copy(&mut reader, &mut file).await?;
        Ok(())
    }
}
