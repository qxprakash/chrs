//! CUBE filebrowser API client module.

use super::search::Search;
use crate::errors::{check, CubeError};
use crate::models::CubeFile;
use crate::types::*;
use aliri_braid::braid;
use serde::Deserialize;
use serde::Serialize;
use serde_with::json::JsonString;
use serde_with::serde_as;

/// A client for the _ChRIS_ filebrowser API.
pub struct FileBrowser {
    client: reqwest::Client,
    search: FileBrowserSearchUrl,
}

impl FileBrowser {
    /// Creates a filebrowser client.
    pub(crate) fn new(client: reqwest::Client, url: &FileBrowserUrl) -> Self {
        FileBrowser {
            client,
            search: FileBrowserSearchUrl::from(format!("{}search/", url)),
        }
    }

    /// List directories and files in _ChRIS_ storage from a given `path` prefix.
    ///
    /// You can think of this method like the `ls` UNIX command.
    pub async fn readdir(
        &self,
        path: impl AsRef<str>,
    ) -> Result<Option<FileBrowserEntry>, CubeError> {
        let res = self
            .client
            .get(self.search.as_str())
            .query(&FileBrowserQuery {
                path: path.as_ref(),
            })
            .send()
            .await?;
        let mut data: FileBrowserSearch = check(res).await?.json().await?;
        if data.results.is_empty() {
            return Ok(None);
        }
        let dir = data.results.swap_remove(0);
        Ok(Some(FileBrowserEntry::new(dir, self.client.clone())))
    }
}

/// Raw response from a GET request to `api/v1/filebrowser/search/`
#[derive(Deserialize)]
struct FileBrowserSearch {
    // count: u8,
    // next: Option<String>,
    // previous: Option<String>,
    results: Vec<FileBrowserDir>,
}

#[serde_as]
#[derive(Deserialize)]
struct FileBrowserDir {
    path: FileBrowserPath,
    #[serde_as(as = "JsonString")]
    subfolders: Vec<String>,
    // url: String,
    files: Option<FileBrowserFilesUrl>,
}

#[braid(serde)]
struct FileBrowserFilesUrl;

/// A filebrowser API response, which contains a listing for a _ChRIS_ file path.
pub struct FileBrowserEntry {
    client: reqwest::Client,
    path: FileBrowserPath,
    subfolders: Vec<String>,
    // url: String,
    /// API Url for files immediately under this path.
    /// Is `None` if path is `""` (root).
    files: Option<FileBrowserFilesUrl>,
}

impl FileBrowserEntry {
    fn new(dir: FileBrowserDir, client: reqwest::Client) -> Self {
        FileBrowserEntry {
            client,
            path: dir.path,
            subfolders: dir.subfolders,
            // url: dir.url,
            files: dir.files,
        }
    }

    /// Get the current path.
    pub fn path(&self) -> &FileBrowserPath {
        &self.path
    }

    /// Get subfolder basenames.
    pub fn subfolders(&self) -> &Vec<String> {
        &self.subfolders
    }

    /// Get absolute paths of subfolders.
    pub fn subpaths(&self) -> impl Iterator<Item = FileBrowserPath> + '_ {
        self.subfolders()
            .iter()
            .map(|subfolder| format!("{}/{}", self.path(), subfolder))
            .map(FileBrowserPath::new)
    }

    /// Iterate over files.
    pub fn iter_files(&self) -> Search<CubeFile, ()> {
        if let Some(url) = &self.files {
            Search::basic(&self.client, url)
        } else {
            Search::Empty
        }
    }
}

#[derive(Serialize)]
struct FileBrowserQuery<'a> {
    path: &'a str,
}
