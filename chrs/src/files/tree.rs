//! Some naming conventions:
//!
//! - `path` is an absolute file path, e.g. `chris/feed_42`
//! - `folder`, `folder_name`, or `subfolder` is just the last component, e.g. `feed_42`

use crate::files::human_paths::MaybeNamer;
use anyhow::bail;
use async_recursion::async_recursion;
use async_stream::stream;
use chris::filebrowser::{FileBrowser, FileBrowserPath, FileBrowserView};
use chris::models::{Downloadable, DownloadableFile};
use chris::ChrisClient;
use console::{style, StyledObject};
use futures::lock::Mutex;
use futures::{StreamExt, TryStreamExt};
use indicatif::ProgressBar;
use itertools::Itertools;
use std::sync::Arc;
use termtree::Tree;
use tokio::join;
use tokio::sync::mpsc;
use tokio::sync::mpsc::UnboundedSender;

/// Show files in _ChRIS_ using the file browser API in a tree diagram.
pub(crate) async fn files_tree(
    client: &ChrisClient,
    path: &FileBrowserPath,
    full: bool,
    depth: u16,
    namer: MaybeNamer,
) -> anyhow::Result<()> {
    let fb = client.file_browser();
    match fb.browse(path).await? {
        None => bail!("Cannot find: {}", path),
        Some(v) => print_tree_from(&fb, v, full, depth, namer).await,
    }?;
    anyhow::Ok(())
}

async fn print_tree_from(
    fb: &FileBrowser,
    v: FileBrowserView,
    full: bool,
    depth: u16,
    mut namer: MaybeNamer,
) -> anyhow::Result<()> {
    let top_path = v.path().to_string();
    let (tx, mut rx) = mpsc::unbounded_channel();
    let main = async move {
        let spinner = ProgressBar::new_spinner();
        let mut count = 0;
        while (rx.recv().await).is_some() {
            count += 1;
            spinner.set_message(format!("Getting information... {}", count));
        }
    };
    let state = DescentState::new(v, top_path, full, depth);
    let tree_builder = construct(fb, tx, state, &mut namer);
    let (_, tree) = join!(main, tree_builder);
    println!("{}", tree?);
    anyhow::Ok(())
}

/// Recursively construct a tree for a ChRIS directory path containing files.
#[async_recursion]
async fn construct(
    fb: &FileBrowser,
    tx: UnboundedSender<()>,
    state: DescentState,
    namer: &mut MaybeNamer,
) -> anyhow::Result<Tree<StyledObject<String>>> {
    let root = state.style_with(namer).await;
    if state.depth == 0 {
        return anyhow::Ok(root);
    }

    // processing files before subfolders first because objects get moved
    // inside generator used for async recursion
    let mut subtrees = subfiles(&state.fbv, namer, state.full).await?;

    let maybe_subfolders = subfolders(fb, &state.fbv)
        .await
        .map_err(anyhow::Error::msg)?;

    // fancy rust async stuff, don't mind me
    let stx = tx.clone();

    // namer is moved by generator, so we use Arc
    let namer = Arc::new(Mutex::new(namer));
    let arc = Arc::clone(&namer);
    let mut rn = arc.lock().await;
    let subtree_stream = stream! {
        for maybe in maybe_subfolders {
            if let Some((subfolder, child)) = maybe {
                let next_state = state.next(child, subfolder);
                yield construct(fb, stx.clone(), next_state, *rn).await;
                // notify channel that we have done some work
                stx.send(()).unwrap();
            }
        }
    };

    let styled_subfolders: Vec<Tree<StyledObject<String>>> = subtree_stream.try_collect().await?;
    subtrees.extend(styled_subfolders);
    anyhow::Ok(root.with_leaves(subtrees))
}

/// Indicates what part of a CUBE (swift) file path we are looking at.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum DescentContext {
    /// Special case at the start
    Unknown,
    /// Empty path, parent of all files in *ChRIS*
    Root,
    /// Left-most base path, which is either a username or "SERVICES"
    Base,
    /// Second-from-the-left component, which is either "feed_N", "PACS", or "UPLOADS"
    Feed,
    /// A middle component of a plugin instance output file's fname
    /// after the feed and before the "data" folder.
    PluginInstances,
    /// A path which lacks a human-friendly name, e.g. PACS file, uploaded file.
    Data,
}

impl Default for DescentContext {
    fn default() -> Self {
        DescentContext::Unknown
    }
}

struct DescentState {
    fbv: FileBrowserView,
    subfolder: String,
    context: DescentContext,
    full: bool,
    depth: u16,
}

impl DescentState {
    fn new(fbv: FileBrowserView, subfolder: String, full: bool, depth: u16) -> Self {
        Self {
            context: Default::default(),
            fbv,
            subfolder,
            full,
            depth,
        }
    }

    /// Change states to the next [DescentContext] for the folder name.
    fn next(&self, fbv: FileBrowserView, subfolder: String) -> Self {
        if self.depth == 0 {
            panic!("depth underflow, calling recursive function should have quit.");
        }
        Self {
            context: next_context(self.context, fbv.path(), &subfolder),
            fbv,
            subfolder,
            full: self.full,
            depth: self.depth - 1,
        }
    }

    async fn style_with(&self, namer: &mut MaybeNamer) -> Tree<StyledObject<String>> {
        let display_name = if self.full || self.context == DescentContext::Unknown {
            namer.rename(&self.fbv.path().clone().into()).await
        } else {
            match self.context {
                DescentContext::Feed => namer.try_get_feed_name(&self.subfolder).await,
                DescentContext::PluginInstances => namer.get_title_for(&self.subfolder).await,
                _ => self.subfolder.clone(),
            }
        };
        Tree::new(style(display_name).bright().blue())
    }
}

/// Return the [DescentContext] of a *ChRIS* absolute file path.
fn initial_context(path: &FileBrowserPath) -> DescentContext {
    let path: &str = path.as_str().trim_end_matches('/');
    if path.is_empty() {
        return DescentContext::Root;
    }
    let mut components = path.split('/');
    components.next(); // skip over base folder
    if let Some(second_folder) = components.next() {
        if second_folder.starts_with("feed_") {
            if components.next().is_some() {
                if components.contains(&"data") {
                    DescentContext::Data
                } else {
                    DescentContext::PluginInstances
                }
            } else {
                DescentContext::Feed
            }
        } else {
            DescentContext::Data
        }
    } else {
        DescentContext::Base
    }
}

fn next_context(
    descent: DescentContext,
    path: &FileBrowserPath,
    subfolder: &str,
) -> DescentContext {
    match descent {
        DescentContext::Unknown => initial_context(path),
        DescentContext::Base => {
            if subfolder.starts_with("feed_") {
                DescentContext::Feed
            } else {
                DescentContext::Data
            }
        }
        DescentContext::Feed => DescentContext::PluginInstances,
        DescentContext::PluginInstances => {
            if subfolder == "data" {
                DescentContext::Data
            } else {
                DescentContext::PluginInstances
            }
        }
        DescentContext::Data => DescentContext::Data,
        DescentContext::Root => DescentContext::Base,
    }
}

/// Get subfolders under a given filebrowser path. Returns 2-tuples of (name, object)
async fn subfolders(
    fb: &FileBrowser,
    v: &FileBrowserView,
) -> Result<Vec<Option<(String, FileBrowserView)>>, String> {
    let subfolders_stream = stream! {
        for subfolder in v.subfolders() {
            let child_path = format!("{}/{}", v.path(), subfolder);
            yield fb.browse(&FileBrowserPath::from(child_path.as_str()))
                .await
                .map(|m| m.map(|child| (subfolder.to_string(), child)))
                .map_err(|e| format!("error browsing path \"{}\": {:?}", &child_path, e));
        }
    };
    subfolders_stream.try_collect().await
}

/// Get file names under a given filebrowser path and apply console output styling to them.
///
/// We're using `Vec` just to avoid dealing with streams.
async fn subfiles(
    v: &FileBrowserView,
    namer: &mut MaybeNamer,
    full: bool,
) -> Result<Vec<Tree<StyledObject<String>>>, reqwest::Error> {
    let file_infos = if full {
        subfiles_full_names(v, namer).await
    } else {
        subfiles_names(v).await
    }?;

    // collect was called so that we can use .map instead of streams
    let styled_files = file_infos.into_iter().map(style).map(Tree::new);
    Ok(styled_files.collect())
}

/// Use `namer` to convert the subfiles of `v` to user-friendly names.
async fn subfiles_full_names(
    v: &FileBrowserView,
    namer: &mut MaybeNamer,
) -> Result<Vec<String>, reqwest::Error> {
    let namer = Arc::new(Mutex::new(namer));
    v.iter_files()
        .try_filter_map(|file| {
            let arc = Arc::clone(&namer);
            async move {
                let mut rn = arc.lock().await;
                let namer = &mut *rn;
                Ok(Some(namer.rename(file.fname()).await))
            }
        })
        .try_collect()
        .await
}

async fn subfiles_names(v: &FileBrowserView) -> Result<Vec<String>, reqwest::Error> {
    v.iter_files().map(|f| f.map(file2name)).try_collect().await
}

fn file2name(f: DownloadableFile) -> String {
    let fname = f.fname().as_str();
    if let Some((_, basename)) = fname.rsplit_once('/') {
        return basename.to_string();
    }
    fname.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    #[case("", DescentContext::Root)]
    #[case("/", DescentContext::Root)]
    #[case("username", DescentContext::Base)]
    #[case("username/", DescentContext::Base)]
    #[case("SERVICES", DescentContext::Base)]
    #[case("SERVICES/PACS", DescentContext::Data)]
    #[case("username/feed_10", DescentContext::Feed)]
    #[case("username/feed_100", DescentContext::Feed)]
    #[case("username/feed_100/", DescentContext::Feed)]
    #[case("username/feed_100/pl-dircopy_600", DescentContext::PluginInstances)]
    #[case(
        "username/feed_100/pl-dircopy_600/pl-simpledsapp_601",
        DescentContext::PluginInstances
    )]
    #[case("username/feed_100/pl-dircopy_600/data", DescentContext::Data)]
    #[case(
        "username/feed_100/pl-dircopy_600/pl-simpledsapp_601/data",
        DescentContext::Data
    )]
    #[case(
        "username/feed_100/pl-dircopy_600/pl-simpledsapp_601/data/something.json",
        DescentContext::Data
    )]
    #[case(
        "username/feed_100/pl-dircopy_600/pl-simpledsapp_601/data/folder/ok.txt",
        DescentContext::Data
    )]
    fn test_initial_context(#[case] path: &str, #[case] expected: DescentContext) {
        assert_eq!(initial_context(path), expected)
    }
}
