use bytes::Bytes;
use chris::{types::*, AnonChrisClient, BaseChrisClient, ChrisPlugin, Downloadable};
use futures::{future, pin_mut, StreamExt, TryStreamExt};
use rstest::*;
use std::collections::HashSet;

mod helpers;
use helpers::{AnyResult, TESTING_URL};

#[fixture]
fn cube_url() -> CubeUrl {
    TESTING_URL.to_string().parse().unwrap()
}

#[fixture]
#[once]
fn chris_client(cube_url: CubeUrl) -> AnonChrisClient {
    futures::executor::block_on(async {
        AnonChrisClient::build(cube_url)
            .unwrap()
            .connect()
            .await
            .unwrap()
    })
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn test_filebrowser_subdirs(chris_client: &AnonChrisClient) -> AnyResult {
    let fb = chris_client.filebrowser();
    let entry = fb
        .readdir("chrisui")
        .await?
        .expect("Filebrowser path not found");
    let subdirs = entry.subfolders();
    let expected_subdirs = ["feed_307", "feed_310"];
    for expected in expected_subdirs {
        assert!(subdirs.contains(&expected.to_string()))
    }
    Ok(())
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn test_filebrowser_download_file(chris_client: &AnonChrisClient) -> AnyResult {
    let fb = chris_client.filebrowser();
    let entry = fb
        .readdir("chrisui/feed_310/pl-dircopy_313/pl-unstack-folders_314/pl-mri-preview_875/data")
        .await?
        .expect("Filebrowser path not found");
    let search = entry.iter_files();
    let search_results = search.stream_connected().try_filter(|f| {
        future::ready(
            f.object
                .fname()
                .as_str()
                .ends_with("/fetal-template-22.txt"),
        )
    });
    pin_mut!(search_results);
    let file = search_results
        .next()
        .await
        .expect("No files found in filebrowser path")?;
    let stream = file.stream().await?;
    let chunks: Vec<Bytes> = stream.try_collect().await?;
    let bytes: Vec<u8> = chunks
        .into_iter()
        .flat_map(|chunk| chunk.into_iter())
        .collect();
    let actual = String::from_utf8(bytes)?;
    let expected = "1961680 voxels\n1245019.9508666992 mm^3".to_string();
    assert_eq!(actual, expected);
    Ok(())
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn test_get_plugin_parameters(chris_client: &AnonChrisClient) -> AnyResult {
    let plugin = chris_client
        .plugin()
        .name("pl-mri-preview")
        .version("1.2.0")
        .search()
        .get_only()
        .await?;
    let params: Vec<_> = plugin.get_parameters().stream().try_collect().await?;
    let expected = HashSet::from(["--inputs", "--outputs", "--background", "--units-fallback"]);
    let actual = HashSet::from_iter(params.iter().map(|p| p.flag.as_str()));
    assert_eq!(expected, actual);
    Ok(())
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn test_search_public_feeds(chris_client: &AnonChrisClient) -> AnyResult {
    let query = chris_client
        .public_feeds()
        .name_exact("Fetal Brain Atlases");
    let feed = query.search().get_first().await?.expect("Feed not found");
    assert_eq!(&feed.object.name, "Fetal Brain Atlases");
    Ok(())
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn test_get_feed(chris_client: &AnonChrisClient) -> AnyResult {
    let id = FeedId(307);
    let feed = chris_client.get_feed(id).await?;
    assert_eq!(feed.object.id, id);
    Ok(())
}

#[rstest]
#[tokio::test(flavor = "multi_thread")]
async fn test_get_plugin_instance(chris_client: &AnonChrisClient) -> AnyResult {
    let id = PluginInstanceId(875);
    let pi = chris_client.get_plugin_instance(id).await?;
    assert_eq!(pi.object.id, id);
    Ok(())
}

#[rstest]
#[case(3)]
#[case(5)]
#[tokio::test(flavor = "multi_thread")]
async fn test_search_max_items(chris_client: &AnonChrisClient, #[case] count: usize) -> AnyResult {
    let query = chris_client.plugin().max_items(count);
    let items: Vec<_> = query.search().stream().try_collect().await?;
    assert_eq!(items.len(), count);
    Ok(())
}
