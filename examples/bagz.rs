use std::fs;
use std::path::{Path, PathBuf};
use std::ffi::OsString;
use std::collections::{HashMap, HashSet};
use std::thread::{spawn, JoinHandle};
use std::sync::Mutex;
use std::sync::mpsc::{channel, Sender};

use rayon::prelude::*;
use adblock::engine::Engine;
use itertools::Itertools;
use petgraph::Direction;
use regex::Regex;
use cookie::Cookie;

use pagegraph::from_xml::read_from_file;
use pagegraph::graph::PageGraph;
use pagegraph::types::{NodeType, EdgeType};

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

/// Approximate Python's os.walk() generator function using a mutable callback closure
fn walk(dir: &Path, cb: &mut dyn FnMut(&Path, &Vec<PathBuf>, Vec<PathBuf>) -> Result<(), Box<dyn std::error::Error>>) -> Result<(), Box<dyn std::error::Error>> {
    // Collect the names of sub-directories and files in the current directory
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            dirs.push(path);
        } else if path.is_file() {
            files.push(path);
        }
    }

    // Invoke the callback with the current directory's path,
    // a reference to the vector of sub-directory names,
    // and moved-ownership of the file name list
    cb(dir, &dirs, files)?;

    // BFS: recursively descend into each sub-directory
    for sub_dir in dirs {
        walk(&sub_dir, cb)?;
    }

    Ok(())
}

type ProfileFileMap = HashMap<String, Vec<PathBuf>>;
type CrawlFileMap = HashMap<PathBuf, ProfileFileMap>;

fn parse_crawl_map(roots: Vec<OsString>) -> Result<CrawlFileMap, Box<dyn std::error::Error>> {
    let mut mother: CrawlFileMap = HashMap::new();
    for root in roots {
        let rpath = Path::new(&root);
        let profile = rpath.file_name().unwrap().to_str().expect("bad profile name (not utf8)");
        walk(&rpath, &mut |node, dirs, files| {
            if dirs.len() == 0 {
                let rel_path = node.strip_prefix(&rpath)?.to_path_buf();
                let graph_files = files.into_iter().filter(|f| f.extension().unwrap_or_default() == "graphml").collect();
                match mother.get_mut(&rel_path) {
                    Some(ref mut profile_map) => {
                        profile_map.insert(profile.to_owned(), graph_files);
                    },
                    None => {
                        let mut profile_map = HashMap::new();
                        profile_map.insert(profile.to_owned(), graph_files);
                        mother.insert(rel_path, profile_map);
                    }
                }
            }
            Ok(())
        })?;
    }
    Ok(mother)
}

type ProfileGraphMap = HashMap<String, Vec<PageGraph>>;

fn load_graph_cluster(graph_cluster: &ProfileFileMap) -> ProfileGraphMap {
    graph_cluster.iter().map(|(profile, graph_paths)| {
        (profile.clone(), graph_paths.iter().map(|f| {
            read_from_file(f.to_str().expect("bad filename (not uf8)"))
        }).collect())
    }).collect()
}

fn launch_adblock_server(filterset_blob: Vec<u8>) ->
    (Sender<(String, String, Sender<bool>)>, JoinHandle<std::io::Result<()>>) {
    let (sender, receiver) = channel::<(String, String, Sender<bool>)>();

    let handle = spawn(move || {
        let mut engine = Engine::new(false);
        engine.deserialize(filterset_blob.as_ref()).expect("error deserializing filterset");

        for (frame_url, origin_url, sase) in receiver {
            let result = engine.check_network_urls(frame_url.as_ref(), origin_url.as_ref(), "sub_frame");
            let _ = sase.send(result.matched);
        }
        Ok(())
    });

    (sender, handle)
}

fn retreive_origin_url(stem: &Path, graph_map: &ProfileGraphMap) -> String {
    // First, try to find is_root==true graphs (should be _1_ per profile) and extract their meta URL field
    // (we blithely assume the first is_root==true graph we find in any given profile is the correct crawl URL)
    for (_, graphs) in graph_map {
        for g in graphs {
            if let Some(ref meta) = g.meta {
                if meta.is_root {
                    return meta.url.clone();
                }
            }
        }
    }

    if let std::path::Component::Normal(p) = stem.components().next().expect("missing first component of stem path?!") {
        let hostname = p.to_str().expect("bad filename (not utf8)");
        return format!("https://{0}/", hostname);
    }
    panic!("invalid first component of stem path!")
}

fn url_host_etld1(raw_url: &str) -> Option<String> {
    lazy_static! {
        static ref PSL: publicsuffix::List = publicsuffix::List::from_path("public_suffix_list.dat").expect("unable to read `public_suffix_list.dat`");
    }
    if let Ok(u) = url::Url::parse(raw_url) {
        if let Some(hostname) = u.host_str() {
            if let Ok(domain) = PSL.parse_domain(&hostname) {
                if let Some(s) = domain.root() {
                    return Some(s.to_owned());
                }
            }
        }
    }
    None
}

#[derive(Debug, Serialize)]
struct FeatureVector {
    site_tag: String,
    frame_url: String,
    is_root: bool,
    is_ad: bool,
    p1: String,
    p2: String,
    node_jaccard: f32,
    edge_jaccard: f32,
}

fn launch_csv_server<T: serde::Serialize + std::marker::Send + 'static, W: std::io::Write + std::marker::Send + 'static>(mut wtr: csv::Writer<W>) -> (Sender<T>, JoinHandle<std::io::Result<()>>) {
    let (sender, receiver) = channel::<T>();
    //let mut wtr = csv::Writer::from_writer(std::io::stdout());
    let handle = spawn(move || {
        for record in receiver {
            if let Err(e) = wtr.serialize(record) {
                eprintln!("write error: {0}", e);
            }
        }
        if let Err(e) = wtr.flush() {
            eprintln!("flush error: {0}", e);
        }
        Ok(())
    });

    (sender, handle)
}


type FeatureBag = HashSet<String>;

fn compute_node_feature(node: &NodeType) -> Option<String> {
    match node {
        // trying the union of "best-edge-subset" and "best-node-subset" (by CM1 score, measuring separation of vanilla from fullblock3p)
        NodeType::DomRoot { ref url, ref tag_name, .. } => match url {
            Some(url_str) => Some(format!("DomRoot[{0}:{1}]", tag_name, url_host_etld1(url_str).unwrap_or_default())),
            None => Some(format!("DomRoot[{0}]", tag_name)),
        },
        NodeType::LocalStorage { } => Some("LocalStorage".to_owned()),
        NodeType::SessionStorage { } => Some("SessionStorage".to_owned()),
        NodeType::CookieJar { } => Some("CookieJar".to_owned()),
        NodeType::Script { ref url, ref script_type, .. } => match url {
            Some(url_str) => Some(format!("Script[{0}:{1}]", script_type, url_host_etld1(url_str).unwrap_or_default())),
            None => Some(format!("Script[{0}]", script_type)),
        },
        NodeType::FrameOwner { ref tag_name, .. } => Some(format!("FrameOwner[{0}]", tag_name)),
        NodeType::Resource { ref url } => Some(format!("Resource[{0}]", url_host_etld1(url).unwrap_or_default())),
        NodeType::JsBuiltin { ref method } => Some(format!("JsBuiltin[{0}]", method)),

        /* NodeType::RemoteFrame {..} => Some("RemoteFrame".to_owned()),
        NodeType::WebApi { ref method } => Some(format!("WebAPI[{0}]", method)),
        NodeType::HtmlElement { ref tag_name, .. } => Some(format!("Html[{0}]", tag_name)),
        NodeType::TextNode { ref text, .. } => match text {
            Some(text_str) => Some(format!("Text[{0}]", text_str)),
            None => Some("Text[]".to_owned()),
        }, */

        _ => None
    }
}

fn compute_node_bag(g: &PageGraph) -> FeatureBag {
    let mut bag : FeatureBag = FeatureBag::new();
    for (_, ref node) in g.nodes.iter() {
        if let Some(s) = compute_node_feature(&node.node_type) {
            bag.insert(s);
        }
    }
    bag
}

fn compute_edge_feature(edge: &EdgeType, s1: &str, s2: &str) -> Option<String> {
    match edge {
        // Simple structural/interaction links
        EdgeType::Structure { } => Some(format!("{0}->{1}", s1, s2)),
        EdgeType::TextChange { } => Some(format!("{0}-txt->{1}", s1, s2)),
        EdgeType::CreateNode { } => Some(format!("{0}-create->{1}", s1, s2)),
        EdgeType::InsertNode { .. } => Some(format!("{0}-insert->{1}", s1, s2)),
        EdgeType::RemoveNode { }  => Some(format!("{0}-remove->{1}", s1, s2)),
        EdgeType::DeleteNode { }  => Some(format!("{0}-del->{1}", s1, s2)),
        EdgeType::JsCall { .. } => Some(format!("{0}-call->{1}", s1, s2)),
        EdgeType::Execute { } => Some(format!("{0}-exec->{1}", s1, s2)),
        
        // HTTP actions
        EdgeType::RequestStart { ref request_type, .. } => Some(format!("{0}-start[{2:?}]->{1}", s1, s2, request_type)),
        EdgeType::RequestError { ref status, .. } => Some(format!("{0}-error[{2}]->{1}", s1, s2, status)),
        EdgeType::RequestComplete { ref resource_type, size, .. } => Some(format!("{0}-complete[{2};{3}]->{1}", s1, s2, resource_type, size)),
        
        // Event listener actions
        EdgeType::AddEventListener { ref key, .. } => Some(format!("{0}-listen[{2}]->{1}", s1, s2, key)),
        EdgeType::RemoveEventListener { ref key, .. } => Some(format!("{0}-ignore[{2}]->{1}", s1, s2, key)),
        EdgeType::EventListener { ref key, .. } => Some(format!("{0}-event[{2}]->{1}", s1, s2, key)),

        // Storage interactions
        EdgeType::StorageSet { ref key, .. } => Some(format!("{0}-store[{2}]->{1}", s1, s2, key)),
        EdgeType::ReadStorageCall { ref key, .. } => Some(format!("{0}-read[{2}]->{1}", s1, s2, key)),
        EdgeType::DeleteStorage { ref key, .. } => Some(format!("{0}-del[{2}]->{1}", s1, s2, key)),
        EdgeType::ClearStorage { ref key, .. } => match key {
            Some(key_str) => Some(format!("{0}-clear[{2}]->{1}", s1, s2, key_str)),
            None => Some(format!("{0}-clear[]->{1}", s1, s2)),
        },

        // Attribute-related links
        EdgeType::ExecuteFromAttribute { ref attr_name } => Some(format!("{0}-exec[{2}]->{1}", s1, s2, attr_name)),
        EdgeType::SetAttribute { ref key, .. } => Some(format!("{0}-setAttr[{2}]->{1}", s1, s2, key)),
        EdgeType::DeleteAttribute { ref key, .. } => Some(format!("{0}-delAttr[{2}]->{1}", s1, s2, key)),

        // Anything else is not turned into a feature
        _ => None
    }
}

fn compute_edge_bag(g: &PageGraph) -> FeatureBag {
    let mut bag : FeatureBag = FeatureBag::new();
    for (node_id, ref node) in g.nodes.iter() {
        if let Some(s1) = compute_node_feature(&node.node_type) {
            for dest_node_id in g.graph.neighbors_directed(*node_id, Direction::Outgoing) {
                let dest_node = g.nodes.get(&dest_node_id).unwrap();
                if let Some(s2) = compute_node_feature(&dest_node.node_type) {
                    for edge_id in g.graph.edge_weight(*node_id, dest_node_id).unwrap() {
                        let edge = g.edges.get(edge_id).unwrap();
                        if let Some(es) = compute_edge_feature(&edge.edge_type, &s1, &s2) {
                            bag.insert(es);
                        }
                    }
                }
            }
        }
    }
    bag
}

fn jaccard_similarity(bag1: &FeatureBag, bag2: &FeatureBag) -> f32 {
    let n = bag1.intersection(bag2).count() as f32;
    let d = bag1.union(bag2).count() as f32;
    if d > 0.0 {
        n / d
    } else {
        std::f32::NAN
    }
}


#[derive(Debug, Serialize, Hash, Eq, PartialEq)]
enum PrivacyTokenSource {
    QueryParam,
    RawHeader,
    Cookie,
    LocalStorageAPI,
}

#[derive(Debug, Serialize, Hash, Eq, PartialEq)]
struct PrivacyTokenFlow {
    profile: String,
    site_etld1: String,
    http_etld1: String,
    is_root: bool,
    is_ad: bool,
    source: PrivacyTokenSource,
    key: String,
    value: String,
}

fn raw_header_triples<'a>(headers: &'a str, prefix_filter: Option<&str>) -> Vec<(&'a str, &'a str, &'a str)> {
    lazy_static!{
        static ref RE: Regex = Regex::new(r#"^([-a-zA-Z0-9_]+):"(\S+)" "(.*)"$"#).expect("regex error?!");
    }
    let mut triples = Vec::new();
    for line in headers.split_terminator('\n') {
        if let Some(m) = RE.captures(line) {
            let header_prefix = m.get(1).unwrap().as_str();
            if prefix_filter.unwrap_or(header_prefix) == header_prefix {
                let header_name = m.get(2).unwrap().as_str();
                let header_value = m.get(3).unwrap().as_str();
                triples.push((header_prefix, header_name, header_value))
            }
        }
    }
    triples
}

fn extract_privacy_flows(site_etld1: &str, is_root: bool, is_ad: bool, frame_url: &str, profile_tag: &str, g: &PageGraph) -> std::collections::HashSet<PrivacyTokenFlow> {
    let mut flows: std::collections::HashSet<PrivacyTokenFlow> = std::collections::HashSet::new();
    
    let resources = g.filter_nodes(|nt| match nt {
        NodeType::Resource { .. } => true,
        _ => false,
    });

    for (node_id, node) in resources {
        if let NodeType::Resource { ref url } = node.node_type {
            if let Some(url_etld1) = url_host_etld1(url) {
                // Ignore same-eTLD+1 traffic
                if url_etld1 != site_etld1 {
                    // if we can parse the query string, add its name/value pairs
                    if let Ok(url_fields) = url::Url::parse(url) {
                        for (name, value) in url_fields.query_pairs() {
                            flows.insert(PrivacyTokenFlow{
                                profile: profile_tag.to_owned(),
                                site_etld1: site_etld1.to_owned(),
                                http_etld1: url_etld1.clone(),
                                is_root,
                                is_ad,
                                source: PrivacyTokenSource::QueryParam,
                                key: name.to_owned().to_string(),
                                value: value.to_owned().to_string(),
                            });
                        }
                    }

                    // find all request-completed edges out from this node
                    // and parse their headers for flows
                    let all_headers: Vec<_> = g.graph.neighbors_directed(*node_id, Direction::Outgoing)
                        .flat_map(|actor_node_id| {
                            let edge_ids = g.graph.edge_weight(*node_id, actor_node_id).unwrap();
                            edge_ids
                        })
                        .map(|edge_id| (edge_id, g.edges.get(edge_id).unwrap()))
                        .filter_map(|(_id, edge)| {
                            match &edge.edge_type {
                                EdgeType::RequestComplete { headers, .. } => Some(headers),
                                _ => None,
                            }
                        })
                        .collect();
                    for header_block in all_headers {
                        for (_, name, value) in raw_header_triples(&header_block, Some("raw-request")) {
                            if name.to_ascii_lowercase() == "cookie" {
                                for morsel in value.split_terminator(';') {
                                    if let Ok(c) = Cookie::parse(morsel) {
                                        flows.insert(PrivacyTokenFlow{
                                            profile: profile_tag.to_owned(),
                                            site_etld1: site_etld1.to_owned(),
                                            http_etld1: url_etld1.clone(),
                                            is_root,
                                            is_ad,
                                            source: PrivacyTokenSource::Cookie,
                                            key: c.name().to_owned().to_string(),
                                            value: c.value().to_owned().to_string(),
                                        });
                                    }
                                }
                            } 
                            // skip raw-headers as they aren't that useful and take a lot of space (and inject all)
                            /* else {
                                flows.insert(PrivacyTokenFlow{
                                    profile: profile_tag.to_owned(),
                                    site_etld1: site_etld1.to_owned(),
                                    http_etld1: url_etld1.clone(),
                                    is_root,
                                    is_ad,
                                    source: PrivacyTokenSource::RawHeader,
                                    key: name.to_owned().to_string(),
                                    value: value.to_owned().to_string(),
                                });
                            } */
                        }
                    }
                }
            }
        }
    }

    let local_storage_node = g.filter_nodes(|nt| match nt {
        NodeType::LocalStorage { } => true,
        _ => false,
    });
    local_storage_node.into_iter().for_each(|(node_id, _node)| {
        g.graph.neighbors_directed(*node_id, Direction::Outgoing)
            .flat_map(|actor_node_id| {
                let edge_ids = g.graph.edge_weight(*node_id, actor_node_id).unwrap();
                edge_ids
            })
        .map(|edge_id| (edge_id, g.edges.get(edge_id).unwrap()))
        .for_each(|(_id, edge)| {
            match &edge.edge_type {
                EdgeType::StorageReadResult { ref key, ref value } if value.is_some() => {
                    flows.insert(PrivacyTokenFlow{
                        profile: profile_tag.to_owned(),
                        site_etld1: site_etld1.to_owned(),
                        http_etld1: frame_url.to_owned(),
                        is_root,
                        is_ad,
                        source: PrivacyTokenSource::LocalStorageAPI,
                        key: key.clone(),
                        value: value.as_ref().unwrap().clone(),
                    });
                },
                _ => {},
            }
        });
    });
    flows
}

fn main() {
    let roots = std::env::args_os().skip(1).collect::<Vec<OsString>>();
    if roots.len() == 0 {
        eprintln!("usage: {0} DIR1 [DIR2 ...]", std::env::args().next().expect("hey, where's argv[0]??"));
        return
    }

    let filterset_blob = std::fs::read("filterset.dat").expect("unable to read `filterset.dat`");
    let (abp_sender, abp_thread) = launch_adblock_server(filterset_blob);
    let root_abp_sender = Mutex::new(abp_sender);

    let stdout_wtr = csv::Writer::from_writer(std::io::stdout());
    let (wtr_sender, wtr_thread) = launch_csv_server::<FeatureVector, _>(stdout_wtr);
    let root_wtr_sender = Mutex::new(wtr_sender);

    let privacy_wtr = csv::Writer::from_path("privacy_metrics.csv").expect("unable to write `privacy_metrics.csv`");
    let (pwtr_sender, pwtr_thread) = launch_csv_server::<PrivacyTokenFlow, _>(privacy_wtr);
    let root_pwtr_sender = Mutex::new(pwtr_sender);

    match parse_crawl_map(roots) {
        Ok(mother) => {
            // process the crawl/profile/graphml-files map structure in parallel using rayon
            mother.into_par_iter().for_each(|(stem, profile_map)| {
                let profile_count = profile_map.len();

                // load all the graphs in this crawl set (i.e., cluster of directories, one per profile)
                let graph_map = load_graph_cluster(&profile_map);

                // retrieve the starting crawl URL from the collection of graphs and the stem
                let origin_url = retreive_origin_url(&stem, &graph_map);
                let site_etld1 = url_host_etld1(&origin_url).unwrap_or_default();

                // build an inverted index: frame-url -> profile_name -> graph
                // use metadata and adblock rules to identify tag graphs as main/remote and (if remote) ad/not-ad
                // (also use metadata and PSL data to bundle each graph with its root URL eTLD+1)
                // (also run the privacy-flow extractor on all these graphs)
                let abp_sender = root_abp_sender.lock().unwrap().clone();
                let (abp_client_sender, abp_client_receiver) = channel();
                let pwtr_sender = root_pwtr_sender.lock().unwrap().clone();
                let mut inverted_index: HashMap<(bool, bool, String), HashMap<String, PageGraph>> = HashMap::new();
                for (profile, graphs) in graph_map {
                    for g in graphs {
                        if let Some(ref meta) = g.meta {
                            // metadata mining/ad-block classification
                            let frame_url = meta.url.clone();
                            let is_root = meta.is_root;
                            let mut is_ad = false;
                            if !is_root {
                                let _ = abp_sender.send((meta.url.clone(), origin_url.clone(), abp_client_sender.clone()));
                                match abp_client_receiver.recv() {
                                    Ok(is_match) if is_match => { is_ad = true }
                                    _ => {}
                                }
                            }

                            // privacy flow mining (we want flows from _all_ graphs, not just the URL-matched ones we use for similarity analysis)
                            for flow in extract_privacy_flows(&site_etld1, is_root, is_ad, &frame_url, &profile, &g) {
                                pwtr_sender.send(flow).expect("failed to send record for privacy flows CSV?");
                            }

                            // insertion into inverted-index
                            match inverted_index.get_mut(&(is_root, is_ad, frame_url.clone())) {
                                Some(ref mut index) => {
                                    index.insert(profile.clone(), g);
                                },
                                None => {
                                    let mut index = HashMap::new();
                                    index.insert(profile.clone(), g);
                                    inverted_index.insert((is_root, is_ad, frame_url.clone()), index);
                                }
                            }
                        } else {
                            eprintln!("warning: {0:?}/{1} contains graph with no <meta> block", stem, profile);
                        }
                    }
                }

                // walk the inverted index to find graphs/frame-urls with 10 profiles (5 profiles x 2 instances); i.e., same URL loaded for same crawl across all crawls
                let wtr_sender = root_wtr_sender.lock().unwrap().clone();
                for ((is_root, is_ad, frame_url), profile_graphs) in inverted_index {
                    if profile_graphs.len() == profile_count {
                        // compute node bags for each graph
                        let mut node_bag_map: HashMap<String, FeatureBag> = HashMap::new();
                        let mut edge_bag_map: HashMap<String, HashSet<String>> = HashMap::new();
                        let mut profile_names: Vec<String> = Vec::new();
                        for (profile, graph) in profile_graphs {
                            profile_names.push(profile.clone());
                            node_bag_map.insert(profile.clone(), compute_node_bag(&graph));
                            edge_bag_map.insert(profile, compute_edge_bag(&graph));
                        }
                        profile_names.sort_unstable();

                        // perform the cross-product of Jaccard similarity comparisons for both and emit a row of data
                        for combo in profile_names.iter().combinations(2) {
                            let p1 = combo[0];
                            let p2 = combo[1];
                            
                            let nbag1 = node_bag_map.get(p1).unwrap();
                            let nbag2 = node_bag_map.get(p2).unwrap();
                            let nji = jaccard_similarity(nbag1, nbag2);

                            let ebag1 = edge_bag_map.get(p1).unwrap();
                            let ebag2 = edge_bag_map.get(p2).unwrap();
                            let eji = jaccard_similarity(ebag1, ebag2);

                            let record = FeatureVector{
                                site_tag: stem.to_str().unwrap().to_owned(),
                                frame_url: frame_url.clone(),
                                is_root: is_root,
                                is_ad: is_ad,
                                p1: p1.to_string(),
                                p2: p2.to_string(),
                                node_jaccard: nji,
                                edge_jaccard: eji,
                            };
                            wtr_sender.send(record).expect("failed to send record for CSV output?!");
                        }
                    }
                }

            });
        },
        Err(e) => {
            eprintln!("error: {:?}", e);
        }
    }

    drop(root_pwtr_sender);
    pwtr_thread.join().expect("error joining/closing privacy CSV output thread");
    
    drop(root_wtr_sender);
    wtr_thread.join().expect("error joining/closing primary CSV output thread");
    
    drop(root_abp_sender);
    abp_thread.join().expect("error joining/closing ABP server thread");

    
}