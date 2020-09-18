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
    //is_root: bool,
    //is_ad: bool,
    p1: String,
    p2: String,
    node_jaccard: f32,
    edge_jaccard: f32,
}

fn launch_csv_server() -> (Sender<FeatureVector>, JoinHandle<std::io::Result<()>>) {
    let (sender, receiver) = channel::<FeatureVector>();
    let mut wtr = csv::Writer::from_writer(std::io::stdout());
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
        // currently using the "best-edge-subset" (by CM1 score, measuring separation of vanilla from fullblock3p)
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

        /* NodeType::RemoteFrame {..} => Some("RemoteFrame".to_owned()),
        NodeType::Resource { ref url } => Some(format!("Resource[{0}]", url_host_etld1(url).unwrap_or_default())),
        NodeType::WebApi { ref method } => Some(format!("WebAPI[{0}]", method)),
        NodeType::JsBuiltin { ref method } => Some(format!("JsBuiltin[{0}]", method)),
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
    let n = bag1.intersection(bag2).collect::<Vec<_>>().len() as f32;
    let d = bag1.union(bag2).collect::<Vec<_>>().len() as f32;
    if d > 0.0 {
        n / d
    } else {
        std::f32::NAN
    }
}


fn main() {
    let roots = std::env::args_os().skip(1).collect::<Vec<OsString>>();
    if roots.len() == 0 {
        eprintln!("usage: {0} DIR1 [DIR2 ...]", std::env::args().next().expect("hey, where's argv[0]??"));
        return
    }

    /* // TEST: load graphml files directory and dump their node/edge bags
    let test_graph = read_from_file(roots[0].to_str().unwrap());
    let node_bag = compute_node_bag(&test_graph);
    for feature in node_bag {
        println!("{0}", feature);
    }
    println!("-----------------------------------------------------------");
    for feature in compute_edge_bag(&test_graph) {
        println!("{0}", feature);
    } */
    

    let filterset_blob = std::fs::read("filterset.dat").expect("unable to read `filterset.dat`");
    let (abp_sender, abp_thread) = launch_adblock_server(filterset_blob);
    let root_abp_sender = Mutex::new(abp_sender);

    let (wtr_sender, wtr_thread) = launch_csv_server();
    let root_wtr_sender = Mutex::new(wtr_sender);

    match parse_crawl_map(roots) {
        Ok(mother) => {
            // process the crawl/profile/graphml-files map structure in parallel using rayon
            mother.into_par_iter().for_each(|(stem, profile_map)| {
                let profile_count = profile_map.len();

                // load all the graphs in this crawl set (i.e., cluster of directories, one per profile)
                let graph_map = load_graph_cluster(&profile_map);

                // retrieve the starting crawl URL from the collection of graphs and the stem
                let origin_url = retreive_origin_url(&stem, &graph_map);

                // build an inverted index: frame-url -> profile_name -> graph
                // use metadata and adblock rules to identify tag graphs as main/remote and (if remote) ad/not-ad
                // (also use metadata and PSL data to bundle each graph with its root URL eTLD+1)
                let abp_sender = root_abp_sender.lock().unwrap().clone();
                let (abp_client_sender, abp_client_receiver) = channel();
                let mut inverted_index: HashMap<(bool, bool, String), HashMap<String, PageGraph>> = HashMap::new();
                for (profile, graphs) in graph_map {
                    for g in graphs {
                        if let Some(ref meta) = g.meta {
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

                // walk the inverted index to find the 3p-no-ad frames with 10 profiles (5 profiles x 2 instances)
                let wtr_sender = root_wtr_sender.lock().unwrap().clone();
                for ((is_root, is_ad, frame_url), profile_graphs) in inverted_index {
                    if !is_root && !is_ad && profile_graphs.len() == profile_count {
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

    drop(root_abp_sender);
    abp_thread.join().expect("error joining/closing ABP server thread");

    drop(root_wtr_sender);
    wtr_thread.join().expect("error joining/closing CSV output thread");
}