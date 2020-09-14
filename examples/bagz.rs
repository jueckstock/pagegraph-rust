use std::fs;
use std::path::{Path, PathBuf};
use std::ffi::OsString;
use std::collections::HashMap;
use std::thread::{spawn, JoinHandle};
use std::sync::Mutex;
use std::sync::mpsc::{channel, Sender};

use rayon::prelude::*;
use adblock::engine::Engine;
use regex::Regex;
use petgraph::Direction;
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

fn url_host_etld1(raw_url: &str, psl: &publicsuffix::List) -> Option<String> {
    if let Ok(u) = url::Url::parse(raw_url) {
        if let Some(hostname) = u.host_str() {
            if let Ok(domain) = psl.parse_domain(&hostname) {
                if let Some(s) = domain.root() {
                    return Some(s.to_owned());
                }
            }
        }
    }
    None
}

/* #[derive(Debug, Serialize)]
struct FeatureVector {
    site_tag: String,
    profile_tag: String,
    url: String,
    url_etld1: Option<String>,
    is_root: bool,
    is_ad: bool,
    total_nodes: usize,
    total_edges: usize,
    total_dom_nodes: usize,
    total_remote_frames: usize,
    touched_dom_nodes: usize,
    completed_requests: usize,
    event_listenings: usize,
    post_storage_script_edges: usize,
    post_storage_console_errors: usize,
}

#[derive(Debug, Deserialize)]
struct ConsoleLogArgs {
    level: String,
    // others not important for us right now
}
 */


fn main() {
    let roots = std::env::args_os().skip(1).collect::<Vec<OsString>>();
    if roots.len() == 0 {
        eprintln!("usage: {0} DIR1 [DIR2 ...]", std::env::args().next().expect("hey, where's argv[0]??"));
        return
    }

    let filterset_blob = std::fs::read("filterset.dat").expect("unable to read `filterset.dat`");
    let (abp_sender, _) = launch_adblock_server(filterset_blob);
    let root_abp_sender = Mutex::new(abp_sender);

    let psl = publicsuffix::List::from_path("public_suffix_list.dat").expect("unable to read `public_suffix_list.dat`");

    let wtr = csv::Writer::from_writer(std::io::stdout());
    let wtr_mut = Mutex::new(wtr);

    match parse_crawl_map(roots) {
        Ok(mother) => {
            // process the crawl/profile/graphml-files map structure in parallel using rayon
            mother.into_par_iter().for_each(|(stem, profile_map)| {
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
                                    match index.insert(profile.clone(), g) {
                                        Some(_) => {
                                            eprintln!("warning: {0:?}/{1} contains duplicate graphs for URL '{2}'", stem, profile, frame_url);
                                        },
                                        None => {}
                                    }
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
                for ((is_root, is_ad, frame_url), profile_graphs) in inverted_index {
                    if !is_root && !is_ad && profile_graphs.len() == 10 {
                        println!("{0}", frame_url);
                    } else {
                        eprintln!("info: {0:?} has graph URL '{1}' (is_root={2}, is_ad={3}) with cross-profile mismatch", stem, frame_url, is_root, is_ad);
                    }
                }

            });
             wtr_mut.lock().unwrap().flush().expect("error flushing main CSV output stream?!");
        },
        Err(e) => {
            eprintln!("error: {:?}", e);
        }
    }
}