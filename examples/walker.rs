use std::fs;
use std::path::{Path, PathBuf};
use std::ffi::OsString;
use std::collections::HashMap;
use std::thread::{spawn, JoinHandle};
use std::sync::Mutex;
use std::sync::mpsc::{channel, Sender};

use rayon::prelude::*;
use adblock::engine::Engine;

use pagegraph::from_xml::read_from_file;
use pagegraph::graph::PageGraph;
use pagegraph::types::{NodeType, EdgeType};

#[macro_use]
extern crate serde_derive;

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

fn stem_to_origin_url(stem: &Path) -> String {
    if let std::path::Component::Normal(p) = stem.components().next().expect("missing first component of stem path?!") {
        let hostname = p.to_str().expect("bad filename (not utf8)");
        return format!("https://{0}/", hostname);
    }
    panic!("invalid first component of stem path!")
}

#[derive(Debug, Serialize)]
struct FeatureVector {
    site_tag: String,
    profile_tag: String,
    total_nodes: usize,
    total_edges: usize,
    total_dom_nodes: usize,
    net_dom_nodes: usize,
    touched_dom_nodes: usize,
    completed_requests: usize,
    event_listenings: usize,
}

fn main() {
    let roots = std::env::args_os().skip(1).collect::<Vec<OsString>>();
    if roots.len() == 0 {
        eprintln!("usage: {0} DIR1 [DIR2 ...]", std::env::args().next().expect("hey, where's argv[0]??"));
        return
    }

    let filterset_blob = std::fs::read("filterset.dat").expect("unable to read `filterset.dat`");
    let (abp_sender, _) = launch_adblock_server(filterset_blob);
    let root_sender = Mutex::new(abp_sender);

    let wtr = csv::Writer::from_writer(std::io::stdout());
    let wtr_mut = Mutex::new(wtr);

    match parse_crawl_map(roots) {
        Ok(mother) => {
            // process the crawl/profile/graphml-files map structure in parallel using rayon
            mother.into_par_iter().for_each(|(stem, profile_map)| {
                // load all the graphs in this crawl set (i.e., cluster of directories, one per profile)
                let graph_map = load_graph_cluster(&profile_map);

                // compute "origin URL" from the directory structure (or panic)
                let origin_url = stem_to_origin_url(&stem);
                
                // use metadata and adblock rules to identify 3p-non-ad-URL remote frames
                let abp_sender = root_sender.lock().unwrap().clone();
                let graph_map: ProfileGraphMap = graph_map.into_iter().map(|(profile, graphs)| {
                    let abp_sender = abp_sender.clone();
                    let (client_sender, client_receiver) = channel();
                    (profile.clone(), graphs.into_iter().filter_map(|g| {
                        if let Some(ref meta) = g.meta {
                            if !meta.is_root {
                                let _ = abp_sender.send((meta.url.clone(), origin_url.clone(), client_sender.clone()));
                                match client_receiver.recv() {
                                    Ok(is_match) if is_match => return Some(g),
                                    _ => {}
                                }
                            }
                        }
                        None
                    }).collect())
                }).collect();

                // extract features of interest from these graphs
                graph_map.into_iter().for_each(|(profile, graphs)| {
                    let mut rec = FeatureVector {
                        site_tag: stem.to_str().unwrap().to_owned(),
                        profile_tag: profile.clone(),
                        total_nodes: 0,
                        total_edges: 0,
                        total_dom_nodes: 0,
                        net_dom_nodes: 0,
                        touched_dom_nodes: 0,
                        completed_requests: 0,
                        event_listenings: 0,
                    };
                    graphs.into_iter().for_each(|g| {
                        rec.total_nodes += g.nodes.len();
                        rec.total_edges += g.edges.len();
                        g.nodes.iter().for_each(|(id, node)| {
                            match node.node_type {
                                NodeType::HtmlElement { is_deleted, .. } => {
                                    rec.total_dom_nodes += 1;
                                    if !is_deleted { rec.net_dom_nodes += 1; }
                                    let html_mods = g.all_html_element_modifications(*id);
                                    if html_mods.len() > 2 { rec.touched_dom_nodes += 1; }
                                }
                                _ => {}
                            }
                        });
                        rec.completed_requests += g.filter_edges(|edge_type| {
                            match edge_type {
                                EdgeType::RequestComplete { .. } => true,
                                _ => false,
                            }
                        }).len();
                        rec.event_listenings += g.filter_edges(|edge_type| {
                            match edge_type {
                                EdgeType::AddEventListener { .. } => true,
                                _ => false,
                            }
                        }).len();
                    });

                    if let Err(e) = wtr_mut.lock().unwrap().serialize(rec) {
                        eprintln!("error: {:?}", e);
                    }
                });
            });
            wtr_mut.lock().unwrap().flush().expect("error flushing CSV output stream?!");
        },
        Err(e) => {
            eprintln!("error: {:?}", e);
        }
    }
}