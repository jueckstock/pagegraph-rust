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

fn stem_to_origin_url(stem: &Path) -> String {
    if let std::path::Component::Normal(p) = stem.components().next().expect("missing first component of stem path?!") {
        let hostname = p.to_str().expect("bad filename (not utf8)");
        return format!("https://{0}/", hostname);
    }
    panic!("invalid first component of stem path!")
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

#[derive(Debug, Serialize, Hash, Eq, PartialEq)]
enum PrivacyTokenSource {
    QueryParam,
    RawHeader,
    Cookie,
}

#[derive(Debug, Serialize, Hash, Eq, PartialEq)]
struct PrivacyTokenFlow {
    profile: String,
    site_etld1: String,
    http_etld1: String,
    source: PrivacyTokenSource,
    key: String,
    value: String,
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

fn extract_privacy_flows(site_tag: &str, profile_tag: &str, g: &PageGraph, psl: &publicsuffix::List) -> std::collections::HashSet<PrivacyTokenFlow> {
    let mut flows: std::collections::HashSet<PrivacyTokenFlow> = std::collections::HashSet::new();
    
    let resources = g.filter_nodes(|nt| match nt {
        NodeType::Resource { .. } => true,
        _ => false,
    });

    let site_host = site_tag.splitn(2, '/').next().unwrap();
    let site_etld1 = match psl.parse_domain(site_host) {
        Ok(domain) => domain.root().unwrap().to_owned(),
        _ => site_host.to_owned(),
    };

    for (node_id, node) in resources {
        if let NodeType::Resource { ref url } = node.node_type {
            if let Some(url_etld1) = url_host_etld1(url, psl) {
                // Ignore same-eTLD+1 traffic
                if url_etld1 != site_etld1 {
                    // if we can parse the query string, add its name/value pairs
                    if let Ok(url_fields) = url::Url::parse(url) {
                        for (name, value) in url_fields.query_pairs() {
                            flows.insert(PrivacyTokenFlow{
                                profile: profile_tag.to_owned(),
                                site_etld1: site_etld1.clone(),
                                http_etld1: url_etld1.clone(),
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
                                            site_etld1: site_etld1.clone(),
                                            http_etld1: url_etld1.clone(),
                                            source: PrivacyTokenSource::Cookie,
                                            key: c.name().to_owned().to_string(),
                                            value: c.value().to_owned().to_string(),
                                        });
                                    }
                                }
                            } else {
                                flows.insert(PrivacyTokenFlow{
                                    profile: profile_tag.to_owned(),
                                    site_etld1: site_etld1.clone(),
                                    http_etld1: url_etld1.clone(),
                                    source: PrivacyTokenSource::RawHeader,
                                    key: name.to_owned().to_string(),
                                    value: value.to_owned().to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    flows
}

#[derive(Debug, Serialize)]
struct FeatureVector {
    site_tag: String,
    profile_tag: String,
    url_etld1: Option<String>,
    is_root: bool,
    is_ad: bool,
    total_nodes: usize,
    total_edges: usize,
    total_dom_nodes: usize,
    net_dom_nodes: usize,
    touched_dom_nodes: usize,
    completed_requests: usize,
    event_listenings: usize,
    post_storage_script_edges: usize,
}

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

    let privacy_wtr = csv::Writer::from_path("privacy_metrics.csv").expect("unable to write `privacy_metrics.csv`");
    let privacy_wtr_mut = Mutex::new(privacy_wtr);

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
                
                // use metadata and adblock rules to identify tag graphs as main/remote and (if remote) ad/not-ad
                // also use metadata and PSL data to bundle each graph with its root URL eTLD+1
                let abp_sender = root_abp_sender.lock().unwrap().clone();
                let graph_map: Vec<_> = graph_map.into_iter().map(|(profile, graphs)| {
                    let abp_sender = abp_sender.clone();
                    let (abp_client_sender, abp_client_receiver) = channel();
                    (profile.clone(), graphs.into_iter().filter_map(|g| {
                        if let Some(ref meta) = g.meta {
                            let is_root = meta.is_root;
                            let mut is_ad = false;
                            if !is_root {
                                let _ = abp_sender.send((meta.url.clone(), origin_url.clone(), abp_client_sender.clone()));
                                match abp_client_receiver.recv() {
                                    Ok(is_match) if is_match => { is_ad = true }
                                    _ => {}
                                }
                            }
                            let url_etld1 = url_host_etld1(&meta.url, &psl);
                            return Some((is_root, is_ad, url_etld1, g))
                        }
                        None
                    }).collect())
                }).collect();

                // extract features of interest from these graphs
                graph_map.into_iter().for_each(|arg: (String, Vec<(bool, bool, Option<String>, PageGraph)>)| {
                    let (profile, graphs) = arg;

                    let site_tag = stem.to_str().unwrap();
                    graphs.into_iter().for_each(|(is_root, is_ad, url_etld1, g)| {
                        let ohmy = extract_privacy_flows(site_tag, &profile, &g, &psl);
                        if ohmy.len() > 0 {
                            let mut pwtr = privacy_wtr_mut.lock().unwrap();
                            for flow in ohmy {
                                if let Err(e) = pwtr.serialize(flow) {
                                    eprintln!("error: {:?}", e);
                                }
                            }
                        }

                        let mut rec = FeatureVector {
                            site_tag: site_tag.to_owned(),
                            profile_tag: profile.clone(),
                            url_etld1: url_etld1,
                            is_root: is_root,
                            is_ad: is_ad,
                            total_nodes: g.nodes.len(),
                            total_edges: g.edges.len(),
                            total_dom_nodes: 0,
                            net_dom_nodes: 0,
                            touched_dom_nodes: 0,
                            completed_requests: 0,
                            event_listenings: 0,
                            post_storage_script_edges: 0,
                        };
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

                        let script_actions = g.post_contact_script_actions(|nt| match nt {
                            NodeType::LocalStorage { } => true,
                            NodeType::CookieJar { } => true,
                            _ => false,
                        });
                        let script_action_tally: usize = script_actions.into_iter().map(|(_, history)| history.len()).sum();
                        rec.post_storage_script_edges += script_action_tally;

                        if let Err(e) = wtr_mut.lock().unwrap().serialize(rec) {
                            eprintln!("error: {:?}", e);
                        }
                    });
                });
            });
            wtr_mut.lock().unwrap().flush().expect("error flushing CSV output stream?!");
        },
        Err(e) => {
            eprintln!("error: {:?}", e);
        }
    }
}