use std::io::prelude::*;

use petgraph::Direction;
use sha2::Digest;

use pagegraph::from_xml::read_from_file;
use pagegraph::graph::PageGraph;
use pagegraph::types::{NodeType, EdgeType};

type FeatureBag = Vec<String>;

fn compute_node_feature(node: &NodeType) -> Option<String> {
    match node {
        NodeType::RemoteFrame {..} => Some("RemoteFrame".to_owned()),
        NodeType::Resource { ref url } => Some(format!("Resource[{0}]", url)),
        NodeType::WebApi { ref method } => Some(format!("WebAPI[{0}]", method)),
        NodeType::JsBuiltin { ref method } => Some(format!("JsBuiltin[{0}]", method)),
        NodeType::HtmlElement { ref tag_name, .. } => Some(format!("Html[{0}]", tag_name)),
        NodeType::TextNode { ref text, .. } => match text {
            Some(text_str) if text_str.len() > 0 => {
                let hash = sha2::Sha256::digest(text_str.as_ref());
                Some(format!("Text[{0}]", hex::encode(hash)))
            },
            _ => Some("Text[]".to_owned()),
        },
        NodeType::DomRoot { ref url, ref tag_name, .. } => match url {
            Some(url_str) => Some(format!("DomRoot[{0}:{1}]", tag_name, url_str)),
            None => Some(format!("DomRoot[{0}]", tag_name)),
        },
        NodeType::FrameOwner { ref tag_name, .. } => Some(format!("FrameOwner[{0}]", tag_name)),
        NodeType::LocalStorage { } => Some("LocalStorage".to_owned()),
        NodeType::SessionStorage { } => Some("SessionStorage".to_owned()),
        NodeType::CookieJar { } => Some("CookieJar".to_owned()),
        NodeType::Script { ref url, ref script_type, .. } => match url {
            Some(url_str) => Some(format!("Script[{0}:{1}]", script_type, url_str)),
            None => Some(format!("Script[{0}]", script_type)),
        },
        NodeType::Parser { } => Some("Parser".to_owned()),
        _ => None
    }
}

fn compute_node_bag(g: &PageGraph) -> FeatureBag {
    let mut bag : FeatureBag = FeatureBag::new();
    for (_, ref node) in g.nodes.iter() {
        if let Some(s) = compute_node_feature(&node.node_type) {
            bag.push(s);
        }
    }
    bag
}

fn compute_edge_feature(edge: &EdgeType, s1: &str, s2: &str) -> Option<String> {
    match edge {
        // Simple structural/interaction links
        EdgeType::Structure { } => Some(format!("Structure:{0}->{1}", s1, s2)),
        EdgeType::TextChange { } => Some(format!("TextChange:{0}->{1}", s1, s2)),
        EdgeType::CreateNode { } => Some(format!("CreateNode:{0}->{1}", s1, s2)),
        EdgeType::InsertNode { .. } => Some(format!("InsertNode:{0}->{1}", s1, s2)),
        EdgeType::RemoveNode { }  => Some(format!("RemoveNode:{0}->{1}", s1, s2)),
        EdgeType::DeleteNode { }  => Some(format!("DeleteNode:{0}->{1}", s1, s2)),
        EdgeType::JsCall { .. } => Some(format!("JsCall:{0}->{1}", s1, s2)), // initiation only, not results
        EdgeType::Execute { } => Some(format!("Execute:{0}->{1}", s1, s2)),
        
        // HTTP actions
        EdgeType::RequestStart { ref request_type, .. } => Some(format!("RequestStart:{0}-[{2:?}]->{1}", s1, s2, request_type)),
        EdgeType::RequestError { ref status, .. } => Some(format!("RequestError:{0}-[{2}]->{1}", s1, s2, status)),
        EdgeType::RequestComplete { ref resource_type, size, .. } => Some(format!("RequestComplete:{0}-[{2};{3}]->{1}", s1, s2, resource_type, size)),
        
        // Event listener actions
        EdgeType::AddEventListener { ref key, .. } => Some(format!("AddEventListener:{0}-[{2}]->{1}", s1, s2, key)),
        EdgeType::RemoveEventListener { ref key, .. } => Some(format!("RemoveEventListener:{0}-[{2}]->{1}", s1, s2, key)),
        EdgeType::EventListener { ref key, .. } => Some(format!("EventListener:{0}-[{2}]->{1}", s1, s2, key)),

        // Storage interactions (initiation only, not results)
        EdgeType::StorageSet { ref key, .. } => Some(format!("StorageSet:{0}-[{2}]->{1}", s1, s2, key)),
        EdgeType::ReadStorageCall { ref key, .. } => Some(format!("ReadStorageCall:{0}-[{2}]->{1}", s1, s2, key)),
        EdgeType::DeleteStorage { ref key, .. } => Some(format!("DeleteStorage:{0}-[{2}]->{1}", s1, s2, key)),
        EdgeType::ClearStorage { ref key, .. } => match key {
            Some(key_str) => Some(format!("ClearStorage:{0}-[{2}]->{1}", s1, s2, key_str)),
            None => Some(format!("ClearStorage:{0}->{1}", s1, s2)),
        },

        // Attribute-related links
        EdgeType::ExecuteFromAttribute { ref attr_name } => Some(format!("ExecuteFromAttribute:{0}-[{2}]->{1}", s1, s2, attr_name)),
        EdgeType::SetAttribute { ref key, .. } => Some(format!("SetAttribute:{0}-[{2}]->{1}", s1, s2, key)),
        EdgeType::DeleteAttribute { ref key, .. } => Some(format!("DeleteAttribute:{0}-[{2}]->{1}", s1, s2, key)),

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
                            bag.push(es);
                        }
                    }
                }
            }
        }
    }
    bag
}

fn usage() -> ! {
    eprintln!("usage: {0} (node|edge) GRAPHML [GRAPHML ...]", std::env::args().next().expect("hey, where's argv[0]??"));
    std::process::exit(1);
}

type Collector = fn(&PageGraph) -> FeatureBag;

fn main() {
    let mode: Option<String> = std::env::args().skip(1).next();
    let (collector, tag) = match mode {
        Some(s) => match s.as_ref() {
            "node" => (compute_node_bag as Collector, "nbag"),
            "edge" => (compute_edge_bag as Collector, "ebag"),
            _ => usage(),
        },
        _ => usage(),
    };
    let filenames: Vec<String> = std::env::args().skip(2).collect::<Vec<String>>();
    if filenames.len() == 0 {
        usage();
    }

    for filename in filenames {
        let ipath = std::path::Path::new(&filename);
        let opath = ipath.with_extension(tag);

        let g = read_from_file(ipath.to_str().expect("bad filename"));
        let bag = collector(&g);

        match std::fs::File::create(&opath) {
            Ok(mut ofile) => {
                for item in bag {
                    if let Err(e) = writeln!(&mut ofile, "{0}", item) {
                        eprintln!("error: can't write to '{0}' ({1})", opath.display(), e);
                        break;
                    }
                }
            },
            Err(e) => eprintln!("error: can't open '{0}' for writing ({1})", opath.display(), e)
        }
    }
}