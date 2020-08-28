
use itertools::Itertools;

use petgraph::Direction;

use pagegraph::from_xml::read_from_file;
use pagegraph::graph::{EdgeId, NodeId};
use pagegraph::types::NodeType;

/// Post-Storage Script Activity analysis test
fn main() {
    let filename = std::env::args().skip(1).next().expect("need a filename");
    let graph = read_from_file(&filename);

    print!("{0} ", filename);
    if let Some(ref meta) = graph.meta {
        print!("[url='{0}', is_root={1}] ", meta.url, meta.is_root);
    }
    println!("-> {0} nodes, {1} edges", graph.nodes.len(), graph.edges.len());

    // Find the storage nodes of interest (LocalStorage, CookieJar)
    let storage_nodes: Vec<_> = graph.filter_nodes(|nt| match nt {
        NodeType::LocalStorage { } => true,
        NodeType::CookieJar { } => true,
        _ => false,
    });

    // Find the list of (script_node_id, earliest_edge_id_to_storage_node) tuples for each storage node in the graph
    let mut first_storage_accesses: Vec<_> = storage_nodes.into_iter().map(|(storage_node_id, _storage_node)| {
        let storage_node_id = *storage_node_id;
        graph.graph.neighbors_directed(storage_node_id, Direction::Incoming).filter_map(|script_node_id| {
            let script_node = graph.nodes.get(&script_node_id).unwrap();
            if let NodeType::Script { .. } = script_node.node_type {
                if let Some(min_edge_id) = graph.graph.edge_weight(script_node_id, storage_node_id).unwrap().into_iter().min() {
                    return Some((script_node_id, min_edge_id))
                }
            }
            None
        })
        .map(|(script_node_id, earliest_edge_id)| {
            (script_node_id, *earliest_edge_id)
        })
        .collect::<Vec<(NodeId, EdgeId)>>()
    })
    .flatten()
    .collect();

    // Collapse down to just (script_node, vector-of-edges-after-first-storage-access)
    first_storage_accesses.sort_unstable();
    let payload: Vec<_> = first_storage_accesses.iter()
        .group_by(|(node_id, _)| node_id)
        .into_iter().map(|(script_node_id, group)| {
            let (_, earliest_edge_id) = group.min_by_key(|(_, eid)| eid).unwrap();
            let script_node = graph.nodes.get(script_node_id).unwrap();
            let mut edge_history: Vec<_> = graph.graph.neighbors_directed(*script_node_id, Direction::Outgoing).flat_map(|target_id| {
                let edge_ids = graph.graph.edge_weight(*script_node_id, target_id).unwrap();
                edge_ids.into_iter().map(move |edge_id| {
                    (edge_id, target_id)
                })
            })
            .filter_map(|(edge_id, target_id)| {
                if edge_id >= earliest_edge_id {
                    Some((edge_id, target_id))
                } else {
                    None
                }
            })
            .collect();
            edge_history.sort_unstable_by_key(|(edge_id, _)| *edge_id);
            (script_node, edge_history)
        })
        .collect();

    for (script_node, edge_history) in payload {
        println!("script: {:?}", script_node);
        println!("=========================================");
        for (edge_id, node_id) in edge_history {
            let edge = graph.edges.get(edge_id).unwrap();
            let node = graph.nodes.get(&node_id).unwrap();
            println!("{:?} -> {:?}", edge, node);
        }
        println!("-----------------------------------------");
    }

}