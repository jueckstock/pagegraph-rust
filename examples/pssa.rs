use pagegraph::from_xml::read_from_file;
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

    let payload = graph.post_contact_script_actions(|nt| match nt {
        NodeType::LocalStorage { } => true,
        NodeType::CookieJar { } => true,
        _ => false,
    });

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