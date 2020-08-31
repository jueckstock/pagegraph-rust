use std::sync::Mutex;

use rayon::prelude::*;

use pagegraph::from_xml::read_from_file;

#[macro_use]
extern crate serde_derive;

#[derive(Debug, Serialize)]
struct FeatureVector {
    site_tag: String,
    profile_tag: String,
    frame_url: String,
    node_count: usize,
    edge_count: usize,
}

fn main() {
    let graph_files = std::env::args().skip(1).collect::<Vec<String>>();
    if graph_files.len() == 0 {
        eprintln!("usage: {0} GRAPHML_FILE [GRAPHML_FILE ...]", std::env::args().take(1).next().expect("no argv[0]?!"));
    }

    let wtr = csv::Writer::from_writer(std::io::stdout());
    let wtr_mut = Mutex::new(wtr);
    
    graph_files.into_par_iter()
        .filter_map(|filename| {
            let graph = read_from_file(&filename);
            match graph.meta {
                Some(ref meta) if !meta.is_root => Some((filename, meta.url.clone(), graph)),
                _ => None,
            }
        })
        .for_each(|(filename, frame_url, graph)| {
            let fpath = std::path::Path::new(&filename);
            let fcoms: Vec<_> = fpath.components().rev().take(4).map(|c| match c { 
                std::path::Component::Normal(nn) => nn.to_str().expect("bad filename (not utf8)").to_owned(), 
                _ => panic!("bad filename") }).collect();
            let host_name = &fcoms[1];
            let url_tag = &fcoms[2];
            let profile_name = &fcoms[3];

            let rec = FeatureVector {
                site_tag: format!("{0}/{1}", host_name, url_tag),
                profile_tag: profile_name.clone(),
                frame_url: frame_url,
                node_count: graph.nodes.len(),
                edge_count: graph.edges.len(),
            };

            if let Err(e) = wtr_mut.lock().unwrap().serialize(rec) {
                eprintln!("error: {:?}", e);
            }
        });
}
