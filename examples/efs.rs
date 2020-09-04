use std::sync::Mutex;

use rayon::prelude::*;

use pagegraph::from_xml::read_from_file;
use pagegraph::types::NodeType;

#[macro_use]
extern crate serde_derive;

#[derive(Debug, Serialize)]
struct FeatureVector {
    site_tag: String,
    profile_tag: String,
    base_name: String,
    is_root: bool,
    frame_etld1: Option<String>,
    frame_url: String,
    remote_frames: usize,
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

fn main() {
    let graph_files = std::env::args().skip(1).collect::<Vec<String>>();
    if graph_files.len() == 0 {
        eprintln!("usage: {0} GRAPHML_FILE [GRAPHML_FILE ...]", std::env::args().take(1).next().expect("no argv[0]?!"));
    }

    let psl = publicsuffix::List::from_path("public_suffix_list.dat").expect("unable to read `public_suffix_list.dat`");

    let wtr = csv::Writer::from_writer(std::io::stdout());
    let wtr_mut = Mutex::new(wtr);
    
    graph_files.into_par_iter()
        .filter_map(|filename| {
            let graph = read_from_file(&filename);
            match graph.meta {
                Some(_) => Some((filename, graph)),
                _ => None,
            }
        })
        .for_each(|(filename, graph)| {
            let fpath = std::path::Path::new(&filename);
            let fcoms: Vec<_> = fpath.components().rev().take(4).map(|c| match c { 
                std::path::Component::Normal(nn) => nn.to_str().expect("bad filename (not utf8)").to_owned(), 
                _ => panic!("bad filename") }).collect();
            let url_tag = &fcoms[1];
            let host_name = &fcoms[2];
            let profile_name = &fcoms[3];

            let remote_frames = graph.filter_nodes(|nt| match nt {
                NodeType::RemoteFrame { .. } => true,
                _ => false,
            });

            let (is_root, frame_url) = match graph.meta {
                Some(ref meta) => (meta.is_root, meta.url.clone()),
                _ => panic!("oh noes"),
            };

            let rec = FeatureVector {
                site_tag: format!("{0}/{1}", host_name, url_tag),
                profile_tag: profile_name.clone(),
                base_name: fcoms[0].clone(),
                is_root: is_root,
                frame_etld1: url_host_etld1(&frame_url, &psl),
                frame_url: frame_url,
                remote_frames: remote_frames.len(),
            };

            if let Err(e) = wtr_mut.lock().unwrap().serialize(rec) {
                eprintln!("error: {:?}", e);
            }
        });
}
