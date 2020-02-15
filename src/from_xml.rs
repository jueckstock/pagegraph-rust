use std::fs::File;
use std::io::BufReader;
use std::collections::HashMap;
use std::convert::TryFrom;

use xml::reader::{ EventReader, XmlEvent };
use petgraph::graphmap::DiGraphMap;

use crate::{ graph, types };

/// Reads a PageGraph from a GraphML-formatted file.
pub fn read_from_file(file: &str) -> graph::PageGraph {
    let file = File::open(file).unwrap();
    let file = BufReader::new(file);

    let mut parser = EventReader::new(file);

    if let Ok(XmlEvent::StartDocument { .. }) = parser.next() {
        return parse_xml_document(&mut parser);
    } else {
        panic!("couldn't find start of document");
    }
}

fn parse_xml_document<R: std::io::Read>(parser: &mut EventReader<R>) -> graph::PageGraph {
    if let Ok(XmlEvent::StartElement { name, .. }) = parser.next() {
        if name.local_name == "graphml" {
            return parse_graphml(parser);
        } else {
            panic!("expected graphml element");
        }
    } else {
        panic!("could not find graphml element");
    }
}

fn parse_graphml<R: std::io::Read>(parser: &mut EventReader<R>) -> graph::PageGraph {
    let mut node_items = HashMap::new();
    let mut edge_items = HashMap::new();
    while let Ok(e) = parser.next() {
        match e {
            XmlEvent::StartElement { name, attributes, namespace: _ } => {
                match &name.local_name[..] {
                    "key" => {
                        let (for_type, id, key) = build_key(parser, attributes);
                        match for_type {
                            KeyItemFor::Node => node_items.insert(id, key),
                            KeyItemFor::Edge => edge_items.insert(id, key),
                        };
                    }
                    "graph" => {
                        break;
                    }
                    _ => println!("Unhandled local name: {}", name.local_name),
                }
            }
            XmlEvent::EndElement { name } => {
                if name.local_name == "graphml" {
                    panic!("graphml ended without graph definition");
                } else {
                    panic!("unexpected end of element {}", name);
                }
            }
            XmlEvent::Whitespace(_) => (),
            o => {panic!("unexpected {:?} in `graphml`", o)}
        }
    }

    let key = KeyModel { node_items, edge_items };
    let graph = Some(build_graph(parser, &key));

    while let Ok(e) = parser.next() {
        match e {
            XmlEvent::StartElement { name, attributes: _, namespace: _ } => {
                match &name.local_name[..] {
                    "key" => {
                        panic!("key item located after graph");
                    }
                    "graph" => {
                        panic!("more than one graph item not supported");
                    }
                    _ => println!("Unhandled local name: {}", name.local_name),
                }
            }
            XmlEvent::EndElement { name } => {
                if name.local_name == "graphml" {
                    break
                }
            }
            XmlEvent::Whitespace(_) => (),
            o => {panic!("Unexpected {:?} in `graphml`", o)}
        }
    }

    graph.expect("could not find graph")
}

struct KeyModel {
    node_items: HashMap<String, KeyItem>,
    edge_items: HashMap<String, KeyItem>,
}

struct KeyItem {
    id: String,
    _attr_type: String,
}

enum KeyItemFor {
    Node,
    Edge,
}

impl TryFrom<&str> for KeyItemFor {
    type Error = ();

    fn try_from(v: &str) -> Result<Self, ()> {
        match v {
            "node" => Ok(Self::Node),
            "edge" => Ok(Self::Edge),
            _ => Err(())
        }
    }
}

fn build_key<R: std::io::Read>(
    parser: &mut EventReader<R>,
    attributes: Vec<xml::attribute::OwnedAttribute>
) -> (KeyItemFor, String, KeyItem) {
    let mut id = None;
    let mut for_type = None;
    let mut attr_name = None;
    let mut attr_type = None;
    for attribute in attributes {
        let name = attribute.name.local_name;
        match &name[..] {
            "id" => id = Some(attribute.value),
            "for" => for_type = Some(attribute.value),
            "attr.name" => attr_name = Some(attribute.value),
            "attr.type" => attr_type = Some(attribute.value),
            _ => panic!("Unexpected value in key: {}", &name),
        }
    }
    let key_item = KeyItem {
        id: id.expect("couldn't find `id` value on key"),
        _attr_type: attr_type.expect("couldn't find `attr.type` value on key"),
    };

    if let Ok(XmlEvent::EndElement { name }) = parser.next() {
        if &name.local_name != "key" {
            panic!("expected end of key element");
        }
    } else {
        panic!("could not find end of key element");
    }

    (
        KeyItemFor::try_from(&for_type.expect("couldn't find `for` value on key")[..])
            .expect("unexpected `for` value on key"),
        attr_name.expect("couldn't find `attr.name` value on key"),
        key_item,
    )
}

fn build_graph<R: std::io::Read>(parser: &mut EventReader<R>, key: &KeyModel) -> graph::PageGraph {
    const STR_REP: &'static str = "graph";

    let mut edges = HashMap::new();
    let mut nodes = HashMap::new();
    let mut graph = DiGraphMap::new();

    while let Ok(e) = parser.next() {
        match e {
            XmlEvent::StartElement { name, attributes, namespace: _ } => {
                match &name.local_name[..] {
                    "node" => {
                        let (id, node) = build_node(parser, attributes, &key.node_items);
                        nodes.insert(id, node);
                        graph.add_node(id);
                    }
                    "edge" => {
                        let (id, edge, (source, target)) = build_edge(parser, attributes, &key.edge_items);
                        edges.insert(id, edge);
                        graph.add_edge(source, target, id);
                    }
                    _ => println!("Unhandled local name in {}: {}", STR_REP, name.local_name),
                }
            }
            XmlEvent::EndElement { name } => {
                if name.local_name == STR_REP {
                    break
                }
            }
            XmlEvent::Whitespace(_) => (),
            o => {panic!("Unexpected {:?} in `{}`", o, STR_REP)}
        }
    }

    graph::PageGraph {
        edges,
        nodes,
        graph,
    }
}

fn build_edge<R: std::io::Read>(
    parser: &mut EventReader<R>,
    attributes: Vec<xml::attribute::OwnedAttribute>,
    key: &HashMap<String, KeyItem>
) -> (graph::EdgeId, graph::Edge, (graph::NodeId, graph::NodeId)) {
    const STR_REP: &'static str = "edge";

    let mut id_value = None;
    let mut source_value = None;
    let mut target_value = None;
    let mut edge_type = None;
    let mut edge_timestamp = None;
    let mut data = HashMap::new();
    for attribute in attributes {
        let name = attribute.name.local_name;
        match &name[..] {
            "id" => id_value = Some(attribute.value
                    .trim_start_matches('e')
                    .parse::<usize>()
                    .expect("Parse edge id as usize")
                    .into()
                ),
            "source" => source_value = Some(attribute.value
                    .trim_start_matches('n')
                    .parse::<usize>()
                    .expect("Parse source node id as usize")
                    .into()
                ),
            "target" => target_value = Some(attribute.value
                    .trim_start_matches('n')
                    .parse::<usize>()
                    .expect("Parse target node id as usize")
                    .into()
                ),
            _ => panic!("Unexpected attribute in {}: {}", STR_REP, name),
        }
    }

    while let Ok(e) = parser.next() {
        match e {
            XmlEvent::StartElement { name, attributes, namespace: _ } => {
                match &name.local_name[..] {
                    DataItem::STR_REP => {
                        let data_item = DataItem::build_data(parser, attributes);
                        let contained = data_item.contained;
                        if key.get("edge type").unwrap().id == data_item.key {
                            edge_type = Some(contained.to_string());
                        } else if key.get("id").unwrap().id == data_item.key {
                            let edge_id: graph::EdgeId = contained.parse::<usize>()
                                .expect("parse edge id as usize")
                                .into();
                            if edge_id != id_value.unwrap() {
                                panic!("wrong edge id");
                            }
                        } else if key.get("timestamp").unwrap().id == data_item.key {
                            edge_timestamp = Some(contained
                                .trim_end_matches("0")
                                .trim_end_matches(".")
                                .parse::<isize>()
                                .expect(&format!("parse edge timestamp as isize: {}", contained))
                            );
                        } else {
                            data.insert(data_item.key, contained);
                        }
                    }
                    _ => println!("Unhandled local name in {}: {}", STR_REP, name.local_name),
                }
            }
            XmlEvent::EndElement { name } => {
                if name.local_name == STR_REP {
                    break
                }
            }
            XmlEvent::Whitespace(_) => (),
            o => {panic!("Unexpected {:?} in `{}`", o, STR_REP)}
        }
    }

    let edge_type_attr = &edge_type.as_ref().expect("couldn't find `edge type` attr on node")[..];

    let edge_type = types::EdgeType::construct(edge_type_attr, &mut data, key);
    assert!(data.is_empty(), "extra data on node {:?}: {:?}", edge_type, data);

    let id = id_value.expect("couldn't find `id` value on edge");
    let source = source_value.expect("couldn't find `source` value on edge");
    let target = target_value.expect("couldn't find `target` value on edge");

    let edge_item = graph::Edge {
        edge_type,
        edge_timestamp,
    };

    (id, edge_item, (source, target))
}

fn build_node<R: std::io::Read>(
    parser: &mut EventReader<R>,
    attributes: Vec<xml::attribute::OwnedAttribute>,
    key: &HashMap<String, KeyItem>
) -> (graph::NodeId, graph::Node) {
    const STR_REP: &'static str = "node";

    let mut id_value = None;
    let mut node_type = None;
    let mut node_timestamp = None;
    let mut data = HashMap::new();
    for attribute in attributes {
        let name = attribute.name.local_name;
        match &name[..] {
            "id" => id_value = Some(attribute.value
                    .trim_start_matches('n')
                    .parse::<usize>()
                    .expect("Parse node id as usize")
                    .into()
                ),
            _ => panic!("Unexpected attribute in {}: {}", STR_REP, name),
        }
    }

    while let Ok(e) = parser.next() {
        match e {
            XmlEvent::StartElement { name, attributes, namespace: _ } => {
                match &name.local_name[..] {
                    DataItem::STR_REP => {
                        let data_item = DataItem::build_data(parser, attributes);
                        let contained = data_item.contained;
                        if key.get("node type").unwrap().id == data_item.key {
                            node_type = Some(contained.to_string());
                        } else if key.get("id").unwrap().id == data_item.key {
                            let node_id: graph::NodeId = contained.parse::<usize>()
                                .expect("parse node id as usize")
                                .into();
                            if node_id != id_value.unwrap() {
                                panic!("wrong node id");
                            }
                        } else if key.get("timestamp").unwrap().id == data_item.key {
                            node_timestamp = Some(contained
                                .trim_end_matches("0")
                                .trim_end_matches(".")
                                .parse::<isize>()
                                .expect(&format!("parse node timestamp as isize: {}", contained))
                            );
                        } else {
                            data.insert(data_item.key, contained);
                        }
                    }
                    _ => println!("Unhandled local name in {}: {}", STR_REP, name.local_name),
                }
            }
            XmlEvent::EndElement { name } => {
                if name.local_name == STR_REP {
                    break
                }
            }
            XmlEvent::Whitespace(_) => (),
            o => {panic!("Unexpected {:?} in `{}`", o, STR_REP)}
        }
    }

    let node_type_attr = &node_type.as_ref().expect("couldn't find `node type` attr on node")[..];

    let node_type = types::NodeType::construct(node_type_attr, &mut data, key);
    assert!(data.is_empty(), "extra data on node {:?}: {:?}", node_type, data);

    let id = id_value.expect("couldn't find `id` value on node");
    let node_timestamp = node_timestamp.expect("couldn't find `timestamp` attr on node");

    let node_item = graph::Node {
        node_type,
        node_timestamp,
    };

    (id, node_item)
}

/// Represents a `data` GraphML node, which provides attributes associated with a particular node
/// or edge.
#[derive(Debug, PartialEq)]
struct DataItem {
    key: String,
    contained: String,
}

impl DataItem {
    const STR_REP: &'static str = "data";

    fn build_data<R: std::io::Read>(
        parser: &mut EventReader<R>,
        attributes: Vec<xml::attribute::OwnedAttribute>
    ) -> Self {
        let mut key_value = None;
        let mut contained_value = None;

        for attribute in attributes {
            let name = attribute.name.local_name;
            match &name[..] {
                "key" => key_value = Some(attribute.value),
                _ => panic!("Unexpected attribute in {}: {}", Self::STR_REP, name),
            }
        }

        while let Ok(e) = parser.next() {
            match e {
                XmlEvent::EndElement { name } => {
                    if name.local_name == Self::STR_REP {
                        break
                    }
                }
                XmlEvent::Characters(c) => {
                    contained_value = Some(c);
                }
                XmlEvent::Whitespace(_) => (),
                o => {panic!("Unexpected {:?} in `{}`", o, Self::STR_REP)}
            }
        }

        Self {
            key: key_value.expect("couldn't find `key` value on data"),
            contained: contained_value.unwrap_or_default(),
        }
    }
}

/// Remove and return an attribute from an attribute map according to the key, if present
macro_rules! drain_opt_string_from {
    ( $attrs:ident, $key:ident, $attr:expr ) => {
        $attrs.remove(&$key.get($attr).expect(&format!("could not find `{}` in key", $attr)).id)
    };
}
/// Panic if the attribute string does not exist in the map
macro_rules! drain_string_from {
    ( $attrs:ident, $key:ident, $attr:expr ) => {
        drain_opt_string_from!($attrs, $key, $attr)
            .expect(&format!("attribute `{}` was not present", $attr))
    };
}
/// Panic if the attribute string cannot be parsed as a boolean value
macro_rules! drain_bool_from {
    ( $attrs:ident, $key:ident, $attr:expr ) => {
        drain_string_from!($attrs, $key, $attr)
            .to_ascii_lowercase()
            .parse::<bool>()
            .expect(&format!("could not parse attribute `{}` as bool", $attr))
    };
}
/// Panic if the optional attribute string cannot be parsed as an unsigned numeric value
macro_rules! drain_opt_usize_from {
    ( $attrs:ident, $key:ident, $attr:expr ) => {
        drain_opt_string_from!($attrs, $key, $attr)
            .map(|inner_data| inner_data
                .parse::<usize>()
                .expect(&format!("could not parse attribute `{}` as usize", $attr))
            )
    };
}
/// Panic if the attribute string cannot be parsed as an unsigned numeric value
macro_rules! drain_usize_from {
    ( $attrs:ident, $key:ident, $attr:expr ) => {
        drain_string_from!($attrs, $key, $attr)
            .parse::<usize>()
            .expect(&format!("could not parse attribute `{}` as usize", $attr))
    };
}

/// Allows building this type from a type string and a set of associated attributes, each of which
/// correspond to intelligible string representations through a key.
///
/// Any attributes used will be drained from `attrs`.
trait KeyedAttrs {
    fn construct(type_str: &str, attrs: &mut HashMap<String, String>, key: &HashMap<String, KeyItem>) -> Self;
}

impl KeyedAttrs for types::NodeType {
    fn construct(type_str: &str, attrs: &mut HashMap<String, String>, key: &HashMap<String, KeyItem>) -> Self {
        macro_rules! drain_opt_string {
            ( $attr:expr ) => { drain_opt_string_from!(attrs, key, $attr) }
        }
        macro_rules! drain_string {
            ( $attr:expr ) => { drain_string_from!(attrs, key, $attr) }
        }
        macro_rules! drain_bool {
            ( $attr:expr ) => { drain_bool_from!(attrs, key, $attr) }
        }
        macro_rules! drain_usize {
            ( $attr:expr ) => { drain_usize_from!(attrs, key, $attr) }
        }

        match type_str {
            "extensions" => Self::Extensions {},
            "remote frame" => Self::RemoteFrame {
                url: drain_string!("url")
            },
            "resource" => Self::Resource {
                url: drain_string!("url")
            },
            "ad filter" => Self::AdFilter {
                rule: drain_string!("rule")
            },
            "tracker filter" => Self::TrackerFilter,
            "fingerprinting filter" => Self::FingerprintingFilter,
            "web API" => Self::WebApi {
                method: drain_string!("method")
            },
            "JS builtin" => Self::JsBuiltin {
                method: drain_string!("method")
            },
            "HTML element" => Self::HtmlElement {
                tag_name: drain_string!("tag name"),
                is_deleted: drain_bool!("is deleted"),
                node_id: drain_usize!("node id"),
            },
            "text node" => Self::TextNode{
                text: drain_opt_string!("text"),
                is_deleted: drain_bool!("is deleted"),
                node_id: drain_usize!("node id"),
            },
            "DOM root" => Self::DomRoot {
                url: drain_opt_string!("url"),
                tag_name: drain_string!("tag name"),
                is_deleted: drain_bool!("is deleted"),
                node_id: drain_usize!("node id"),
            },
            "frame owner" => Self::FrameOwner {
                tag_name: drain_string!("tag name"),
                is_deleted: drain_bool!("is deleted"),
                node_id: drain_usize!("node id"),
            },
            "storage" => Self::Storage {},
            "local storage" => Self::LocalStorage {},
            "session storage" => Self::SessionStorage {},
            "cookie jar" => Self::CookieJar {},
            "script" => Self::Script {
                url: drain_opt_string!("url"),
                script_type: drain_string!("script type"),
                script_id: drain_usize!("script id"),
            },
            "parser" => Self::Parser {},
            "Brave Shields" => Self::BraveShields {},
            "ads shield" => Self::AdsShield {},
            "trackers shield" => Self::TrackersShield {},
            "javascript shield" => Self::JavascriptShield {},
            "fingerprinting shield" => Self::FingerprintingShield {},
            _ => panic!("Unknown node type `{}`", type_str),
        }
    }
}

impl KeyedAttrs for types::EdgeType {
    fn construct(type_str: &str, attrs: &mut HashMap<String, String>, key: &HashMap<String, KeyItem>) -> Self {
        macro_rules! drain_opt_string {
            ( $attr:expr ) => { drain_opt_string_from!(attrs, key, $attr) }
        }
        macro_rules! drain_string {
            ( $attr:expr ) => { drain_string_from!(attrs, key, $attr) }
        }
        macro_rules! drain_bool {
            ( $attr:expr ) => { drain_bool_from!(attrs, key, $attr) }
        }
        macro_rules! drain_opt_usize {
            ( $attr:expr ) => { drain_opt_usize_from!(attrs, key, $attr) }
        }
        macro_rules! drain_usize {
            ( $attr:expr ) => { drain_usize_from!(attrs, key, $attr) }
        }

        match type_str {
            "filter" => Self::Filter {},
            "structure" => Self::Structure {},
            "cross DOM" => Self::CrossDom {},
            "resource block" => Self::ResourceBlock {},
            "shield" => Self::Shield {},
            "text change" => Self::TextChange {},
            "remove node" => Self::RemoveNode {},
            "delete node" => Self::DeleteNode {},
            "insert node" => Self::InsertNode {
                parent: drain_usize!("parent"),
                before: drain_opt_usize!("before"),
            },
            "create node" => Self::CreateNode {},
            "js result" => Self::JsResult {
                value: drain_opt_string!("value"),
            },
            "js call" => Self::JsCall {
                args: drain_opt_string!("args"),
            },
            "request complete" => Self::RequestComplete {
                resource_type: drain_string!("resource type"),
                status: drain_string!("status"),
                value: drain_string!("value"),
                response_hash: drain_opt_string!("response hash"),
                request_id: drain_usize!("request id"),
            },
            "request error" => Self::RequestError {
                status: drain_string!("status"),
                request_id: drain_usize!("request id"),
                value: drain_string!("value"),
            },
            "request start" => Self::RequestStart {
                request_type: drain_string!("request type"),
                status: drain_string!("status"),
                request_id: drain_usize!("request id"),
            },
            "request response" => Self::RequestResponse,
            "add event listener" => Self::AddEventListener {
                key: drain_string!("key"),
                event_listener_id: drain_usize!("event listener id"),
                script_id: drain_usize!("script id"),
            },
            "remove event listener" => Self::RemoveEventListener {
                key: drain_string!("key"),
                event_listener_id: drain_usize!("event listener id"),
                script_id: drain_usize!("script id"),
            },
            "event listener" => Self::EventListener{
                key: drain_string!("key"),
                event_listener_id: drain_usize!("event listener id"),
            },
            "storage set" => Self::StorageSet {
                key: drain_string!("key"),
                value: drain_opt_string!("value"),
            },
            "storage read result" => Self::StorageReadResult {
                key: drain_string!("key"),
                value: drain_opt_string!("value"),
            },
            "delete storage" => Self::DeleteStorage {
                key: drain_string!("key"),
            },
            "read storage call" => Self::ReadStorageCall {
                key: drain_string!("key"),
            },
            "clear storage" => Self::ClearStorage,
            "storage bucket" => Self::StorageBucket {},
            "execute from attribute" => Self::ExecuteFromAttribute {
                attr_name: drain_string!("attr name"),
            },
            "execute" => Self::Execute {},
            "set attribute" => Self::SetAttribute {
                key: drain_string!("key"),
                value: drain_opt_string!("value"),
                is_style: drain_bool!("is style"),
            },
            "delete attribute" => Self::DeleteAttribute {
                key: drain_string!("key"),
                is_style: drain_bool!("is style"),
            },
            _ => panic!("Unknown edge type `{}`", type_str),
        }
    }
}