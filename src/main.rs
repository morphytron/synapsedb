#![feature(proc_macro_hygiene, decl_macro)]
#![feature(ip)]
extern crate actix_multipart;
extern crate actix_rt;
extern crate actix_web;
extern crate md5;
extern crate rand_core;
extern crate rand_pcg;
//extern crate ipconfig;
extern crate actix_tls;
extern crate derive_more;
extern crate openssl;
extern crate serde;
extern crate serde_json;
extern crate string_builder;
mod io;
use actix_multipart::{Field, Multipart};
use actix_tls::openssl::{SslAcceptor, SslAcceptorBuilder};
use actix_web::client::{Client, ClientBuilder};
use actix_web::{
    get, guard, http::StatusCode, patch, post, put, web::*, App, HttpRequest, HttpResponse,
    HttpServer, Responder, web
};
use derive_more::AsMut;
use form_data::{handle_multipart, Form};
use futures::{Future, Stream, StreamExt, TryStreamExt};
use io::pufms_io::*;
use md5::{Context, Digest};
use openssl::ssl::{SslFiletype, SslMethod};
use rand_core::{RngCore, SeedableRng};
use rand_pcg::Lcg64Xsh32;
//use ipconfig::Adapter;
use actix_web::http::Method;
use futures::executor::block_on;
use serde::{Deserialize, Serialize};
use std::env;
use std::io::{Error, Result};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use string_builder::Builder;

static help_str: &'static str = r#"
    Warning!  Do not scale up or down aka. do not add or remove nodes while users can add files to the cluster!
    Functionality for easily scaling up and down will be added later...
    -global-url : A domain name or full ip address with https in front and the port, e.g. https://42.244.32.31:444
    -bind : An ipv4 or ipv6 address, e.g., 0.0.0.0
    -port : The application port.
    -connect-to : Works best when connecting to a DNS server for proper load balancing. This is the URL of any of the nodes in a given cluster of nodes.
    -data-folder : the OS path to the data folder: path must be a folder with a '/' at the end of the arg.  E.g. data/
    -node-number-id : the unique identification of this node.  All nodes must be named from 0 through N where N is the number of nodes without any gaps!
    -persist : Saves the arguments passed into synapsedb into a configuration file so that during cluster downtime, the user may restart the nodes without reentering args.
"#;

#[derive(Serialize, Deserialize, Debug)]
pub struct Hashy {
    pub ext: String,
    pub mime: String,
    pub identifiers: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, AsMut, Debug)]
pub struct SharableConfig {
    pub this_node: Node,
    pub other_nodes_id_and_urls: Vec<Node>,
}

pub struct AppState {
    conf: Mutex<SharableConfig>,
    data_path: Mutex<String>,
    application_key : Mutex<String>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RedirectResponse {
    pub node_url: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FileDoesNotExistResponse {
    pub error_code: usize,
    pub message: String,
}

pub trait Hashable {
    fn get_digest(&self) -> Digest;
    fn get_digest_string(digest: Digest) -> String;
}

pub trait FileLocatable {
    fn get_path_and_name<'a>(&self, digest: &String, data_path: &String) -> Result<String>;
    fn write_meta_data<'a>(
        &self,
        file_ext: &str,
        mime: &str,
        data_path_and_name: &String,
    ) -> Result<()>;
    fn read_meta_data(data_path_and_name: &String) -> Result<(String, String)>;
    fn decode_mime<'a>(mime: &str) -> String;
}

pub trait OrganizedConfig {
    fn get_max_identification_num(&self) -> usize;
}

pub trait NodeLocatable {
    fn get_which_node(&self, digest: &String, conf: &SharableConfig) -> Option<Node>;
}

pub trait DeDuping {
    fn de_dupe_config(&mut self, node: &Node);
}

impl NodeLocatable for Hashy {
    /**
     * If it is this node, option unwraps to None.
     */
    fn get_which_node(&self, digest: &String, sc: &SharableConfig) -> Option<Node> {
        let total_nodes = sc.other_nodes_id_and_urls.len() + 1;
        let mut s: [u8; 16] = [0; 16];
        let hash_as_bytes: Vec<u8> = (*digest.clone().into_bytes()).to_vec();
        let mut index = 0;
        for b in s.iter_mut() {
            *b = hash_as_bytes[index];
            index += 1;
        }
        let mut r: Lcg64Xsh32 = Lcg64Xsh32::from_seed(s);
        let val = r.next_u32() as usize;
        let node_number = val % total_nodes;
        println!("Determined node has node_id #{}", node_number);
        if sc.this_node.node_number == node_number {
            return None;
        }
        for node in &sc.other_nodes_id_and_urls {
            if node.node_number == node_number {
                return Some(node.clone());
            }
        }
        eprintln!("No node was found, this will never happen!");
        None
    }
}

impl OrganizedConfig for SharableConfig {
    fn get_max_identification_num(&self) -> usize {
        let mut max = 0;
        for node in &self.other_nodes_id_and_urls {
            if node.node_number > max {
                max = node.node_number;
            }
        }
        max
    }
}

impl FileLocatable for Hashy {
    fn get_path_and_name<'a>(&self, digest: &String, data_path: &String) -> Result<String> {
        let t = format!("{}{}", data_path, digest);
        println!("File name and path is {}", t);
        Ok(t)
    }
    fn decode_mime(mime: &str) -> String {
        let x = mime.replacen("%2F", "/", 5);
        x.to_string()
    }
    fn write_meta_data<'a>(
        &self,
        file_ext: &str,
        mime: &str,
        path_and_name: &String,
    ) -> Result<()> {
        let mut builder = Builder::default();
        builder.append(path_and_name.clone());
        builder.append(".meta");
        let mut builder2 = Builder::default();
        builder2.append(file_ext);
        builder2.append(",");
        builder2.append(mime);
        io::pufms_io::create_and_write_to_file(
            &builder.string().unwrap(),
            builder2.string().unwrap().into_bytes().as_slice(),
        )
    }
    fn read_meta_data(data_path_and_name: &String) -> Result<(String, String)> {
        let mut builder = Builder::default();
        builder.append(data_path_and_name.as_str());
        builder.append(".meta");
        let content = io::pufms_io::read_file(builder.string().unwrap().as_str())?;
        let fext_mime: Vec<String> = String::from_utf8(content)
            .unwrap()
            .split(",")
            .map(|v| v.to_string())
            .collect();
        Ok((fext_mime[0].clone(), fext_mime[1].clone()))
    }
}

impl DeDuping for SharableConfig {
    fn de_dupe_config(&mut self, this_node: &Node) -> () {
        let mut latest = Vec::new();
        self.this_node = this_node.clone();
        for node in &self.other_nodes_id_and_urls {
            let mut count = 0;
            for node2 in &self.other_nodes_id_and_urls {
                if node.node_number == node2.node_number {
                    count += 1;
                }
            }
            if self.this_node.node_number == node.node_number {
                continue;
            }
            if count <= 1 {
                latest.push(node.clone());
            }
        }
        self.other_nodes_id_and_urls = latest;
    }
}

impl Hashable for Hashy {
    fn get_digest(&self) -> Digest {
        let mut builder = Builder::default();
        builder.append(self.ext.clone());
        builder.append(self.mime.clone());
        for s in &self.identifiers {
            builder.append(s.as_bytes());
        }
        md5::compute(builder.string().unwrap())
    }
    fn get_digest_string(d: Digest) -> String {
        format!("{:?}", d)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Node {
    pub node_number: usize,
    pub node_url: String,
}

fn load_ssl() -> SslAcceptorBuilder {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("key.pem", SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file("cert.pem").unwrap();
    builder
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    //defaults
    let mut node_id = 0; //first node
    let mut node_url = "http://0.0.0.0:8088".to_string();
    let mut bind_address = "0.0.0.0".to_string();
    let mut application_key = "thisisthepufapikey".to_string();
    let mut port = "8088".to_string();
    /*match ipconfig::get_adapters() {
        Ok(adaptors) => {
            //println!("{:?}", &adaptors);
            let adaptor = &adaptors[0];
            let addrs = adaptor.ip_addresses();
            for addr in addrs {
                if addr.is_ipv4() && !addr.is_loopback() {
                    node_url = addr.to_string();
                    println!("Auto-sharable node url is {}.  This might be overwritten though...", node_url);
                    break;
                }
            }
        }
        Err(_e) => {
            println!("No adaptors found.");
        }
    }*/
    let mut connect_to = None;
    let mut data_folder = "data/".to_string();
    //read from args
    let args: Vec<String> = env::args().collect();
    let mut offset = 0usize;
    for arg_index in 1..args.len() {
        let index = offset + arg_index;
        if index >= args.len() {
            break;
        }
        let arg = args[offset + arg_index].as_str();
        match arg {
            "-node-number-id" => {
                offset += 1;
                node_id = args[index + 1].as_str().parse::<usize>().unwrap();
            }
            "-public-url" => {
                offset += 1;
                node_url = args[index + 1].clone();
            }
            "-port" => {
                offset += 1;
                port = args[index + 1].clone();
            }
            "-bind" => {
                offset += 1;
                bind_address = args[index + 1].clone();
            }
            "-connect-to" => {
                offset += 1;
                connect_to = Some(args[index + 1].as_str());
            }
            "-api-token" => {
                offset += 1;
                application_key = args[index + 1].clone();
            }
            "-data-folder" => {
                offset += 1;
                data_folder = args[index + 1].clone();
            }
            "-h" => {
                return Ok(print_help());
            }
            "-?" => {
                return Ok(print_help());
            }
            _ => {
                println!("Argument mismatch: {}", arg);
            }
        }
    }
    let z = SharableConfig {
        this_node: Node {
            node_number: node_id,
            node_url: node_url,
        },
        other_nodes_id_and_urls: Vec::new(),
    };
    match connect_to {
        Some(url) => {
            println!("Connecting to node...");
            connect_with_node(&z.this_node, url);
        }
        None => {
            println!("Not connecting to other nodes...");
        }
    }
    let url = format!("{}:{}", bind_address, port);
    println!("Binding server to {}.", url);
    let app_data = Arc::new(AppState {
        conf: Mutex::new(z.clone()),
        data_path: Mutex::new(data_folder.clone()),
        application_key : Mutex::new(application_key)
    });
    HttpServer::new(move || {
        App::new()
            .service(retreive_file)
            .service(write_file)
            .service(add_node)
            .service(get_config)
            .data(app_data.clone())
    })
    .bind_openssl(url, load_ssl())?
    .run()
    .await
}

async fn connect_with_node(this_node: &Node, node_url: &str) -> Result<()> {
    let mut builder: ClientBuilder = Client::build();
    // Create request builder and send request
    let client = builder
        .timeout(std::time::Duration::from_millis(2000))
        .disable_redirects()
        .finish();
    let mut b = Builder::default();
    b.append(node_url);
    b.append("/config/node");
    let request = client.request(Method::POST, b.string().unwrap());
    let client_response = request.send_json(this_node).await;
    println!("Client responded with {:?}", client_response);
    Ok(())
}

fn is_authorized(req : &HttpRequest, state : &Data<Arc<AppState>>) -> bool {
    let headers= req.headers();
    match headers.get("puf-api-token") {
        Some(val) => {
            match state.application_key.lock() {
                Ok(key) => {
                    if key.as_str() != val.to_str().unwrap() {
                        return false;
                    } else {
                        return true
                    }
                }
                Err(_) => {
                    return false;
                }
            }
        }
        None => return false
    }
    false
}


#[get("/config")]
async fn get_config(req : HttpRequest, state: Data<Arc<AppState>>) -> HttpResponse {
    println!("Lands on get config!");
    match is_authorized(&req, &state) {
        true => {
            HttpResponse::Ok().content_type("application/json")
            .body(serde_json::to_string(&*state.conf.lock().unwrap()).unwrap())
        } 
        false => {
            HttpResponse::Unauthorized().finish()
        }
    }
}

#[post("/config/node")]
async fn add_node(req : HttpRequest, node: Json<Node>, state: Data<Arc<AppState>>) -> HttpResponse {
    println!("Lands on add node!");
    match is_authorized(&req, &state) {
        false => {
            return HttpResponse::Unauthorized().finish()
        }
        true => {
            println!("Authorized!");
        }
    }
    let mut guard = state.conf.lock().unwrap();
    println!("unlocked config is {:?}", guard);
    let mut conf_copy = SharableConfig {
        this_node: guard.this_node.clone(),
        other_nodes_id_and_urls: guard.other_nodes_id_and_urls.clone(),
    };
    //let new_node_number = conf_copy.get_max_identification_num() + 1;
    let new_node = Node {
        node_number: node.node_number,
        node_url: node.node_url.clone(),
    };
    conf_copy.other_nodes_id_and_urls.push(new_node);
    //let conf_copy_copy = conf_copy.clone();
    println!("Before dedeupe, conf: {:?}", conf_copy);
    conf_copy.de_dupe_config(&conf_copy.this_node.clone());
    println!("Deduped conf: {:?}", conf_copy);
    *guard = conf_copy;
    HttpResponse::Ok()
        .content_type("application/json")
        .body(serde_json::to_string(&*guard).unwrap())
}

#[post("/upload/{identifiers}")]
async fn write_file(
    req : HttpRequest, 
    mut body: Payload,
    identifiers: Path<String>,
    state: Data<Arc<AppState>>,
) -> HttpResponse {
    println!("Lands in write file function!");
    match is_authorized(&req, &state) {
        false => {
            return HttpResponse::Unauthorized().finish()
        }
        true => {
            println!("Authorized!");
        }
    }
    let mut ids = unsafe { identifiers.split("&id=") };
    let vector: Vec<String> = ids.map(|v| v.to_string()).collect();
    let hashy = Hashy {
        ext: vector[0].clone(),
        mime: Hashy::decode_mime(vector[1].as_str()),
        identifiers: vector[2..].to_vec(),
    };
    drop(vector);
    println!(
        "Identifiers: {:?}. Ext: {}.  Mime: {}",
        hashy.identifiers, hashy.ext, hashy.mime
    );
    let ref digest = hashy.get_digest();
    let guard = &state.data_path.lock().unwrap();
    let data_path = guard.clone();
    drop(guard);
    let c_guard = &state.conf.lock().unwrap();
    let digest = hashy.get_digest();
    let digest_string = Hashy::get_digest_string(digest);
    let x = hashy.get_which_node(&digest_string, c_guard).clone();
    drop(digest);
    drop(c_guard);
    match x {
        Some(node) => {
            HttpResponse::Ok()
                .content_type("application/json")
                //.header("X-Hdr", "sample")
                .body(
                    serde_json::to_string(&RedirectResponse {
                        node_url: node.node_url,
                    })
                    .unwrap(),
                )
        }
        None => {
            print!("This node!\n");
            match hashy.get_path_and_name(&digest_string, &data_path) {
                Ok(file) => {
                    let mut bytes = BytesMut::new();
                    while let Some(item) = body.next().await {
                        bytes.extend_from_slice(&item.unwrap());
                    }
                    match hashy.write_meta_data(hashy.ext.as_str(), hashy.mime.as_str(), &file) {
                        Ok(_) => {
                            match io::pufms_io::create_and_write_to_file(
                                file.as_str(),
                                bytes.as_ref(),
                            ) {
                                Ok(_) => {
                                    format!("Body {:?}!", bytes);
                                    HttpResponse::Ok().body("Uploaded!")
                                }
                                Err(e) => HttpResponse::build(StatusCode::BAD_REQUEST)
                                    .content_type("text/plain")
                                    .body(format!("{:?}", e.kind())),
                            }
                        }
                        Err(e) => HttpResponse::build(StatusCode::BAD_REQUEST)
                            .content_type("text/plain")
                            .body(format!("{:?}", e.kind())),
                    }
                }
                Err(e) => HttpResponse::build(StatusCode::BAD_REQUEST)
                    .content_type("application/json")
                    .body(format!("{:?}", e.kind())),
            }
        }
    }
}

#[get("/dl")]
async fn retreive_file(req : HttpRequest, hashy: Json<Hashy>, state: Data<Arc<AppState>>) -> HttpResponse {
    println!("Lands in retreive_file!");
    match is_authorized(&req, &state) {
        false => {
            return HttpResponse::Unauthorized().finish()
        }
        true => {
            println!("Authorized!");
        }
    }
    let conf = &state.conf.lock().unwrap();
    let data_path = &state.data_path.lock().unwrap();
    let digest = hashy.get_digest();
    let digest_string = Hashy::get_digest_string(digest);
    let x = hashy.get_which_node(&digest_string, &conf);
    drop(digest);
    match x {
        Some(node) => {
            HttpResponse::Ok()
                .content_type("application/json")
                //.header("X-Hdr", "sample")
                .body(
                    serde_json::to_string(&RedirectResponse {
                        node_url: node.node_url,
                    })
                    .unwrap(),
                )
        }
        None => {
            print!("This node!\n");
            match hashy.get_path_and_name(&digest_string, &data_path) {
                Ok(file) => {
                    match read_file(file.as_str()) {
                        Ok(content) => {
                            //read mime type from meta file...
                            println!("Successfully read file!");
                            match Hashy::read_meta_data(&file) {
                                Ok((_ext, mime_type)) => {
                                    HttpResponse::Ok().content_type(mime_type).body(content)
                                }
                                Err(e) => {
                                    eprintln!("Error in creating response: {}", e);
                                    HttpResponse::build(StatusCode::BAD_REQUEST)
                                        .content_type("text/plain")
                                        .body(format!("{:?}", e.kind()))
                                }
                            }
                        }
                        Err(e) => {
                            println!("Could not read file!");
                            HttpResponse::build(StatusCode::BAD_REQUEST)
                                .content_type("text/plain")
                                .body(format!("{:?}", e.kind()))
                        }
                    }
                }
                Err(e) => {
                    println!("Could not get path and name!");
                    HttpResponse::build(StatusCode::BAD_REQUEST)
                        .content_type("text/plain")
                        .body(format!("{:?}", e.kind()))
                }
            }
        }
    }
}

fn print_help() {
    println!("{}", help_str);
}
