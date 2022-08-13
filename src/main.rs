// TODO: this is kind of absurd, should be impls of OrderedDict
use crate::bencoded::{
    get_integer_if_exists,
    get_list_if_exists, //get_string_if_exists,
    get_string_if_exists_as_utf8_string,
    Bencoded,
};
use anyhow::{bail, Context, Result};
use bencoded::read_bencoded;
use bytes::{Buf, Bytes};
#[allow(unused_imports)]
use log::{debug, error, info, log, trace};
use num_enum::TryFromPrimitive;
use rand::{distributions::Alphanumeric, seq::SliceRandom, thread_rng, Rng};
use reqwest::Url;
use sha1::{Digest, Sha1};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use structopt::StructOpt;
use thiserror::Error;
use tokio::{net::UdpSocket, time::timeout};
use url as url_lib;

mod bencoded;
mod peer_to_peer;

#[derive(StructOpt)]
struct Cli {
    #[structopt(parse(from_os_str))]
    file: PathBuf,
    #[structopt(short, long, parse(from_occurrences))]
    verbose: u8,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    run().await?;
    Ok(())
}

async fn run() -> Result<()> {
    let args = Cli::from_args();
    debug!("Reading file {:?}, Verbosity: {}", args.file, args.verbose);
    let file = File::open(args.file).with_context(|| "Couldn't open file")?;
    let reader = BufReader::new(file);
    let torrent = parse_torrent(reader)?;
    // debug!("parsed torrent: \n{:?}", torrent);
    debug!("info hash: {:x?}", torrent.info_hash);
    let peers = get_peers(&torrent).await?;
    debug!("Got peers {:?}", peers);
    peer_to_peer::interact(peers, torrent, generate_peer_id()).await?;
    Ok(())
}

#[derive(Error, Debug)]
pub enum ParseTorrentError {
    #[error("At the end of the reader, nothing to read")]
    CompletedReader,
    #[error("Max length {0} surpassed")]
    ExceededMaxLength(usize),
    #[error("Found leading zeroes, not following spec")]
    NoLeadingZeroesAllowd,
    #[error("Expected type {exp}, got {got}")]
    WrongTypeInTorrent { exp: String, got: String },
}

#[derive(Debug)]
struct SingleFileInfo {
    length: i64,
    _md5sum: Option<String>,
}

#[derive(Debug)]
struct FileInfo {
    length: i64,
    _md5sum: Option<String>,
    _path: Vec<String>,
}

#[derive(Debug)]
#[allow(dead_code)]
struct Info {
    piece_length: i64,
    pieces: Vec<u8>,
    private: Option<i64>,

    // If there is a single file
    file: Option<SingleFileInfo>,
    // If there are multiple files
    files: Option<Vec<FileInfo>>,
    // This can means two different things: If there is one file, this is it's name.
    // If there are multiple this is the directory the files want to be in.
    name: String,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Torrent {
    info: Info,
    info_hash: Vec<u8>,
    announce: String,
    announce_list: Option<Vec<Vec<String>>>,
    creation_date: Option<i64>,
    comment: Option<String>,
    created_by: Option<String>,
    encoding: Option<String>,
}

impl Info {
    fn total_length(&self) -> Result<i64> {
        if let Some(file) = &self.file {
            return Ok(file.length);
        } else if let Some(files) = &self.files {
            return Ok(files.iter().fold(0i64, |sum, file| sum + file.length));
        }
        bail!("No files in torrent???");
    }
}

fn url_encode_bytes(bytes: &Vec<u8>) -> String {
    // URL encoding arbitary bytes according to bittorrent spec
    // https://wiki.theory.org/BitTorrentSpecification#Tracker_HTTP.2FHTTPS_Protocol
    let unencoded_chars = HashSet::<_>::from_iter(
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-_~"
            .as_bytes()
            .iter(),
    );
    let mut encoded = String::new();
    for byte in bytes {
        if unencoded_chars.contains(&byte) {
            encoded.push(*byte as char);
        } else {
            encoded.push_str(&format!("%{:X?}", byte))
        }
    }
    return encoded;
}

fn build_url(base: &String, torrent: &Torrent) -> Result<reqwest::Url> {
    Url::parse_with_params(
        base,
        vec![
            ("peer_id", "-SD6578"),
            ("info_hash", &url_encode_bytes(&torrent.info_hash)),
            ("port", "6888"),
            ("uploaded", "0"),
            ("downloaded", "0"),
            ("left", &torrent.info.total_length()?.to_string()),
            ("compact", "0"),
            ("event", "started"),
        ],
    )
    .context("Failed to parse announce url and parmeters")
}

async fn contact_tracker_http(url: &String, torrent: &Torrent) -> Result<()> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        bail!("Not a http(s) url");
    }
    debug!("Constructing url");
    let url = build_url(&torrent.announce, &torrent)?;
    let response = reqwest::get(url)
        .await
        .context("Failed to get announce url")?;
    let text = response
        .text()
        .await
        .context("Couldn't read response text")?;
    debug!("Got text: {}", text);
    let decoded_response = read_bencoded(&mut BufReader::new(text.as_bytes()))?;
    if let Some(failure_reason) = get_string_if_exists_as_utf8_string(
        decoded_response.unwrap_dictionary()?,
        "failure reason",
    )? {
        info!("Error from tracker: {}", failure_reason);
        bail!("Tracker responded with error {}", failure_reason);
    }
    dbg!(decoded_response);
    Ok(())
}
#[allow(dead_code)]
#[derive(Debug)]
pub struct Peer {
    ip: Ipv4Addr,
    port: u16,
    choked: bool,
    interested: bool,
    am_choking: bool,
    am_interseted: bool,
}

impl Peer {
    fn new(ip: Ipv4Addr, port: u16) -> Self {
        Self {
            ip,
            port,
            choked: true,
            interested: false,
            am_choking: true,
            am_interseted: true,
        }
    }
}

#[derive(PartialEq, TryFromPrimitive)]
#[repr(i32)]
enum AnnounceEvent {
    None = 0,
    Completed = 1,
    Started = 2,
    Stopped = 3,
}

#[derive(PartialEq, TryFromPrimitive)]
#[repr(i32)]
enum AnnounceAction {
    Connect = 0,
    Announce = 1,
}

fn choose_listen_port() -> i16 {
    return 6881;
}

async fn create_udp_socket(url: &str) -> Result<UdpSocket> {
    let socket = UdpSocket::bind("0.0.0.0:7686")
        .await
        .context("failed to create udp socket")?;
    debug!("connecting to {}, socket: {:?}", url, socket);
    let parsed_url = url_lib::Url::parse(url)?;
    debug!("Parsed url: {:?}", parsed_url);
    let socket_addr = parsed_url.socket_addrs(|| None)?.pop().unwrap();
    socket.connect(socket_addr).await?;
    debug!("Connected successfully, socket: {:?}", socket);
    Ok(socket)
}

async fn connect_udp(socket: &UdpSocket) -> Result<i64> {
    // Gets connection id using the socket
    let mut packet = Vec::<u8>::with_capacity(64 + 32 + 32);
    let protocol_id = 0x41727101980i64;
    let action = AnnounceAction::Connect as i32;
    let transaction_id = rand::random::<i32>();
    packet.extend(protocol_id.to_be_bytes());
    packet.extend(action.to_be_bytes());
    packet.extend(transaction_id.to_be_bytes());
    debug!("Sending initial udp packet to tracker");
    socket
        .send(&packet)
        .await
        .context("Couldn't send udp message")?;
    const MAX_RESPONSE_SIZE: usize = 1500; //MTU
    let mut buf = [0; MAX_RESPONSE_SIZE];
    let bytes_read = timeout(
        tokio::time::Duration::from_millis(500),
        socket.recv(&mut buf),
    )
    .await
    .context("timedout waitng for tracker")?
    .context("Couldn't receive data")?;
    debug!("Read {} bytes", bytes_read);
    let mut response = Bytes::from(Box::from(&buf[..bytes_read]));
    if response.len() < 16 {
        error!("Invalid packet: too small");
        bail!("Invalid packet: too small");
    }

    let action = response.get_i32();
    if AnnounceAction::try_from_primitive(action) != Ok(AnnounceAction::Connect) {
        error!(
            "Got wrong action: sent {}, received {}",
            AnnounceAction::Connect as i32,
            action
        );
        bail!("")
    }
    let received_transaction_id = response.get_i32();
    if received_transaction_id.ne(&transaction_id) {
        bail!(
            "Wrong transaction id: expected {:X}, got {:X}",
            transaction_id,
            received_transaction_id
        );
    }
    let connection_id = response.get_i64();
    return Ok(connection_id);
}

async fn announce_udp(
    socket: &UdpSocket,
    connection_id: i64,
    torrent: &Torrent,
) -> Result<Vec<Peer>> {
    let mut packet = Vec::<u8>::with_capacity(96);
    let action = AnnounceAction::Announce as i32;
    let transaction_id = rand::random::<i32>();
    let info_hash = &torrent.info_hash;
    let peer_id = generate_peer_id();
    debug!("Peer ID: {}", String::from_utf8_lossy(&peer_id));
    let downlaoded = 0i64;
    let left = torrent.info.total_length()?;
    let uploaded = 0i64;
    let event = AnnounceEvent::Started as i32;
    let ip_address = 0i32;
    let key = 0i32;
    let num_want = -1i32;
    let port = choose_listen_port();
    packet.extend(connection_id.to_be_bytes());
    packet.extend(action.to_be_bytes());
    packet.extend(transaction_id.to_be_bytes());
    packet.extend(info_hash);
    packet.extend(peer_id);
    packet.extend(downlaoded.to_be_bytes());
    packet.extend(left.to_be_bytes());
    packet.extend(uploaded.to_be_bytes());
    packet.extend(event.to_be_bytes());
    packet.extend(ip_address.to_be_bytes());
    packet.extend(key.to_be_bytes());
    packet.extend(num_want.to_be_bytes());
    packet.extend(port.to_be_bytes());
    socket
        .send(&packet)
        .await
        .context("Couldn't send udp message")?;

    const MAX_RESPONSE_SIZE: usize = 1500;
    let mut response = [0; MAX_RESPONSE_SIZE];
    let bytes_read = socket
        .recv(&mut response)
        .await
        .context("Couldn't receive data")?;
    debug!("Read {} bytes", bytes_read);
    let mut response = Bytes::from(Box::from(&response[..bytes_read]));
    if response.len() < 20 {
        error!("Invalid packet: too small");
        bail!("Invalid packet: too small");
    }
    debug!("{:?}", response);
    let action = response.get_i32();
    if AnnounceAction::try_from_primitive(action) != Ok(AnnounceAction::Announce) {
        error!(
            "Got wrong action: sent {}, received {}",
            AnnounceAction::Announce as i32,
            action
        );
        bail!("Wrong action")
    }

    let received_transaction_id = response.get_i32();
    if transaction_id.ne(&received_transaction_id) {
        bail!(
            "Wrong transaction_id: expected {} got {}",
            transaction_id,
            received_transaction_id
        );
    }
    let interval = response.get_i32();
    let leechers = response.get_i32();
    let seeders = response.get_i32();
    let peers_count = response.remaining() / 6;
    debug!(
        "{} peers, {} leechers, {} seeders",
        peers_count, leechers, seeders
    );
    debug!("interval {interval}");
    let mut peers: Vec<Peer> = Vec::with_capacity(peers_count);
    for _ in 1..peers_count {
        let ip = Ipv4Addr::new(
            response.get_u8(),
            response.get_u8(),
            response.get_u8(),
            response.get_u8(),
        );
        let port = response.get_u16();
        peers.push(Peer::new(ip, port));
    }
    Ok(peers)
}

fn generate_peer_id() -> Vec<u8> {
    // Is there a better peer id to use? should this be randomised as well?
    // https://www.bittorrent.org/beps/bep_0020.html
    let mut peer_id = "-DY0001-".as_bytes().to_vec();
    peer_id.extend(
        &thread_rng()
            .sample_iter(Alphanumeric)
            .take(12)
            .collect::<Vec<u8>>(),
    );
    peer_id
}

async fn try_url(url: &String, torrent: &Torrent) -> Result<Vec<Peer>> {
    if url.starts_with("udp://") {
        debug!("url {:?} is udp", url);
        // According to spec https://www.bittorrent.org/beps/bep_0015.html
        let socket = create_udp_socket(&url).await?;
        let connection_id = connect_udp(&socket).await?;
        debug!("Got connection id {} from {}", connection_id, url);
        let peers = announce_udp(&socket, connection_id, torrent).await?;
        return Ok(peers);
    } else if url.starts_with("http") {
        // todo!();
        debug!("url {:?} is http", url);
        contact_tracker_http(url, torrent).await?;
    }
    bail!("Unkown url, couldn't announce");
}

async fn get_peers(torrent: &Torrent) -> Result<Vec<Peer>> {
    // Spec: https://www.bittorrent.org/beps/bep_0012.html
    info!("Trying announce {}", torrent.announce);
    match try_url(&torrent.announce, &torrent).await {
        Ok(peers) => return Ok(peers),
        Err(err) => info!("Failed to get url {} : {}", torrent.announce, err),
    }
    if let Some(ref announce_list) = torrent.announce_list {
        info!("Trying trackers from announce list");
        for tier in announce_list {
            let mut tier = tier.clone();
            tier.shuffle(&mut thread_rng());
            for tracker in tier {
                debug!("Trying tracker {}", tracker);
                match try_url(&tracker, torrent).await {
                    Ok(peers) => return Ok(peers),
                    Err(err) => info!("Failed to get url {} : {}", tracker, err),
                }
            }
        }
    }
    bail!("Failed to get peers");
}

fn parse_torrent(reader: impl BufRead) -> Result<Torrent> {
    let buf_reader = BufReader::new(reader);
    let mut reader = buf_reader;
    let torrent_dict = read_bencoded(&mut reader).context("Failed to parse bencoded")?;
    // debug!("{}", torrent_dict);
    match torrent_dict {
        Bencoded::Dictionary(ref map) => {
            if !map.contains_key("announce") {
                bail!("No announce key, invalid torrent");
            }
            let announce = map.get("announce").unwrap().unwrap_string_as_utf8()?;
            let creation_date = get_integer_if_exists(map, "creation date")?;
            let comment = get_string_if_exists_as_utf8_string(map, "comment")?;
            let created_by = get_string_if_exists_as_utf8_string(map, "created by")?;
            let encoding = get_string_if_exists_as_utf8_string(map, "encoding")?;

            let announce_list = match get_list_if_exists(map, "announce-list")? {
                None => None,
                Some(bencoded_tracker_tiers) => {
                    let mut tiers: Vec<Vec<String>> = Vec::new();
                    for bencoded_tier in bencoded_tracker_tiers {
                        let mut tier = Vec::new();
                        for tracker in bencoded_tier.unwrap_list()? {
                            tier.push(tracker.unwrap_string_as_utf8()?);
                        }
                        tiers.push(tier);
                    }
                    Some(tiers)
                }
            };

            if !map.contains_key("info") {
                bail!("No info dictionary, invalid torrent");
            }
            let raw_info = map.get("info").unwrap();
            let mut hasher = Sha1::new();
            hasher.update(raw_info.encode());
            let info_hash = hasher.finalize().to_vec();

            let info = raw_info.unwrap_dictionary()?;
            if !info.contains_key("piece length") {
                bail!("No piece length in info dict")
            }
            let piece_length = info.get("piece length").unwrap().unwrap_integer()?;
            let pieces = info.get("pieces").unwrap().unwrap_string()?;
            let private: Option<i64> = get_integer_if_exists(info, "private")?;

            // Multiple files mode
            if info.contains_key("files") {
                if !info.contains_key("name") {
                    bail!("No name for directory");
                }
                let direcotry = info.get("name").unwrap().unwrap_string_as_utf8()?;
                let files = info.get("files").unwrap().unwrap_list()?;
                let mut file_list = Vec::<FileInfo>::new();
                for file in files.iter() {
                    let file = file.unwrap_dictionary()?;
                    if !file.contains_key("length") {
                        bail!("No length for file");
                    }
                    let length = file.get("length").unwrap().unwrap_integer()?;
                    let md5sum = file
                        .get_string_if_exists("md5sum")?
                        .as_ref()
                        .map(|vec| String::from_utf8_lossy(vec).to_string());
                    if !file.contains_key("path") {
                        bail!("No path for file");
                    }
                    let path = file.get("path").unwrap().unwrap_list()?;
                    let mut path_parts = Vec::<String>::new();
                    for bencoded_part in path.iter() {
                        let part = bencoded_part.unwrap_string_as_utf8()?;
                        path_parts.push(part);
                    }
                    file_list.push(FileInfo {
                        length,
                        _md5sum: md5sum,
                        _path: path_parts,
                    })
                }
                return Ok(Torrent {
                    announce,
                    announce_list,
                    comment,
                    created_by,
                    creation_date,
                    encoding,
                    info: Info {
                        private,
                        piece_length,
                        pieces,
                        file: None,
                        files: Some(file_list),
                        name: direcotry,
                    },
                    info_hash,
                });
            }
            // Single file mode
            else {
                if !info.contains_key("name") {
                    bail!("No name for file");
                }
                let name = info.get("name").unwrap().unwrap_string_as_utf8()?;
                if !info.contains_key("length") {
                    bail!("no length contained for file");
                }
                let length = info.get("length").unwrap().unwrap_integer()?;
                let md5sum = get_string_if_exists_as_utf8_string(info, "md5sum")?;
                return Ok(Torrent {
                    announce,
                    announce_list,
                    comment,
                    created_by,
                    creation_date,
                    encoding,
                    info: Info {
                        private,
                        piece_length,
                        pieces,
                        file: Some(SingleFileInfo {
                            length,
                            _md5sum: md5sum,
                        }),
                        files: None,
                        name,
                    },
                    info_hash,
                });
            }
        }
        _ => {
            bail!("Not a dictionary, an invalid torrent file");
        }
    }
}

#[cfg(test)]
mod torrent_tests {
    use crate::url_encode_bytes;
    #[test]
    fn encoding_bytes() {
        let bytes: Vec<u8> = vec![
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
            0xef, 0x12, 0x34, 0x56, 0x78, 0x9a,
        ];
        let encoded = url_encode_bytes(&bytes);
        assert_eq!(&encoded, "%124Vx%9A%BC%DE%F1%23Eg%89%AB%CD%EF%124Vx%9A")
    }
}
