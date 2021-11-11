#[macro_use]
extern crate error_chain;

use log::{debug, error, info, log, trace};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::io::BufReader;
use std::io::{BufRead, Read};
use std::iter::FromIterator;
use std::path::PathBuf;
use structopt::StructOpt;

mod errors {
    error_chain! {
        errors {
            CompletedReader {
                description("At the end of the reader, nothing to read")
                display("Nothing to read")
            }
            ExceededMaxLength(length: usize) {
                description("Exceeded the max length of reading specified")
                display("Max length {} surpassed", length)
            }
            NoLeadingZeroesAllowd {
                description("Bencoded integers can't have leading zeroes before them")
                display("Leading zeroes found")
            }
            WrongTypeInTorrent(found: String) {
                description("Wrong type in torrent")
                display("The value {} is the wrong type", found)
            }
            Error
        }
    }
}
use errors::*;

#[derive(StructOpt)]
struct Cli {
    #[structopt(parse(from_os_str))]
    file: PathBuf,
    #[structopt(short, long, parse(from_occurrences))]
    verbose: u8,
}

#[derive(PartialEq, Eq, Clone)]
struct OrderdDict<V> {
    inner: HashMap<String, V>,
    keys: Vec<String>,
}

impl<V: Debug> std::fmt::Debug for OrderdDict<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrderdDict")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<V> OrderdDict<V> {
    fn new() -> Self {
        Self {
            inner: HashMap::new(),
            keys: Vec::new(),
        }
    }

    fn keys(&self) -> Vec<String> {
        return self.keys.clone();
    }
    fn get(&self, key: &str) -> Option<&V> {
        self.inner.get(&key.to_string())
    }

    fn contains_key(&self, key: &str) -> bool {
        self.keys.contains(&key.to_string())
    }

    fn insert(&mut self, key: &str, value: V) {
        // No need to check if key is already present, we're fine with duplicate keys
        self.inner.insert(key.to_string(), value);
        self.keys.push(key.to_string())
    }
}

#[derive(PartialEq, Eq, Clone)]
enum Bencoded {
    Integer(i64),
    String(Vec<u8>),
    List(Vec<Bencoded>),
    Dictionary(OrderdDict<Bencoded>),
}

impl std::fmt::Display for Bencoded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Bencoded::Integer(i) => {
                write!(f, "{}", i)?;
            }
            Bencoded::String(vec) => {
                if let Ok(str) = String::from_utf8(vec.to_vec()) {
                    write!(f, "{}", str)?;
                } else {
                    for byte in vec.iter().take(20) {
                        write!(f, "{:#x}", byte)?;
                    }
                };
            }
            Bencoded::List(list) => {
                write!(f, "[")?;
                for item in list.iter() {
                    write!(f, "{}, ", item)?;
                }
                write!(f, "]")?;
            }
            Bencoded::Dictionary(dict) => {
                write!(f, "{{ ")?;
                for key in dict.keys() {
                    write!(f, "{}: {}, ", key, dict.get(&key).unwrap())?;
                }
                write!(f, "}}")?;
            }
        };
        Ok(())
    }
}

impl std::fmt::Debug for Bencoded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Integer(arg0) => f.debug_tuple("Integer").field(arg0).finish(),
            Self::String(arg0) => f
                .debug_tuple("String")
                .field(&String::from_utf8_lossy(arg0))
                .finish(),
            Self::List(arg0) => f.debug_tuple("List").field(arg0).finish(),
            Self::Dictionary(arg0) => f.debug_tuple("Dictionary").field(arg0).finish(),
        }
    }
}

impl Bencoded {
    fn unwrap_integer(&self) -> Result<i64> {
        match self {
            Bencoded::Integer(val) => Ok(*val),
            _ => Err(errors::ErrorKind::WrongTypeInTorrent("Integer".into()).into()),
        }
    }
    fn unwrap_string(&self) -> Result<Vec<u8>> {
        match self {
            Bencoded::String(val) => Ok(val.to_vec()),
            _ => Err(errors::ErrorKind::WrongTypeInTorrent("String".into()).into()),
        }
    }

    fn unwrap_string_as_utf8(&self) -> Result<String> {
        match self {
            Bencoded::String(val) => Ok(String::from_utf8(val.to_vec())
                .chain_err(|| "failed converting to utf8 encoded string")?),
            _ => Err(errors::ErrorKind::WrongTypeInTorrent("String".into()).into()),
        }
    }
    fn unwrap_list(&self) -> Result<Vec<Bencoded>> {
        match self {
            Bencoded::List(val) => Ok(val.to_vec()),
            _ => Err(errors::ErrorKind::WrongTypeInTorrent("List".into()).into()),
        }
    }
    fn unwrap_dictionary(&self) -> Result<&OrderdDict<Bencoded>> {
        match self {
            Bencoded::Dictionary(val) => Ok(val),
            _ => Err(errors::ErrorKind::WrongTypeInTorrent("Dictionary".into()).into()),
        }
    }
}

impl Bencoded {
    fn encode(&self) -> Vec<u8> {
        match self {
            Bencoded::Integer(num) => format!("i{}e", num).as_bytes().to_vec(),
            Bencoded::String(st) => [st.len().to_string().as_bytes(), &[':' as u8], st].concat(),
            Bencoded::List(list) => {
                let mut chars = list.iter().flat_map(|i| i.encode()).collect::<Vec<u8>>();
                chars.insert(0, 'l' as u8);
                chars.push('e' as u8);
                chars
            }
            Bencoded::Dictionary(dict) => {
                let mut vec = vec!['d' as u8];
                for key in dict.keys() {
                    vec.append(&mut Bencoded::String(key.as_bytes().to_vec()).encode());
                    vec.append(&mut dict.get(&key).unwrap().encode());
                }
                vec.push('e' as u8);
                vec
            }
        }
    }
}

fn get_string_if_exists(map: &OrderdDict<Bencoded>, key: &str) -> Result<Option<Vec<u8>>> {
    if map.contains_key(key) {
        Ok(Some(map.get(key).unwrap().unwrap_string()?))
    } else {
        Ok(None)
    }
}

fn get_string_if_exists_as_utf8_string(
    map: &OrderdDict<Bencoded>,
    key: &str,
) -> Result<Option<String>> {
    if map.contains_key(key) {
        Ok(Some(map.get(key).unwrap().unwrap_string_as_utf8()?))
    } else {
        Ok(None)
    }
}

fn get_integer_if_exists(map: &OrderdDict<Bencoded>, key: &str) -> Result<Option<i64>> {
    if map.contains_key(key) {
        Ok(Some(map.get(key).unwrap().unwrap_integer()?))
    } else {
        Ok(None)
    }
}

fn get_list_if_exists(map: &OrderdDict<Bencoded>, key: &str) -> Result<Option<Vec<Bencoded>>> {
    if map.contains_key(key) {
        Ok(Some(map.get(key).unwrap().unwrap_list()?))
    } else {
        Ok(None)
    }
}

fn main() {
    env_logger::init();
    if let Err(ref e) = run() {
        error!("error: {}", e);

        // Showng error chain
        for e in e.iter().skip(1) {
            error!("caused by: {}", e);
        }

        if let Some(backtrace) = e.backtrace() {
            error!("backtrace: {:?}", backtrace);
        }

        ::std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Cli::from_args();
    debug!("Reading file {:?}, Verbosity: {}", args.file, args.verbose);
    let file = File::open(args.file).chain_err(|| "Couldn't open file")?;
    let reader = BufReader::new(file);
    let torrent = parse_torrent(reader)?;
    // debug!("parsed torrent: \n{:?}", torrent);
    debug!("info hash: {:x?}", torrent.info_hash);
    Ok(())
}

#[derive(Debug)]
struct SingleFileInfo {
    length: i64,
    md5sum: Option<String>,
}

#[derive(Debug)]
struct FileInfo {
    length: i64,
    md5sum: Option<String>,
    path: Vec<String>,
}

#[derive(Debug)]
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

#[derive(Debug)]
struct Torrent {
    info: Info,
    info_hash: Vec<u8>,
    announce: String,
    announce_list: Option<Vec<Vec<String>>>,
    creation_date: Option<i64>,
    comment: Option<String>,
    created_by: Option<String>,
    encoding: Option<String>,
}

fn parse_torrent(reader: impl BufRead) -> Result<Torrent> {
    let buf_reader = BufReader::new(reader);
    let mut reader = buf_reader;
    let torrent_dict = read_bencoded(&mut reader).chain_err(|| "Failed to parse bencoded")?;
    debug!("{}", torrent_dict);
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
                    let md5sum = get_string_if_exists(file, "md5sum")?
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
                        md5sum,
                        path: path_parts,
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
                        file: Some(SingleFileInfo { length, md5sum }),
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

fn read_bencoded(reader: &mut BufReader<impl BufRead>) -> Result<Bencoded> {
    // This parsing is based on this spec: https://wiki.theory.org/BitTorrentSpecification

    let first_ch = *read_bytes(reader, 1)?.get(0).unwrap() as char;
    // Strings start with a number signifying it's length.
    // For example '4:rick' is the string "rick" with length 4
    if first_ch.is_ascii_digit() {
        debug!("Found a digit, detected a string");
        // This max length is ridiculous, I doubt it's usefull
        let mut bytes = read_until(reader, ':' as u8, Some(usize::MAX))?;
        bytes.insert(0, first_ch as u8);
        let digit_chars = bytes.iter().map(|c| *c as char);
        let string_length = String::from_iter(digit_chars);
        let length = string_length
            .parse::<usize>()
            .chain_err(|| "couldn't parse number")?;
        debug!("Reading {} characters", string_length);
        let actual_string = read_bytes(reader, length)?;
        let str = Bencoded::String(actual_string);
        debug!("{}", str);
        return Ok(str);
    }
    // Numbers are in this format: 'ixxe', for example i456e is the number 456.
    else if first_ch == 'i' {
        let mut number_string = String::new();
        let mut digit_count = 0;
        loop {
            // Stop if number is more than 64 bit
            if digit_count > 20 {
                bail!("Too large numbers (> 64 bit)")
            }
            let ch = *read_bytes(reader, 1)?.get(0).unwrap() as char;
            if digit_count >= 1 && ch == 'e' {
                let number = number_string
                    .parse::<i64>()
                    .chain_err(|| "Couldnt convert to number")?;
                return Ok(Bencoded::Integer(number));
            }
            if !ch.is_ascii_digit() {
                bail!("Invalid file: non digits in a number");
            }
            number_string.push(ch);
            digit_count += 1;
            if digit_count > 1 && number_string.starts_with('0') {
                return Err(errors::ErrorKind::NoLeadingZeroesAllowd.into());
            }
        }
    }
    // Lists start with l and enf with an e
    else if first_ch == 'l' {
        debug!("Found list");
        let mut items = Vec::<Bencoded>::new();
        let mut current_item: Result<Bencoded>;
        loop {
            if peek_one_byte(reader)? as char == 'e' {
                read_one_byte(reader)?;
                return Ok(Bencoded::List(items));
            }
            current_item = read_bencoded(reader);
            match current_item {
                Err(err) => match err {
                    errors::Error(errors::ErrorKind::CompletedReader, _) => {
                        return Ok(Bencoded::List(items));
                    }
                    errors::Error(_, _) => {
                        return Err(err);
                    }
                },
                Ok(value) => {
                    items.push(value);
                }
            }
        }
    }
    // This is a dictionary
    else if first_ch == 'd' {
        debug!("Found dictionary");
        let mut dict = OrderdDict::new();
        loop {
            if peek_one_byte(reader)? as char == 'e' {
                read_one_byte(reader)?;
                return Ok(Bencoded::Dictionary(dict));
            }
            debug!("Trying to read key");
            let bencoded_key = read_bencoded(reader)?;
            if let Bencoded::String(key) = bencoded_key {
                // Keys are specified by the format so I assume they are actual utf8 strings
                let key = String::from_utf8(key)
                    .chain_err(|| "Bad assumption: This key is not utf8??")?;
                debug!("Found key \"{}\", reading value", key);
                let value = read_bencoded(reader)?;
                debug!("Found value {}. Inserting...", value);
                dict.insert(&key, value);
            } else {
                bail!("Only Strings are can be keys in becoded dictionaries")
            }
        }
    }
    bail!("Couldn't find valid Bencoded value");
}

#[cfg(test)]
mod bencoded_tests {
    use crate::{errors::*, OrderdDict};
    use crate::{read_bencoded, Bencoded};
    use std::collections::HashMap;
    use std::io::BufReader;

    #[test]
    fn reading_zero() {
        let mut reader = BufReader::new("i0e".as_bytes());
        let value = read_bencoded(&mut reader).unwrap();
        assert_eq!(value, Bencoded::Integer(0));
    }
    #[test]
    fn no_leading_zeroes_allowd() {
        let mut reader = BufReader::new("i045e".as_bytes());
        match read_bencoded(&mut reader) {
            Err(err) => match err.kind() {
                ErrorKind::NoLeadingZeroesAllowd => {}
                _ => panic!("Got wrong error: {}", err.kind()),
            },
            Ok(val) => {
                panic!("Got {} instead of error", val);
            }
        }
    }
    #[test]
    fn zero_length_string() {
        let mut reader = BufReader::new("0:".as_bytes());
        let result = read_bencoded(&mut reader).unwrap();
        assert_eq!(result, Bencoded::String(vec![]));
    }

    #[test]
    fn empty_list() {
        let mut reader = BufReader::new("le".as_bytes());
        let result = read_bencoded(&mut reader).unwrap();
        assert_eq!(result, Bencoded::List(vec![]));
    }

    #[test]
    fn list_in_list_list() {
        let mut reader = BufReader::new("llleee".as_bytes());
        let expected = Bencoded::List(vec![Bencoded::List(vec![Bencoded::List(vec![])])]);
        let result = read_bencoded(&mut reader).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn different_types_in_list() {
        let mut reader = BufReader::new("li45e3:firdee".as_bytes());
        let expected = Bencoded::List(vec![
            Bencoded::Integer(45),
            Bencoded::String("fir".as_bytes().to_vec()),
            Bencoded::Dictionary(OrderdDict::new()),
        ]);
        let result = read_bencoded(&mut reader).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn encode_decode() {
        let st = "d5:ewsdfli45e3:firdeee".as_bytes();
        let mut reader = BufReader::new(st);
        assert_eq!(read_bencoded(&mut reader).unwrap().encode(), st);
    }
}

fn read_bytes(reader: &mut BufReader<impl BufRead>, count: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0; count];
    let mut bytes_read = reader.read(&mut buf).chain_err(|| "Failed to read bytes")?;
    while bytes_read < count && bytes_read != 0 {
        buf.resize(bytes_read, 0);
        debug!(
            "Tried reading {} bytes, read {} until now",
            count, bytes_read
        );
        let mut new_buf = vec![0; count - bytes_read];
        bytes_read += reader
            .read(&mut new_buf)
            .chain_err(|| "Failed to read bytes")?;
        buf.append(&mut new_buf);
    }
    Ok(buf)
}

fn read_one_byte(reader: &mut BufReader<impl BufRead>) -> Result<u8> {
    Ok(*read_bytes(reader, 1)?.get(0).unwrap())
}

fn peek_bytes(reader: &mut BufReader<impl BufRead>, byte_count: usize) -> Result<Vec<u8>> {
    let buf = reader.fill_buf().chain_err(|| "Failed to peek")?;
    if buf.len() < byte_count {
        return Err(errors::ErrorKind::CompletedReader.into());
    }
    return Ok(buf.get(0..byte_count).unwrap().to_vec());
}

fn peek_one_byte(reader: &mut BufReader<impl BufRead>) -> Result<u8> {
    Ok(*peek_bytes(reader, 1)?.get(0).unwrap())
}

#[cfg(test)]
mod reader_tests {
    use crate::{peek_bytes, peek_one_byte, read_bytes, read_one_byte};
    use std::io::BufReader;

    #[test]
    fn reading_one_ascii_char() {
        let mut reader = BufReader::new("First".as_bytes());
        let ch = read_one_byte(&mut reader).unwrap() as char;
        assert_eq!(ch, 'F');
    }

    #[test]
    fn peek_one_doesnt_consume() {
        let mut reader = BufReader::new("Repeating".as_bytes());
        let _peeked1 = peek_one_byte(&mut reader).unwrap();
        let _peeked2 = peek_one_byte(&mut reader).unwrap();
        let peeked3 = peek_one_byte(&mut reader).unwrap();
        let consumed = read_one_byte(&mut reader).unwrap();
        assert_eq!(peeked3, consumed);
    }

    #[test]
    fn peek_multiple_bytes() {
        let mut reader = BufReader::new("In a galaxy far far away".as_bytes());
        let chunk = peek_bytes(&mut reader, 15).unwrap();
        let consumed_chunk = read_bytes(&mut reader, 15).unwrap();
        assert_eq!(
            chunk
                .iter()
                .zip(consumed_chunk.iter())
                .filter(|&(a, b)| a == b)
                .count(),
            chunk.len()
        );
    }

    #[test]
    fn chars_in_order() {
        let mut reader = BufReader::new("First".as_bytes());
        let _first_char = read_one_byte(&mut reader).unwrap();
        let second_char = read_one_byte(&mut reader).unwrap() as char;
        assert_eq!(second_char, 'i');
    }
}

fn read_until(
    reader: &mut BufReader<impl BufRead>,
    ch: u8,
    max_length: Option<usize>,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut current_byte: u8;
    loop {
        current_byte = read_one_byte(reader)?;
        if current_byte == ch {
            return Ok(bytes);
        }
        bytes.push(current_byte);
        if let Some(max) = max_length {
            if bytes.len() > max {
                bail!(errors::ErrorKind::ExceededMaxLength(max));
            }
        }
    }
}
