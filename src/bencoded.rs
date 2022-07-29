use anyhow::{bail, Context, Result};
#[allow(unused_imports)]
use log::{debug, error, info, log, trace};
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{BufReader, BufRead, Read};
use std::iter::FromIterator;

use crate::ParseTorrentError;

#[derive(PartialEq, Eq, Clone)]
pub enum Bencoded {
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
    pub fn unwrap_integer(&self) -> Result<i64> {
        match self {
            Bencoded::Integer(val) => Ok(*val),
            _ => Err(ParseTorrentError::WrongTypeInTorrent {
                exp: "Integer".to_string(),
                got: self.to_string(),
            }
            .into()),
        }
    }
    pub fn unwrap_string(&self) -> Result<Vec<u8>> {
        match self {
            Bencoded::String(val) => Ok(val.to_vec()),
            _ => Err(ParseTorrentError::WrongTypeInTorrent {
                exp: "String".to_string(),
                got: self.to_string(),
            }
            .into()),
        }
    }

    pub fn unwrap_string_as_utf8(&self) -> Result<String> {
        match self {
            Bencoded::String(val) => Ok(String::from_utf8(val.to_vec())
                .with_context(|| "failed converting to utf8 encoded string")?),
            _ => Err(ParseTorrentError::WrongTypeInTorrent {
                exp: "String".to_string(),
                got: self.to_string(),
            }
            .into()),
        }
    }
    pub fn unwrap_list(&self) -> Result<Vec<Bencoded>> {
        match self {
            Bencoded::List(val) => Ok(val.to_vec()),
            _ => Err(ParseTorrentError::WrongTypeInTorrent {
                exp: "List".to_string(),
                got: self.to_string(),
            }
            .into()),
        }
    }
    pub fn unwrap_dictionary(&self) -> Result<&OrderdDict<Bencoded>> {
        match self {
            Bencoded::Dictionary(val) => Ok(val),
            _ => Err(ParseTorrentError::WrongTypeInTorrent {
                exp: "Dictionary".to_string(),
                got: self.to_string(),
            }
            .into()),
        }
    }
}

impl Bencoded {
    pub(crate) fn encode(&self) -> Vec<u8> {
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

// TODO: All of these function should probably be impls of OrderdDict
impl OrderdDict<Bencoded> {
    pub(crate) fn get_string_if_exists(self: &Self, key: &str) -> Result<Option<Vec<u8>>> {
        if self.contains_key(key) {
            Ok(Some(self.get(key).unwrap().unwrap_string()?))
        } else {
            Ok(None)
        }
    }
}

pub(crate) fn get_string_if_exists_as_utf8_string(
    map: &OrderdDict<Bencoded>,
    key: &str,
) -> Result<Option<String>> {
    if map.contains_key(key) {
        Ok(Some(map.get(key).unwrap().unwrap_string_as_utf8()?))
    } else {
        Ok(None)
    }
}

pub(crate) fn get_integer_if_exists(map: &OrderdDict<Bencoded>, key: &str) -> Result<Option<i64>> {
    if map.contains_key(key) {
        Ok(Some(map.get(key).unwrap().unwrap_integer()?))
    } else {
        Ok(None)
    }
}

pub(crate) fn get_list_if_exists(
    map: &OrderdDict<Bencoded>,
    key: &str,
) -> Result<Option<Vec<Bencoded>>> {
    if map.contains_key(key) {
        Ok(Some(map.get(key).unwrap().unwrap_list()?))
    } else {
        Ok(None)
    }
}

#[derive(PartialEq, Eq, Clone)]
pub struct OrderdDict<V> {
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
    pub(crate) fn new() -> Self {
        Self {
            inner: HashMap::new(),
            keys: Vec::new(),
        }
    }

    pub(crate) fn keys(&self) -> Vec<String> {
        return self.keys.clone();
    }

    pub(crate) fn get(&self, key: &str) -> Option<&V> {
        self.inner.get(&key.to_string())
    }

    pub(crate) fn contains_key(&self, key: &str) -> bool {
        self.keys.contains(&key.to_string())
    }

    pub(crate) fn insert(&mut self, key: &str, value: V) {
        // No need to check if key is already present, we're fine with duplicate keys. Are we??
        self.inner.insert(key.to_string(), value);
        self.keys.push(key.to_string())
    }
}

pub fn read_bencoded(reader: &mut BufReader<impl BufRead>) -> Result<Bencoded> {
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
            .context("couldn't parse number")?;
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
                    .context("Couldnt convert to number")?;
                return Ok(Bencoded::Integer(number));
            }
            if !ch.is_ascii_digit() {
                bail!("Invalid file: non digits in a number");
            }
            number_string.push(ch);
            digit_count += 1;
            if digit_count > 1 && number_string.starts_with('0') {
                return Err(ParseTorrentError::NoLeadingZeroesAllowd.into());
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
                Err(err) => match err.downcast_ref::<ParseTorrentError>() {
                    Some(ParseTorrentError::CompletedReader) => {
                        return Ok(Bencoded::List(items));
                    }
                    _ => {
                        return Err(err);
                    } // errors::Error(errors::ErrorKind::CompletedReader, _) => {
                      //     return Ok(Bencoded::List(items));
                      // }
                      // errors::Error(_, _) => {
                      //     return Err(err);
                      // }
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
                let key =
                    String::from_utf8(key).context("Bad assumption: This key is not utf8??")?;
                debug!("Found key \"{}\", reading value", key);
                let value = read_bencoded(reader)?;
                debug!("Found value {}. Inserting...", value);
                dict.insert(&key, value);
            } else {
                bail!(
                    "Only Strings are can be keys in becoded dictionaries, not {}",
                    bencoded_key
                )
            }
        }
    }
    bail!(
        "Couldn't find valid Bencoded value: found char {}",
        first_ch
    );
}

#[cfg(test)]
mod bencoded_tests {
    use crate::bencoded::{read_bencoded, Bencoded};
    use crate::bencoded::{OrderdDict, ParseTorrentError};
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
            Err(err) => match err.downcast_ref::<ParseTorrentError>() {
                Some(ParseTorrentError::NoLeadingZeroesAllowd) => {}
                _ => panic!("Got wrong error: {}", err),
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
    let mut bytes_read = reader.read(&mut buf).context("Failed to read bytes")?;
    while bytes_read < count && bytes_read != 0 {
        buf.resize(bytes_read, 0);
        debug!(
            "Tried reading {} bytes, read {} until now",
            count, bytes_read
        );
        let mut new_buf = vec![0; count - bytes_read];
        bytes_read += reader.read(&mut new_buf).context("Failed to read bytes")?;
        buf.append(&mut new_buf);
    }
    Ok(buf)
}

fn read_one_byte(reader: &mut BufReader<impl BufRead>) -> Result<u8> {
    Ok(*read_bytes(reader, 1)?.get(0).unwrap())
}

fn peek_bytes(reader: &mut BufReader<impl BufRead>, byte_count: usize) -> Result<Vec<u8>> {
    let buf = reader.fill_buf().context("Failed to peek")?;
    if buf.len() < byte_count {
        return Err(ParseTorrentError::CompletedReader.into());
    }
    return Ok(buf.get(0..byte_count).unwrap().to_vec());
}

fn peek_one_byte(reader: &mut BufReader<impl BufRead>) -> Result<u8> {
    Ok(*peek_bytes(reader, 1)?.get(0).unwrap())
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
                bail!(ParseTorrentError::ExceededMaxLength(max));
            }
        }
    }
}

#[cfg(test)]
mod reader_tests {
    use crate::bencoded::{peek_bytes, peek_one_byte, read_bytes, read_one_byte};
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
