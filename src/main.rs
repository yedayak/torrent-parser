#[macro_use]
extern crate error_chain;

use log::{debug, error, info, log, trace};
use std::collections::HashMap;
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

enum Bencoded {
    Integer(i64),
    String(Vec<u8>),
    List(Vec<Bencoded>),
    Dictionary(HashMap<String, Bencoded>),
}

impl std::fmt::Debug for Bencoded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Integer(arg0) => f.debug_tuple("Integer").field(arg0).finish(),
            Self::String(arg0) => f.debug_tuple("String").field(&String::from_utf8_lossy(arg0)).finish(),
            Self::List(arg0) => f.debug_tuple("List").field(arg0).finish(),
            Self::Dictionary(arg0) => f.debug_tuple("Dictionary").field(arg0).finish(),
        }
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
    parse_torrent(reader)?;
    Ok(())
}

fn parse_torrent(reader: impl BufRead) -> Result<()> {
    let buf_reader = BufReader::new(reader);
    let mut reader = buf_reader;
    loop {
        let bencoded = read_bencoded(&mut reader).chain_err(|| "Failed to parse bencoded")?;
        debug!("{:?}", bencoded)
    }
}

fn read_bencoded(reader: &mut BufReader<impl BufRead>) -> Result<Bencoded> {
    // This parsing is based on this spec: https://wiki.theory.org/BitTorrentSpecification

    let first_ch = *read_bytes(reader, 1)?.get(0).unwrap() as char;
    // Strings start with a number signifying it's length.
    // For example '4:rick' is the string "rick" with length 4
    if first_ch.is_ascii_digit() {
        debug!("Found a digit, detected a string");
        // let mut string_length = String::new();
        let mut bytes = read_until(reader, ':' as u8)?;
        bytes.insert(0, first_ch as u8);
        let digit_chars = bytes.iter().map(|c| *c as char);
        let string_length = String::from_iter(digit_chars);
        let length = string_length
            .parse::<usize>()
            .chain_err(|| "couldn't parse number")?;
        debug!("Reading {} characters", string_length);
        let actual_string = read_bytes(reader, length)?;
        debug!("Found a string {:?}", String::from_utf8_lossy(&actual_string));
        return Ok(Bencoded::String(actual_string));
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
                bail!("Invalid number: No leading zeroes allowd");
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
                    debug!("Found list item {:?}", value);
                    items.push(value);
                }
            }
        }
    }
    // This is a dictionary
    else if first_ch == 'd' {
        debug!("Found dictionary");
        let mut dict = HashMap::new();
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
                debug!("Found value {:?}. Inserting...", value);
                dict.insert(key, value);
            } else {
                bail!("Only Strings are can be keys in becoded dictionaries")
            }
        }
    }
    bail!("Couldn't find valid Bencoded value");
}

fn read_bytes(reader: &mut BufReader<impl BufRead>, count: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0; count];
    let mut bytes_read = reader.read(&mut buf).chain_err(|| "Failed to read bytes")?;
    while bytes_read < count && bytes_read != 0 {
        buf.resize(bytes_read, 0);
        debug!("Tried reading {} bytes, read {} until now", count, bytes_read);
        let mut new_buf = vec![0; count - bytes_read];
        bytes_read += reader.read(&mut new_buf).chain_err(|| "Failed to read bytes")?;
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

// fn get_char(reader: &mut BufReader<impl BufRead>) -> Result<char> {
//     let ch = reader.read_exact();
//     match ch {
//         Some(ch) => {
//             let ch = ch.chain_err(|| "")?;
//             if ch == '\0' {
//                 Err(errors::ErrorKind::CompletedReader.into())
//             } else {
//                 Ok(ch)
//             }
//         }
//         None => Err(errors::ErrorKind::CompletedReader.into()),
//     }
// }

#[cfg(test)]
mod tests {
    use crate::{read_bytes, peek_bytes, read_one_byte, peek_one_byte};
    use std::io::BufReader;

    #[test]
    fn reading_one_ascii_char() {
        let mut reader = BufReader::new("First".as_bytes());
        let ch = read_one_byte(&mut reader).unwrap() as char;
        assert_eq!(ch, 'F');
    }

    // #[test]
    // fn reading_non_utf8_bytes() {
    //     let reader: BufReader<&[u8]> = BufReader::new(vec![255, 34, 56, 57].as_slice());
    // }

    // #[test]
    // fn utf_char() {
    //     let mut reader = BufReader::new("שלום".as_bytes());
    //     let mut peek_reader = reader.char_iter().peekable();
    //     let ch = get_char(&mut peek_reader).expect("");
    //     assert_eq!(ch, 'ש');
    // }

    #[test]
    fn chars_in_order() {
        let mut reader = BufReader::new("First".as_bytes());
        let _first_char = read_one_byte(&mut reader).unwrap();
        let second_char = read_one_byte(&mut reader).unwrap() as char;
        assert_eq!(second_char, 'i');
    }
}

// fn peek_char(reader: &mut BufReader<impl BufRead>) -> Result<char> {
//     let ch_opt = reader.peek();
//     match ch_opt {
//         Some(ch) => {
//             match ch {
//                 Err(error) => {
//                     bail!("Failed to read char: {}", error.to_string());
//                     // Err(error.into())
//                 }
//                 Ok(ch) => {
//                     if *ch == '\0' {
//                         Err(errors::ErrorKind::CompletedReader.into())
//                     } else {
//                         Ok(*ch)
//                     }
//                 }
//             }
//         }
//         None => Err(errors::ErrorKind::CompletedReader.into()),
//     }
// }

fn read_until(reader: &mut BufReader<impl BufRead>, ch: u8) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut current_byte: u8;
    loop {
        current_byte = read_one_byte(reader)?;
        if current_byte == ch {
            return Ok(bytes);
        }
        bytes.push(current_byte);
    }
}
