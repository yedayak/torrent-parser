use crate::{Peer, Torrent};
use anyhow::{bail, Context, Result};

#[allow(unused_imports)]
use log::{debug, error, info, log, trace};
use num_enum::TryFromPrimitive;
use std::{io::Cursor, sync::Arc, thread, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};

pub async fn interact(
    potential_peers: Vec<Peer>,
    torrent: Torrent,
    peer_id: Vec<u8>,
) -> Result<()> {
    // let mut verified_peers = Vec::new();
    let peer_id = Arc::new(peer_id);
    let info_hash = Arc::new(torrent.info_hash);
    for peer in potential_peers {
        let stream = get_stream(&peer).await;
        let mut stream = match stream {
            Err(err) => {
                info!("no connection: {}. Skipping", err.to_string());
                continue;
            }
            Ok(stream) => stream,
        };
        {
            let peer_id = peer_id.clone();
            let info_hash = info_hash.clone();
            tokio::spawn(async move {
                match do_handshake(&mut stream, &peer, &peer_id, &info_hash).await {
                    Err(err) => {
                        info!("peer {:?} failed handshake: {}", peer, err.to_string());
                        return;
                    }
                    Ok(_) => {}
                };
            });
        }
    }

    Ok(())
}

async fn get_stream(peer: &Peer) -> Result<TcpStream> {
    let addr = format!("{}:{}", peer.ip, peer.port);
    match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
        Ok(stream) => stream.with_context(|| format!("Failed to connect to peer {:?}", peer)),
        Err(_) => bail!("Timeout waiting for peer {:?}", peer),
    }
}

async fn do_handshake(
    stream: &mut (impl AsyncWrite + AsyncRead + std::marker::Unpin),
    peer: &Peer,
    peer_id: &Vec<u8>,
    info_hash: &Vec<u8>,
) -> Result<()> {
    const PSTR: &str = "BitTorrent protocol";
    const PSTRLEN: u8 = 19;
    let reserved_bytes = [0u8; 8];
    const HANDSHAKE_LENGTH: usize = 49 + PSTRLEN as usize;
    let mut handshake = Vec::<u8>::with_capacity(HANDSHAKE_LENGTH);
    handshake.extend(PSTRLEN.to_be_bytes());
    handshake.extend(PSTR.as_bytes());
    handshake.extend(reserved_bytes);
    assert_eq!(info_hash.len(), 20);
    handshake.extend(info_hash);
    assert_eq!(peer_id.len(), 20);
    handshake.extend(peer_id);
    debug!("Sending handshake {:?}", handshake);
    stream.write_all_buf(&mut Cursor::new(handshake)).await?;

    let read_buf = &mut [0u8; HANDSHAKE_LENGTH][..];
    stream.read_exact(read_buf).await.with_context(|| {
        format!(
            "Couldn't read {} bytes from peer {:?}",
            HANDSHAKE_LENGTH, peer
        )
    })?;
    debug!("Received handshake: {:?}", read_buf);
    let recv_pstr_len = read_buf[0] as usize;
    let pstr = &read_buf[1..recv_pstr_len + 1 as usize];
    if String::from_utf8(pstr.to_vec())?.ne(PSTR) {
        bail!(
            "Unrecognized pstr in handshake: {} (length received: {})",
            String::from_utf8_lossy(pstr),
            recv_pstr_len
        );
    }
    let _recv_reserverd = &read_buf[recv_pstr_len..recv_pstr_len + 1 + 8];
    let recv_info_hash = &read_buf[recv_pstr_len + 1 + 8..recv_pstr_len + 1 + 8 + 20];
    if recv_info_hash.ne(info_hash) {
        error!(
            "Wrong handshake: Recieved info hash {:x?}, expected {:x?}",
            recv_info_hash, info_hash
        );
        bail!(
            "Wrong handshake: Recieved info hash {:x?}, expected {:x?}",
            recv_info_hash,
            info_hash
        );
    }
    let recv_peer_id = &read_buf[recv_pstr_len + 1 + 8 + 20..recv_pstr_len + 1 + 8 + 20 + 20];
    info!(
        "Connected peer ID: {}",
        String::from_utf8_lossy(recv_peer_id)
    );

    Ok(())
}

#[cfg(test)]
mod tcp_tests {
    use crate::peer_to_peer::do_handshake;
    use crate::{generate_peer_id, Peer};
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn successfull_handshake() {
        println!("Starting handhsake test");
        let mut stream = Builder::new();
        let mut expected_handshake: Vec<u8> = Vec::new();
        expected_handshake.push(19);
        expected_handshake.extend("BitTorrent protocol".as_bytes());
        expected_handshake.extend([0u8; 8]);
        let info_hash = [0x5; 20];
        expected_handshake.extend(info_hash);
        let peer = generate_peer_id();
        expected_handshake.extend(peer.clone());
        println!("Writing handshake");
        stream.write(&expected_handshake);

        let mut recv_expected_handshake: Vec<u8> = Vec::new();
        recv_expected_handshake.push(19);
        recv_expected_handshake.extend("BitTorrent protocol".as_bytes());
        recv_expected_handshake.extend([0u8; 8]);
        let info_hash = [0x5; 20];
        recv_expected_handshake.extend(info_hash);
        let recv_peer = generate_peer_id();
        recv_expected_handshake.extend(recv_peer.clone());
        stream.read(&recv_expected_handshake);

        do_handshake(
            &mut stream.build(),
            &Peer::new("127.0.0.1".parse().unwrap(), 8686),
            &peer,
            &info_hash.to_vec(),
        )
        .await
        .expect("Failed handshake");
    }
}

