use std::error::Error;
use tokio::net::UdpSocket;

use crate::dns::header::Header;
use crate::dns::query::Query;

mod dns {
    pub mod header;
    pub mod query;
}

use tokio::signal::unix::{signal, SignalKind};

async fn run_dns_server(addr: &str) -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind(addr).await?;
    println!("DNS Server is running on {}", addr);

    let mut buf = [0u8; 512]; // Standard DNS message size
    let mut shutdown_signal = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            _ = shutdown_signal.recv() => {
                println!("Shutdown signal received. Closing server...");
                break;
            }
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, addr)) => {
                        // Process request
                        let header = parse_header(&buf);
                        println!("Received DNS Header: {:?}", header);

                        let query = parse_query(&buf[12..len]);
                        println!("Received DNS Query: {:?}", query);

                        let response = forward_query(&buf[0..len]).await?;
                        socket.send_to(&response, addr).await?;
                    }
                    Err(e) => {
                        eprintln!("Error receiving from socket: {}", e);
                    }
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv::dotenv().ok();

    let port = std::env::var("PORT").unwrap_or_else(|_| "53".to_string());
    let addr = format!("0.0.0.0:{}", port);
    run_dns_server(&addr).await
}

// Parse DNS header from byte buffer
fn parse_header(buf: &[u8]) -> Header {
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let byte2 = buf[2];
    let byte3 = buf[3];

    Header {
        id,
        qr: (byte2 >> 7) & 0x01 == 1,
        opcode: (byte2 >> 3) & 0x0F,
        aa: (byte2 >> 2) & 0x01 == 1,
        tc: (byte2 >> 1) & 0x01 == 1,
        rd: byte2 & 0x01 == 1,
        ra: (byte3 >> 7) & 0x01 == 1,
        z: (byte3 >> 4) & 0x07,
        rcode: byte3 & 0x0F,
        qdcount: u16::from_be_bytes([buf[4], buf[5]]),
        ancount: u16::from_be_bytes([buf[6], buf[7]]),
        nscount: u16::from_be_bytes([buf[8], buf[9]]),
        arcount: u16::from_be_bytes([buf[10], buf[11]]),
    }
}

// Parse DNS query from byte buffer
fn parse_query(buf: &[u8]) -> Query {
    let qname = parse_qname(buf);
    let name_len = qname.len();
    let qtype = u16::from_be_bytes([buf[name_len + 1], buf[name_len + 2]]);
    let qclass = u16::from_be_bytes([buf[name_len + 3], buf[name_len + 4]]);

    Query {
        qname,
        qtype,
        qclass,
    }
}

// Parse the domain name (QNAME) from the byte buffer
fn parse_qname(mut buf: &[u8]) -> String {
    let mut qname = String::new();
    while !buf.is_empty() {
        let len = buf[0] as usize;
        if len == 0 {
            break;
        }
        buf = &buf[1..];
        qname.push_str(&String::from_utf8_lossy(&buf[..len]));
        qname.push('.');
        buf = &buf[len..];
    }
    qname.trim_end_matches('.').to_string()
}

// Forward the query to another DNS server (e.g., 8.8.8.8)
async fn forward_query(query: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let remote_dns_server = "8.8.8.8:53"; // Google's public DNS server
    let socket = UdpSocket::bind("0.0.0.0:0").await?; // Bind to a random local port

    // Send the query to the remote DNS server
    socket.send_to(query, remote_dns_server).await?;

    // Receive the response from the remote DNS server
    let mut response = vec![0u8; 512]; // Standard DNS response buffer
    let _ = socket.recv_from(&mut response).await?;

    Ok(response)
}
