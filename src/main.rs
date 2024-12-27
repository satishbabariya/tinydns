use std::error::Error;
use tokio::net::UdpSocket;

use crate::dns::header::Header;
use crate::dns::query::Query;

mod dns {
    pub mod header;
    pub mod query;
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind("0.0.0.0:5300").await?;
    println!("DNS Server is running on port 5300");

    let mut buf = [0u8; 512]; // Standard DNS message size

    loop {
        let (len, addr) = socket.recv_from(&mut buf).await?;

        // Parse DNS Request
        let header = parse_header(&buf);

        println!("Received DNS Header: {:?}", header);

        let query = parse_query(&buf[12..len]);

        println!("Received DNS Query: {:?}", query);

        // Forward the query to another DNS server (e.g., Google's DNS: 8.8.8.8)
        let response = forward_query(&buf[0..len]).await?;

        // Send DNS Response back to the client
        socket.send_to(&response, addr).await?;
    }
}

// Parse DNS header from byte buffer
fn parse_header(buf: &[u8]) -> Header {
    Header {
        id: u16::from_be_bytes([buf[0], buf[1]]),
        qr: (buf[2] >> 7) & 0x01 == 1,
        opcode: (buf[2] >> 3) & 0x0F,
        aa: (buf[2] >> 2) & 0x01 == 1,
        tc: (buf[2] >> 1) & 0x01 == 1,
        rd: buf[2] & 0x01 == 1,
        ra: (buf[3] >> 7) & 0x01 == 1,
        z: (buf[3] >> 4) & 0x07,
        rcode: buf[3] & 0x0F,
        qdcount: u16::from_be_bytes([buf[4], buf[5]]),
        ancount: u16::from_be_bytes([buf[6], buf[7]]),
        nscount: u16::from_be_bytes([buf[8], buf[9]]),
        arcount: u16::from_be_bytes([buf[10], buf[11]]),
    }
}

// Parse DNS query from byte buffer
fn parse_query(buf: &[u8]) -> Query {
    let qname = parse_qname(buf);
    let qtype = u16::from_be_bytes([buf[qname.len() + 1], buf[qname.len() + 2]]);
    let qclass = u16::from_be_bytes([buf[qname.len() + 3], buf[qname.len() + 4]]);
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
