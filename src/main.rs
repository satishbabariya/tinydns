mod dns;

use log::LevelFilter;
use std::error::Error;
use tokio::net::UdpSocket;
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::{timeout, Duration};

use crate::dns::message::DNSMessage;

async fn run_dns_server(addr: &str) -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind(addr).await?;
    println!("DNS Server is running on {}", addr);

    // Reuse the same socket for forwarding requests
    let remote_dns_server = "8.8.8.8:53"; // Google's public DNS server

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
                        let message = DNSMessage::parse(&buf[0..len]);
                        println!("Received DNS Message: {:?}", message);

                        let response = forward_query(&socket, remote_dns_server, &buf[0..len]).await?;
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

    // Initialize logger
    env_logger::builder().filter_level(LevelFilter::Info).init();

    let port = std::env::var("PORT").unwrap_or_else(|_| "53".to_string());
    let addr = format!("0.0.0.0:{}", port);
    run_dns_server(&addr).await
}

// Forward the query to another DNS server (e.g., 8.8.8.8)
async fn forward_query(
    socket: &UdpSocket,
    remote_dns_server: &str,
    query: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    // Set timeout duration (e.g., 1 seconds)
    let timeout_duration = Duration::from_secs(5);

    // Send the query to the remote DNS server
    socket.send_to(query, remote_dns_server).await?;

    // Set up timeout for receiving the response
    let mut response = vec![0u8; 512]; // Standard DNS response buffer
    let res = timeout(timeout_duration, socket.recv_from(&mut response)).await;

    match res {
        Ok(Ok(_)) => Ok(response),      // Successfully received the response
        Ok(Err(e)) => Err(Box::new(e)), // Error occurred while receiving
        Err(_) => Err("Timeout while waiting for response".into()), // Handle timeout
    }
}
