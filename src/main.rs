mod dns;

use log::LevelFilter;
use log::{error, info, warn};
use std::error::Error;
use tokio::net::UdpSocket;
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::{timeout, Duration};

use crate::dns::message::DNSMessage;

async fn run_dns_server(addr: &str) -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind(addr).await?;
    info!("DNS Server is running on {}", addr);

    // Reuse the same socket for forwarding requests
    let remote_dns_server = "8.8.8.8:53"; // Google's public DNS server

    let mut buf = [0u8; 512]; // Standard DNS message size
    let mut shutdown_signal = signal(SignalKind::interrupt())?;

    loop {
        tokio::select! {
            _ = shutdown_signal.recv() => {
                info!("Shutdown signal received. Closing server...");
                break;
            }
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, addr)) => {
                        match DNSMessage::parse(&buf[0..len]) {
                            Ok(message) => info!("Received DNS Message from {}: {:?}", addr, message),
                            Err(e) => warn!("Failed to parse DNS message from {}: {}", addr, e),
                        }

                        match forward_query(&socket, remote_dns_server, &buf[0..len]).await {
                            Ok(response) => {
                                if let Err(e) = socket.send_to(&response, addr).await {
                                    error!("Error sending response to {}: {}", addr, e);
                                }
                            }
                            Err(e) => error!("Error forwarding query to remote server: {}", e),
                        }
                    }
                    Err(e) => error!("Error receiving from socket: {}", e),
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

    info!("tinydns v0.1.0");
    if let Err(e) = run_dns_server(&addr).await {
        error!("DNS server encountered an error: {}", e);
    }
    Ok(())
}

// Forward the query to another DNS server (e.g., 8.8.8.8)
async fn forward_query(
    socket: &UdpSocket,
    remote_dns_server: &str,
    query: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let timeout_duration = Duration::from_secs(5);

    // Send the query to the remote DNS server
    if let Err(e) = socket.send_to(query, remote_dns_server).await {
        error!("Error sending query to remote DNS server: {}", e);
        return Err(Box::new(e));
    }

    let mut response = vec![0u8; 512]; // Standard DNS response buffer
    let res = timeout(timeout_duration, socket.recv_from(&mut response)).await;

    match res {
        Ok(Ok(_)) => Ok(response), // Successfully received the response
        Ok(Err(e)) => {
            error!("Error receiving response from remote server: {}", e);
            Err(Box::new(e))
        }
        Err(_) => {
            warn!("Timeout while waiting for response from remote DNS server");
            Err("Timeout while waiting for response".into())
        }
    }
}
