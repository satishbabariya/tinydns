#![allow(dead_code)]
#[derive(Debug)]
pub struct Header {
    pub id: u16,
    pub qr: bool,     // Query (0) or Response (1)
    pub opcode: u8,   // Operation code (standard query is 0)
    pub aa: bool,     // Authoritative answer
    pub tc: bool,     // Truncated message
    pub rd: bool,     // Recursion desired
    pub ra: bool,     // Recursion available
    pub z: u8,        // Reserved for future use
    pub rcode: u8,    // Response code
    pub qdcount: u16, // Number of questions
    pub ancount: u16, // Number of answers
    pub nscount: u16, // Number of authority records
    pub arcount: u16, // Number of additional records
}