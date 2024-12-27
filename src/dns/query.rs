#![allow(dead_code)]
#[derive(Debug)]
pub struct Query {
    pub qname: String,
    pub qtype: u16,
    pub qclass: u16,
}