#![allow(dead_code)]
// #[derive(Debug)]
// pub struct Header {
//     pub id: u16,
//     pub qr: bool,     // Query (0) or Response (1)
//     pub opcode: u8,   // Operation code (standard query is 0)
//     pub aa: bool,     // Authoritative answer
//     pub tc: bool,     // Truncated message
//     pub rd: bool,     // Recursion desired
//     pub ra: bool,     // Recursion available
//     pub z: u8,        // Reserved for future use
//     pub rcode: u8,    // Response code
//     pub qdcount: u16, // Number of questions
//     pub ancount: u16, // Number of answers
//     pub nscount: u16, // Number of authority records
//     pub arcount: u16, // Number of additional records
// }

use crate::dns::message::DNSParseError;

#[derive(Debug)]
pub struct Header {
    pub transaction_id: u16,
    pub flags: Flags,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

#[derive(Debug)]
pub struct Flags {
    pub qr: bool,
    pub opcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: u8,
    pub rcode: u8,
}

impl Header {
    pub fn parse(buf: &[u8]) -> Result<Self, DNSParseError> {
        // Ensure the buffer is at least 12 bytes
        if buf.len() < 12 {
            return Err(DNSParseError::BufferTooShort);
        }

        // Inline parsing for better performance
        let transaction_id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags_byte1 = buf[2];
        let flags_byte2 = buf[3];
        let question_count = u16::from_be_bytes([buf[4], buf[5]]);
        let answer_count = u16::from_be_bytes([buf[6], buf[7]]);
        let authority_count = u16::from_be_bytes([buf[8], buf[9]]);
        let additional_count = u16::from_be_bytes([buf[10], buf[11]]);

        // Parse flags
        let flags = Flags {
            qr: flags_byte1 & 0x80 != 0,
            opcode: (flags_byte1 >> 3) & 0x0F,
            aa: flags_byte1 & 0x04 != 0,
            tc: flags_byte1 & 0x02 != 0,
            rd: flags_byte1 & 0x01 != 0,
            ra: flags_byte2 & 0x80 != 0,
            z: (flags_byte2 >> 4) & 0x07,
            rcode: flags_byte2 & 0x0F,
        };

        // Construct and return the header
        Ok(Header {
            transaction_id,
            flags,
            question_count,
            answer_count,
            authority_count,
            additional_count,
        })
    }
}
