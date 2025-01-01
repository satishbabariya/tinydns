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

    pub fn parse(buf: &[u8]) -> Self {
        let transaction_id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = Flags {
            qr: (buf[2] >> 7) & 0x01 == 1,
            opcode: (buf[2] >> 3) & 0x0F,
            aa: (buf[2] >> 2) & 0x01 == 1,
            tc: (buf[2] >> 1) & 0x01 == 1,
            rd: buf[2] & 0x01 == 1,
            ra: (buf[3] >> 7) & 0x01 == 1,
            z: (buf[3] >> 4) & 0x07,
            rcode: buf[3] & 0x0F,
        };
        let question_count = u16::from_be_bytes([buf[4], buf[5]]);
        let answer_count = u16::from_be_bytes([buf[6], buf[7]]);
        let authority_count = u16::from_be_bytes([buf[8], buf[9]]);
        let additional_count = u16::from_be_bytes([buf[10], buf[11]]);

        Header {
            transaction_id,
            flags,
            question_count,
            answer_count,
            authority_count,
            additional_count,
        }
    }
}