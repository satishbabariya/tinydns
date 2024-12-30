#![allow(dead_code)]

#[derive(Debug)]
pub struct Query {
    pub name: String,
    pub query_type: QueryType,
    pub query_class: u16, // Usually IN (Internet), but can be other values
}

impl Query {
    pub fn parse(query_buffer: &[u8]) -> Self {
        let mut index = 0;

        // Parse the domain name
        let mut domain_name = String::new();
        loop {
            let length = query_buffer[index] as usize;
            if length == 0 {
                index += 1; // Move past the null byte
                break; // End of the domain name
            }
            index += 1;
            domain_name.push_str(&String::from_utf8_lossy(
                &query_buffer[index..index + length],
            ));
            index += length;
            domain_name.push('.'); // Add the dot between labels
        }
        domain_name.pop(); // Remove the trailing dot

        // Parse the query type (next 2 bytes)
        let query_type = QueryType::from_u16(u16::from_be_bytes([
            query_buffer[index],
            query_buffer[index + 1],
        ]));
        index += 2;

        // Parse the query class (next 2 bytes)
        let query_class = u16::from_be_bytes([query_buffer[index], query_buffer[index + 1]]);
        // index += 2; // Not needed since we're at the end of the buffer

        Query {
            name: domain_name,
            query_type,
            query_class,
        }
    }
}

#[derive(Debug)]
#[repr(u16)]
pub enum QueryType {
    A = 1,            // IPv4 Address
    NS = 2,           // Name Server
    MD = 3,           // Mail Destination (obsolete)
    MF = 4,           // Mail Forwarder (obsolete)
    CNAME = 5,        // Canonical Name for an alias
    SOA = 6,          // Start of a zone of authority
    MB = 7,           // Mailbox domain name (experimental)
    MG = 8,           // Mail group member (experimental)
    MR = 9,           // Mail rename domain name (experimental)
    Null = 10,        // Null resource record (experimental)
    PTR = 12,         // Domain name pointer
    HINFO = 13,       // Host information
    MINFO = 14,       // Mailbox or mail list information
    MX = 15,          // Mail Exchange
    TXT = 16,         // Text strings
    RP = 17,          // Responsible person
    AFSDB = 18,       // AFS database record
    X25 = 19,         // X.25 PSDN address
    ISDN = 20,        // ISDN address
    RT = 21,          // Route Through
    NSAPPTR = 23,     // NSAP Pointer
    SIG = 24,         // Signature
    KEY = 25,         // Key record
    PX = 26,          // Pointer to X.400 mail mapping information
    GPOS = 27,        // Geographical position
    AAAA = 28,        // IPv6 Address
    LOC = 29,         // Location information
    NXT = 30,         // Next domain (obsolete)
    EID = 31,         // Endpoint Identifier
    NIMLOC = 32,      // Nimrod Locator
    SRV = 33,         // Service locator
    ATMA = 34,        // ATM Address
    NAPTR = 35,       // Naming Authority Pointer
    KX = 36,          // Key Exchanger
    CERT = 37,        // Certificate
    DNAME = 39,       // Delegation Name
    OPT = 41,         // Option (used for EDNS)
    APL = 42,         // Address Prefix List
    DS = 43,          // Delegation Signer
    SSHFP = 44,       // SSH Fingerprint
    IPSECKEY = 45,    // IPSEC Key
    RRSIG = 46,       // Resource Record Signature
    NSEC = 47,        // Next Secure record
    DNSKEY = 48,      // DNS Key record
    DHCID = 49,       // DHCP Identifier
    NSEC3 = 50,       // Next Secure record version 3
    NSEC3PARAM = 51,  // NSEC3 parameters
    TLSA = 52,        // TLS Authentication
    SMIMEA = 53,      // S/MIME cert association
    HIP = 55,         // Host Identity Protocol
    NINFO = 56,       // Zone information
    RKEY = 57,        // RKEY record
    TALINK = 58,      // Trust Anchor LINK
    CDS = 59,         // Child DS
    CDNSKEY = 60,     // Child DNSKEY
    OPENPGPKEY = 61,  // OpenPGP Key
    CSYNC = 62,       // Child-to-Parent Synchronization
    ZONEMD = 63,      // Zone MD record
    SVCB = 64,        // Service Binding
    HTTPS = 65,       // HTTPS Binding
    SPF = 99,         // Sender Policy Framework
    UINFO = 100,      // User Information (experimental)
    UID = 101,        // User ID (experimental)
    GID = 102,        // Group ID (experimental)
    UNSPEC = 103,     // Unspecified format (experimental)
    NID = 104,        // Node Identifier
    L32 = 105,        // Locator 32-bit
    L64 = 106,        // Locator 64-bit
    LP = 107,         // Locator Pointer
    EUI48 = 108,      // MAC Address (EUI-48)
    EUI64 = 109,      // MAC Address (EUI-64)
    NXNAME = 128,     // Non-existent domain
    URI = 256,        // Uniform Resource Identifier
    CAA = 257,        // Certification Authority Authorization
    AVC = 258,        // Application Visibility and Control
    AMTRELAY = 260,   // Automatic Multicast Tunneling Relay
    TKEY = 249,       // Transaction Key
    TSIG = 250,       // Transaction Signature
    IXFR = 251,       // Incremental Zone Transfer
    AXFR = 252,       // Authoritative Zone Transfer
    MAILB = 253,      // Mailbox-related RRs
    MAILA = 254,      // Mail Agent RRs
    ANY = 255,        // Any type of record
    TA = 32768,       // Trust Authority
    DLV = 32769,      // DNSSEC Lookaside Validation
    Reserved = 65535, // Reserved
    Unknown = 0,      // Unknown query type
}

impl QueryType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => QueryType::A,
            2 => QueryType::NS,
            3 => QueryType::MD,
            4 => QueryType::MF,
            5 => QueryType::CNAME,
            6 => QueryType::SOA,
            7 => QueryType::MB,
            8 => QueryType::MG,
            9 => QueryType::MR,
            10 => QueryType::Null,
            12 => QueryType::PTR,
            13 => QueryType::HINFO,
            14 => QueryType::MINFO,
            15 => QueryType::MX,
            16 => QueryType::TXT,
            17 => QueryType::RP,
            18 => QueryType::AFSDB,
            19 => QueryType::X25,
            20 => QueryType::ISDN,
            21 => QueryType::RT,
            23 => QueryType::NSAPPTR,
            24 => QueryType::SIG,
            25 => QueryType::KEY,
            26 => QueryType::PX,
            27 => QueryType::GPOS,
            28 => QueryType::AAAA,
            29 => QueryType::LOC,
            30 => QueryType::NXT,
            31 => QueryType::EID,
            32 => QueryType::NIMLOC,
            33 => QueryType::SRV,
            34 => QueryType::ATMA,
            35 => QueryType::NAPTR,
            36 => QueryType::KX,
            37 => QueryType::CERT,
            39 => QueryType::DNAME,
            41 => QueryType::OPT,
            42 => QueryType::APL,
            43 => QueryType::DS,
            44 => QueryType::SSHFP,
            45 => QueryType::IPSECKEY,
            46 => QueryType::RRSIG,
            47 => QueryType::NSEC,
            48 => QueryType::DNSKEY,
            49 => QueryType::DHCID,
            50 => QueryType::NSEC3,
            51 => QueryType::NSEC3PARAM,
            52 => QueryType::TLSA,
            53 => QueryType::SMIMEA,
            55 => QueryType::HIP,
            56 => QueryType::NINFO,
            57 => QueryType::RKEY,
            58 => QueryType::TALINK,
            59 => QueryType::CDS,
            60 => QueryType::CDNSKEY,
            61 => QueryType::OPENPGPKEY,
            62 => QueryType::CSYNC,
            63 => QueryType::ZONEMD,
            64 => QueryType::SVCB,
            65 => QueryType::HTTPS,
            99 => QueryType::SPF,
            100 => QueryType::UINFO,
            101 => QueryType::UID,
            102 => QueryType::GID,
            103 => QueryType::UNSPEC,
            104 => QueryType::NID,
            105 => QueryType::L32,
            106 => QueryType::L64,
            107 => QueryType::LP,
            108 => QueryType::EUI48,
            109 => QueryType::EUI64,
            128 => QueryType::NXNAME,
            256 => QueryType::URI,
            257 => QueryType::CAA,
            258 => QueryType::AVC,
            260 => QueryType::AMTRELAY,
            249 => QueryType::TKEY,
            250 => QueryType::TSIG,
            251 => QueryType::IXFR,
            252 => QueryType::AXFR,
            253 => QueryType::MAILB,
            254 => QueryType::MAILA,
            255 => QueryType::ANY,
            32768 => QueryType::TA,
            32769 => QueryType::DLV,
            65535 => QueryType::Reserved,
            _ => QueryType::Unknown,
        }
    }
}
