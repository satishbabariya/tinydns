#[derive(Debug)]
pub struct ResourceRecord {
    pub name: String,
    pub record_type: RecordType,
    pub class: RecordClass,
    pub ttl: u32,
    pub data_length: u16,
    pub data: Vec<u8>,
}

impl ResourceRecord {
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
        let record_type = RecordType::from_u16(u16::from_be_bytes([
            query_buffer[index],
            query_buffer[index + 1],
        ]));
        index += 2;

        // Parse the query class (next 2 bytes)
        let class = RecordClass::from_u16(u16::from_be_bytes([
            query_buffer[index],
            query_buffer[index + 1],
        ]));
        index += 2;

        // Parse the TTL (next 4 bytes)
        let ttl = u32::from_be_bytes([
            query_buffer[index],
            query_buffer[index + 1],
            query_buffer[index + 2],
            query_buffer[index + 3],
        ]);
        index += 4;

        // Parse the data length (next 2 bytes)
        let data_length = u16::from_be_bytes([query_buffer[index], query_buffer[index + 1]]);
        index += 2;

        // Parse the data
        let data = query_buffer[index..index + data_length as usize].to_vec();

        ResourceRecord {
            name: domain_name,
            record_type,
            class,
            ttl,
            data_length,
            data,
        }
    }
}

#[repr(u16)]
#[derive(Debug)]
pub enum RecordClass {
    IN = 1,
    CH = 3,
    HS = 4,
    NONE = 254,
    ANY = 255,
    OPT = 41,
    Unknown = 0,
}

impl RecordClass {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => RecordClass::IN,
            3 => RecordClass::CH,
            4 => RecordClass::HS,
            254 => RecordClass::NONE,
            255 => RecordClass::ANY,
            41 => RecordClass::OPT,
            _ => RecordClass::Unknown,
        }
    }
}

#[derive(Debug)]
pub enum RecordType {
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

impl RecordType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            2 => RecordType::NS,
            3 => RecordType::MD,
            4 => RecordType::MF,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            7 => RecordType::MB,
            8 => RecordType::MG,
            9 => RecordType::MR,
            10 => RecordType::Null,
            12 => RecordType::PTR,
            13 => RecordType::HINFO,
            14 => RecordType::MINFO,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            17 => RecordType::RP,
            18 => RecordType::AFSDB,
            19 => RecordType::X25,
            20 => RecordType::ISDN,
            21 => RecordType::RT,
            23 => RecordType::NSAPPTR,
            24 => RecordType::SIG,
            25 => RecordType::KEY,
            26 => RecordType::PX,
            27 => RecordType::GPOS,
            28 => RecordType::AAAA,
            29 => RecordType::LOC,
            30 => RecordType::NXT,
            31 => RecordType::EID,
            32 => RecordType::NIMLOC,
            33 => RecordType::SRV,
            34 => RecordType::ATMA,
            35 => RecordType::NAPTR,
            36 => RecordType::KX,
            37 => RecordType::CERT,
            39 => RecordType::DNAME,
            41 => RecordType::OPT,
            42 => RecordType::APL,
            43 => RecordType::DS,
            44 => RecordType::SSHFP,
            45 => RecordType::IPSECKEY,
            46 => RecordType::RRSIG,
            47 => RecordType::NSEC,
            48 => RecordType::DNSKEY,
            49 => RecordType::DHCID,
            50 => RecordType::NSEC3,
            51 => RecordType::NSEC3PARAM,
            52 => RecordType::TLSA,
            53 => RecordType::SMIMEA,
            55 => RecordType::HIP,
            56 => RecordType::NINFO,
            57 => RecordType::RKEY,
            58 => RecordType::TALINK,
            59 => RecordType::CDS,
            60 => RecordType::CDNSKEY,
            61 => RecordType::OPENPGPKEY,
            62 => RecordType::CSYNC,
            63 => RecordType::ZONEMD,
            64 => RecordType::SVCB,
            65 => RecordType::HTTPS,
            99 => RecordType::SPF,
            100 => RecordType::UINFO,
            101 => RecordType::UID,
            102 => RecordType::GID,
            103 => RecordType::UNSPEC,
            104 => RecordType::NID,
            105 => RecordType::L32,
            106 => RecordType::L64,
            107 => RecordType::LP,
            108 => RecordType::EUI48,
            109 => RecordType::EUI64,
            128 => RecordType::NXNAME,
            256 => RecordType::URI,
            257 => RecordType::CAA,
            258 => RecordType::AVC,
            260 => RecordType::AMTRELAY,
            249 => RecordType::TKEY,
            250 => RecordType::TSIG,
            251 => RecordType::IXFR,
            252 => RecordType::AXFR,
            253 => RecordType::MAILB,
            254 => RecordType::MAILA,
            255 => RecordType::ANY,
            32768 => RecordType::TA,
            32769 => RecordType::DLV,
            65535 => RecordType::Reserved,
            _ => RecordType::Unknown,
        }
    }
}
