use super::resource_record::{RecordClass, RecordType};

#[derive(Debug)]
pub struct Question {
    pub name: String,
    pub record_type: RecordType,
    pub class: RecordClass,
}

impl Question {
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
        let query_type = RecordType::from_u16(u16::from_be_bytes([
            query_buffer[index],
            query_buffer[index + 1],
        ]));
        index += 2;

        // Parse the query class (next 2 bytes)
        let query_class = RecordClass::from_u16(u16::from_be_bytes([
            query_buffer[index],
            query_buffer[index + 1],
        ]));

        Question {
            name: domain_name,
            record_type: query_type,
            class: query_class,
        }
    }
}
