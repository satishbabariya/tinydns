use log_execution_time::log_execution_time;
use super::header::Header;
use super::question::Question;
use super::resource_record::{RecordClass, RecordType, ResourceRecord};

#[derive(Debug)]
pub struct DNSMessage {
    pub header: Header,
    pub questions: Vec<Question>,
    // pub answers: Vec<ResourceRecord>,
    // pub authority_records: Vec<ResourceRecord>,
    // pub additional_records: Vec<ResourceRecord>,
}

impl DNSMessage {

    #[log_execution_time]
    pub fn parse(query_buffer: &[u8]) -> Self {
        let header = Header::parse(query_buffer);
        let questions = Self::parse_questions(query_buffer, header.question_count);

        // let mut index = 12 + query_buffer[12..].len(); // Skip the header and questions
        // let mut answers = Vec::new();
        // for _ in 0..header.answer_count {
        //     let answer = ResourceRecord::parse(&query_buffer[index..]);
        //     answers.push(answer);
        //     index += 1; // Move to the next answer
        // }
        //
        // let mut authority_records = Vec::new();
        // for _ in 0..header.authority_count {
        //     let authority_record = ResourceRecord::parse(&query_buffer[index..]);
        //     authority_records.push(authority_record);
        //     index += 1; // Move to the next authority record
        // }
        //
        // let mut additional_records = Vec::new();
        // for _ in 0..header.additional_count {
        //     let additional_record = ResourceRecord::parse(&query_buffer[index..]);
        //     additional_records.push(additional_record);
        //     index += 1; // Move to the next additional record
        // }

        DNSMessage {
            header,
            questions,
            // answers,
            // authority_records,
            // additional_records,
        }
    }

    fn parse_questions(query_buffer: &[u8], question_count: u16) -> Vec<Question> {
        let mut questions = Vec::new();
        let mut index = 12; // Skip the header
        for _ in 0..question_count {
            let question = Question::parse(&query_buffer[index..]);
            questions.push(question);
            index += 1; // Move to the next question
        }
        questions
    }

}