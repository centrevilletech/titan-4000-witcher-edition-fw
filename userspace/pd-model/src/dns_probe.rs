//! A DNS question for the boot confirm (v1.0.17).
//!
//! The boot confirm needs one answer through the core. It pings its targets,
//! and since v1.0.17 also asks each one a DNS question: a carrier's DNS
//! servers often ignore ping but must answer DNS, or no customer could
//! browse. Any reply to the question counts, whatever it says, because it
//! went up and came back through the core.

/// A question for the root zone's name servers (`.`, NS, IN), with
/// recursion desired. Every resolver can answer it from its root hints.
pub fn query(id: u16) -> [u8; 17] {
    let [hi, lo] = id.to_be_bytes();
    [hi, lo, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0x00, 0, 2, 0, 1]
}

/// `reply` answers the question `id`: a DNS header with the same id and the
/// response bit set. The answer itself does not matter.
pub fn answers(id: u16, reply: &[u8]) -> bool {
    reply.len() >= 12 && reply[..2] == id.to_be_bytes() && reply[2] & 0x80 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_with_the_same_id_answers_whatever_it_says() {
        let question = query(0xbeef);
        assert_eq!(&question[..2], &[0xbe, 0xef]);
        assert!(!answers(0xbeef, &question), "the question is no answer");
        let mut reply = question.to_vec();
        reply[2] |= 0x80;
        assert!(answers(0xbeef, &reply));
        reply[3] = 0x05; // REFUSED still went up and came back.
        assert!(answers(0xbeef, &reply));
        assert!(!answers(0xbeee, &reply));
        assert!(!answers(0xbeef, &reply[..11]));
    }
}
