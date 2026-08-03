//! Minimal DER walker — just enough to pull the `SubjectPublicKeyInfo` out of
//! an X.509 certificate so we can pin it.
//!
//! We deliberately do NOT pull in a full X.509 parser. The only structural
//! question we ask of a peer certificate is "what is your public key?", and the
//! answer is the 7th element of `TBSCertificate`. Everything else about the
//! certificate (issuer, validity, extensions) is irrelevant to us: trust is
//! anchored on the pinned key, not on a name or a CA.
//!
//! This parser is strict — indefinite lengths, non-minimal lengths, and
//! truncated input are all rejected — because it runs on attacker-controlled
//! bytes during the TLS handshake.

use crate::error::{Error, Result};

/// DER tag for a constructed SEQUENCE.
const TAG_SEQUENCE: u8 = 0x30;
/// DER tag for the `[0] EXPLICIT` version field of a TBSCertificate.
const TAG_CONTEXT_0: u8 = 0xA0;

/// One parsed TLV: its tag, its content bytes, and how many bytes of the input
/// the whole element (header + content) occupied.
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    total_len: usize,
}

/// Read one DER TLV from the front of `buf`.
///
/// Rejects indefinite-length encodings, non-minimal length encodings, lengths
/// wider than 4 bytes, and any element that runs off the end of `buf`.
fn read_tlv(buf: &[u8]) -> Result<Tlv<'_>> {
    if buf.len() < 2 {
        return Err(Error::Invalid("der: truncated tag/length".into()));
    }
    let tag = buf[0];
    // High-tag-number form (tag byte 0x1F in the low bits) never appears in the
    // structures we walk; refusing it keeps the parser tiny.
    if tag & 0x1F == 0x1F {
        return Err(Error::Invalid("der: multi-byte tags unsupported".into()));
    }
    let first_len = buf[1];
    let (content_start, content_len) = if first_len < 0x80 {
        (2usize, first_len as usize)
    } else {
        let n = (first_len & 0x7F) as usize;
        if n == 0 {
            return Err(Error::Invalid("der: indefinite length not allowed".into()));
        }
        if n > 4 {
            return Err(Error::Invalid("der: length too wide".into()));
        }
        if buf.len() < 2 + n {
            return Err(Error::Invalid("der: truncated length".into()));
        }
        let bytes = &buf[2..2 + n];
        if bytes[0] == 0 {
            return Err(Error::Invalid("der: non-minimal length".into()));
        }
        let mut len: usize = 0;
        for b in bytes {
            len = (len << 8) | *b as usize;
        }
        if len < 0x80 {
            return Err(Error::Invalid("der: non-minimal length".into()));
        }
        (2 + n, len)
    };

    let total_len = content_start
        .checked_add(content_len)
        .ok_or_else(|| Error::Invalid("der: length overflow".into()))?;
    if buf.len() < total_len {
        return Err(Error::Invalid("der: element runs past end of buffer".into()));
    }
    Ok(Tlv { tag, content: &buf[content_start..total_len], total_len })
}

/// Extract the raw DER `SubjectPublicKeyInfo` element (including its own
/// SEQUENCE header) from an X.509 certificate.
///
/// Layout being walked:
/// ```text
/// Certificate ::= SEQUENCE {
///   tbsCertificate ::= SEQUENCE {
///     [0] version          -- optional
///     serialNumber         -- 1
///     signature            -- 2
///     issuer               -- 3
///     validity             -- 4
///     subject              -- 5
///     subjectPublicKeyInfo -- 6  <-- what we want
///     ...
///   }
///   signatureAlgorithm
///   signatureValue
/// }
/// ```
pub fn subject_public_key_info(cert_der: &[u8]) -> Result<&[u8]> {
    let cert = read_tlv(cert_der)?;
    if cert.tag != TAG_SEQUENCE {
        return Err(Error::Invalid("der: certificate is not a SEQUENCE".into()));
    }
    let tbs = read_tlv(cert.content)?;
    if tbs.tag != TAG_SEQUENCE {
        return Err(Error::Invalid("der: tbsCertificate is not a SEQUENCE".into()));
    }

    let mut rest = tbs.content;
    // Skip the optional [0] EXPLICIT version.
    let first = read_tlv(rest)?;
    if first.tag == TAG_CONTEXT_0 {
        rest = &rest[first.total_len..];
    }
    // Skip serialNumber, signature, issuer, validity, subject.
    for field in ["serialNumber", "signature", "issuer", "validity", "subject"] {
        let tlv = read_tlv(rest)
            .map_err(|e| Error::Invalid(format!("der: while skipping {field}: {e}")))?;
        rest = &rest[tlv.total_len..];
    }

    let spki = read_tlv(rest)?;
    if spki.tag != TAG_SEQUENCE {
        return Err(Error::Invalid("der: subjectPublicKeyInfo is not a SEQUENCE".into()));
    }
    Ok(&rest[..spki.total_len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_truncated() {
        assert!(read_tlv(&[]).is_err());
        assert!(read_tlv(&[0x30]).is_err());
        assert!(read_tlv(&[0x30, 0x05, 0x00]).is_err());
    }

    #[test]
    fn rejects_indefinite_and_non_minimal_lengths() {
        assert!(read_tlv(&[0x30, 0x80]).is_err());
        // 0x81 0x7F is non-minimal (0x7F fits in the short form).
        assert!(read_tlv(&[0x30, 0x81, 0x7F]).is_err());
        // Leading zero byte in a long-form length.
        assert!(read_tlv(&[0x30, 0x82, 0x00, 0x81]).is_err());
    }

    #[test]
    fn reads_short_and_long_form() {
        let short = [0x30u8, 0x02, 0xAA, 0xBB];
        let t = read_tlv(&short).unwrap();
        assert_eq!(t.tag, 0x30);
        assert_eq!(t.content, &[0xAA, 0xBB]);
        assert_eq!(t.total_len, 4);

        let mut long = vec![0x04u8, 0x81, 0x80];
        long.extend(std::iter::repeat_n(0x11u8, 0x80));
        let t = read_tlv(&long).unwrap();
        assert_eq!(t.tag, 0x04);
        assert_eq!(t.content.len(), 0x80);
        assert_eq!(t.total_len, 3 + 0x80);
    }

    #[test]
    fn rejects_garbage_certificate() {
        assert!(subject_public_key_info(&[0x02, 0x01, 0x00]).is_err());
        assert!(subject_public_key_info(&[]).is_err());
        // A SEQUENCE containing only a SEQUENCE with too few fields.
        assert!(subject_public_key_info(&[0x30, 0x02, 0x30, 0x00]).is_err());
    }
}
