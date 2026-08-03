//! A hand-rolled STUN client: the RFC 5389 / RFC 8489 subset DirectDesk needs.
//!
//! We only ever send a Binding Request and read the reflexive transport address
//! back out of the response. No authentication, no TURN, no ICE — those would
//! pull in a large dependency for something this crate uses once, at the user's
//! request, from a settings screen.
//!
//! Parsing rules (this code reads bytes from an unauthenticated remote, so it is
//! written defensively):
//! - Every read is bounds-checked; the parser never indexes without a length
//!   check and never panics on any input. Malformed input yields [`StunError`].
//! - The magic cookie and the transaction ID must both match, which is the only
//!   thing standing between us and an off-path spoofer. A 96-bit transaction ID
//!   is what RFC 5389 §6 gives us for that job.
//! - Attributes past the declared message length are ignored, and an attribute
//!   whose declared length runs past the message is a hard error.
//!
//! Only the attributes we act on are decoded: XOR-MAPPED-ADDRESS, the legacy
//! MAPPED-ADDRESS, and ERROR-CODE. Everything else is skipped by length.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;

/// RFC 5389 magic cookie. Present in every modern STUN message.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Fixed STUN header size in bytes.
pub const HEADER_LEN: usize = 20;

/// Largest response we will even look at. STUN messages are tiny; anything
/// bigger is either not for us or an attempt to make us allocate.
pub const MAX_MESSAGE_LEN: usize = 1280;

// Message types (class + method) we care about.
const TYPE_BINDING_REQUEST: u16 = 0x0001;
const TYPE_BINDING_SUCCESS: u16 = 0x0101;
const TYPE_BINDING_ERROR: u16 = 0x0111;

// Attribute types.
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// Pre-standard XOR-MAPPED-ADDRESS still emitted by some old servers.
const ATTR_XOR_MAPPED_ADDRESS_LEGACY: u16 = 0x8020;

const FAMILY_V4: u8 = 0x01;
const FAMILY_V6: u8 = 0x02;

/// Everything that can go wrong decoding a STUN response.
///
/// This is a *data* error type: it means the peer sent us something we could not
/// use, which is a normal thing to observe on the open internet, not a bug.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StunError {
    /// Fewer bytes than a STUN header.
    #[error("stun message too short: {got} bytes (need at least {HEADER_LEN})")]
    TooShort { got: usize },
    /// Leading bits or magic cookie say this is not a STUN message.
    #[error("not a stun message (bad leading bits or magic cookie)")]
    NotStun,
    /// The declared attribute length does not fit the datagram.
    #[error("stun length {declared} exceeds {available} available bytes")]
    BadLength { declared: usize, available: usize },
    /// RFC 5389 requires the message length to be a multiple of four.
    #[error("stun length {0} is not a multiple of 4")]
    UnalignedLength(u16),
    /// The transaction ID did not match the request we sent.
    #[error("stun transaction id mismatch")]
    TransactionMismatch,
    /// The server answered with an error response.
    #[error("stun error response {code}: {reason}")]
    ErrorResponse { code: u16, reason: String },
    /// Not a binding success or error response.
    #[error("unexpected stun message type 0x{0:04x}")]
    UnexpectedType(u16),
    /// A success response carried no address we could read.
    #[error("stun response carried no mapped address")]
    NoMappedAddress,
    /// Address family byte was neither IPv4 nor IPv6.
    #[error("unknown stun address family 0x{0:02x}")]
    BadAddressFamily(u8),
    /// An attribute claimed more bytes than the message contains.
    #[error("truncated stun attribute 0x{attr:04x}")]
    TruncatedAttribute { attr: u16 },
}

/// A 96-bit STUN transaction ID.
///
/// Must be cryptographically random per RFC 5389 §6: it is the only thing that
/// makes a response hard to forge without seeing the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TransactionId([u8; 12]);

impl TransactionId {
    /// Draw a fresh random transaction ID.
    pub fn random() -> Self {
        TransactionId(rand::random::<[u8; 12]>())
    }

    /// Wrap explicit bytes (used by tests and by response matching).
    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        TransactionId(bytes)
    }

    /// The raw 12 bytes.
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

/// Encode a Binding Request: a bare 20-byte header, no attributes.
///
/// RFC 5389 permits an attribute-free binding request, and adding SOFTWARE only
/// leaks our version string to third parties, so we don't.
pub fn binding_request(txid: &TransactionId) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    out[0..2].copy_from_slice(&TYPE_BINDING_REQUEST.to_be_bytes());
    out[2..4].copy_from_slice(&0u16.to_be_bytes()); // length: no attributes
    out[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out[8..20].copy_from_slice(txid.as_bytes());
    out
}

/// Read the transaction ID out of a datagram without validating anything else.
///
/// Used to demultiplex responses arriving on one socket from several servers.
/// Returns `None` if the datagram is too short or is not STUN-shaped.
pub fn peek_transaction_id(buf: &[u8]) -> Option<TransactionId> {
    if buf.len() < HEADER_LEN || buf[0] & 0xC0 != 0 {
        return None;
    }
    if u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) != MAGIC_COOKIE {
        return None;
    }
    let mut id = [0u8; 12];
    id.copy_from_slice(&buf[8..20]);
    Some(TransactionId(id))
}

/// Parse a Binding Response and return our reflexive transport address.
///
/// `expect` is the transaction ID of the request this is supposed to answer; a
/// mismatch is rejected rather than trusted.
pub fn parse_binding_response(buf: &[u8], expect: &TransactionId) -> Result<SocketAddr, StunError> {
    if buf.len() < HEADER_LEN {
        return Err(StunError::TooShort { got: buf.len() });
    }
    // The two most significant bits of a STUN message are always zero.
    if buf[0] & 0xC0 != 0 {
        return Err(StunError::NotStun);
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let declared = u16::from_be_bytes([buf[2], buf[3]]);
    if u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) != MAGIC_COOKIE {
        return Err(StunError::NotStun);
    }
    if !declared.is_multiple_of(4) {
        return Err(StunError::UnalignedLength(declared));
    }
    let body_len = declared as usize;
    let available = buf.len() - HEADER_LEN;
    if body_len > available {
        return Err(StunError::BadLength { declared: body_len, available });
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&buf[8..20]);
    if &txid != expect.as_bytes() {
        return Err(StunError::TransactionMismatch);
    }

    match msg_type {
        TYPE_BINDING_SUCCESS => {}
        TYPE_BINDING_ERROR => return Err(parse_error_code(&buf[HEADER_LEN..HEADER_LEN + body_len])),
        other => return Err(StunError::UnexpectedType(other)),
    }

    let body = &buf[HEADER_LEN..HEADER_LEN + body_len];
    // Prefer XOR-MAPPED-ADDRESS; fall back through the legacy variants. We scan
    // the whole body once and keep the best candidate found.
    let mut best: Option<(u8, SocketAddr)> = None;
    let mut err: Option<StunError> = None;
    for attr in AttrIter::new(body) {
        let (atype, value) = attr?;
        let (rank, decoded) = match atype {
            ATTR_XOR_MAPPED_ADDRESS => (2u8, decode_address(value, Some(&txid))),
            ATTR_XOR_MAPPED_ADDRESS_LEGACY => (1u8, decode_address(value, Some(&txid))),
            ATTR_MAPPED_ADDRESS => (0u8, decode_address(value, None)),
            _ => continue,
        };
        match decoded {
            Ok(addr) => {
                if best.as_ref().is_none_or(|(r, _)| rank > *r) {
                    best = Some((rank, addr));
                }
            }
            Err(e) => err = Some(e),
        }
    }

    match best {
        Some((_, addr)) => Ok(addr),
        None => Err(err.unwrap_or(StunError::NoMappedAddress)),
    }
}

/// Iterator over TLV attributes in a STUN body, with bounds checking.
struct AttrIter<'a> {
    body: &'a [u8],
    off: usize,
}

impl<'a> AttrIter<'a> {
    fn new(body: &'a [u8]) -> Self {
        AttrIter { body, off: 0 }
    }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Result<(u16, &'a [u8]), StunError>;

    fn next(&mut self) -> Option<Self::Item> {
        // A trailing stub shorter than a TLV header is padding, not an error.
        if self.off + 4 > self.body.len() {
            return None;
        }
        let atype = u16::from_be_bytes([self.body[self.off], self.body[self.off + 1]]);
        let alen = u16::from_be_bytes([self.body[self.off + 2], self.body[self.off + 3]]) as usize;
        let vstart = self.off + 4;
        let vend = match vstart.checked_add(alen) {
            Some(v) if v <= self.body.len() => v,
            _ => {
                self.off = self.body.len();
                return Some(Err(StunError::TruncatedAttribute { attr: atype }));
            }
        };
        // Values are padded to a 4-byte boundary; the padding is not counted in
        // the attribute length but is present in the message.
        self.off = vend + ((4 - (alen % 4)) % 4);
        Some(Ok((atype, &self.body[vstart..vend])))
    }
}

/// Decode a MAPPED-ADDRESS-shaped attribute value.
///
/// `xor_txid` is `Some` for the XOR variants: the port is XORed with the top 16
/// bits of the magic cookie and the address with the cookie (IPv4) or the cookie
/// concatenated with the transaction ID (IPv6).
fn decode_address(value: &[u8], xor_txid: Option<&[u8; 12]>) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::TruncatedAttribute { attr: ATTR_XOR_MAPPED_ADDRESS });
    }
    let family = value[1];
    let raw_port = u16::from_be_bytes([value[2], value[3]]);
    let port = match xor_txid {
        Some(_) => raw_port ^ ((MAGIC_COOKIE >> 16) as u16),
        None => raw_port,
    };
    let cookie = MAGIC_COOKIE.to_be_bytes();

    match family {
        FAMILY_V4 => {
            if value.len() < 8 {
                return Err(StunError::TruncatedAttribute { attr: ATTR_XOR_MAPPED_ADDRESS });
            }
            let mut octets = [0u8; 4];
            octets.copy_from_slice(&value[4..8]);
            if xor_txid.is_some() {
                for (i, b) in octets.iter_mut().enumerate() {
                    *b ^= cookie[i];
                }
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        FAMILY_V6 => {
            if value.len() < 20 {
                return Err(StunError::TruncatedAttribute { attr: ATTR_XOR_MAPPED_ADDRESS });
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            if let Some(txid) = xor_txid {
                let mut key = [0u8; 16];
                key[0..4].copy_from_slice(&cookie);
                key[4..16].copy_from_slice(txid);
                for (b, k) in octets.iter_mut().zip(key.iter()) {
                    *b ^= *k;
                }
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        other => Err(StunError::BadAddressFamily(other)),
    }
}

/// Turn an error response body into a [`StunError::ErrorResponse`].
fn parse_error_code(body: &[u8]) -> StunError {
    for attr in AttrIter::new(body).flatten() {
        let (atype, value) = attr;
        if atype == ATTR_ERROR_CODE && value.len() >= 4 {
            let class = u16::from(value[2] & 0x07);
            let number = u16::from(value[3]);
            let code = class * 100 + number.min(99);
            // Reason is UTF-8 per RFC 5389 and comes from a stranger: bound it
            // and replace anything invalid rather than trusting it.
            let reason: String =
                String::from_utf8_lossy(&value[4..]).chars().take(128).collect();
            return StunError::ErrorResponse { code, reason };
        }
    }
    StunError::ErrorResponse { code: 0, reason: "no error-code attribute".into() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5769 §2.1 sample transaction ID, reused by the sample responses.
    const RFC5769_TXID: [u8; 12] =
        [0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae];

    /// Build a binding success response carrying one attribute.
    fn response_with(txid: &[u8; 12], attr_type: u16, value: &[u8]) -> Vec<u8> {
        let pad = (4 - (value.len() % 4)) % 4;
        let body_len = 4 + value.len() + pad;
        let mut m = Vec::with_capacity(HEADER_LEN + body_len);
        m.extend_from_slice(&TYPE_BINDING_SUCCESS.to_be_bytes());
        m.extend_from_slice(&(body_len as u16).to_be_bytes());
        m.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        m.extend_from_slice(txid);
        m.extend_from_slice(&attr_type.to_be_bytes());
        m.extend_from_slice(&(value.len() as u16).to_be_bytes());
        m.extend_from_slice(value);
        m.extend(std::iter::repeat_n(0u8, pad));
        m
    }

    #[test]
    fn binding_request_is_well_formed() {
        let txid = TransactionId::from_bytes(RFC5769_TXID);
        let req = binding_request(&txid);
        assert_eq!(req.len(), HEADER_LEN);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), TYPE_BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0);
        assert_eq!(u32::from_be_bytes([req[4], req[5], req[6], req[7]]), MAGIC_COOKIE);
        assert_eq!(&req[8..20], &RFC5769_TXID);
        assert_eq!(peek_transaction_id(&req), Some(txid));
    }

    #[test]
    fn transaction_ids_are_random_and_distinct() {
        let a = TransactionId::random();
        let b = TransactionId::random();
        assert_ne!(a, b, "two random transaction ids collided");
        assert_ne!(a.as_bytes(), &[0u8; 12]);
    }

    #[test]
    fn parses_rfc5769_ipv4_xor_mapped_address() {
        // Exact XOR-MAPPED-ADDRESS bytes from RFC 5769 §2.2: 192.0.2.1:32853.
        let value = [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43];
        let msg = response_with(&RFC5769_TXID, ATTR_XOR_MAPPED_ADDRESS, &value);
        let got =
            parse_binding_response(&msg, &TransactionId::from_bytes(RFC5769_TXID)).unwrap();
        assert_eq!(got, "192.0.2.1:32853".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parses_rfc5769_ipv6_xor_mapped_address() {
        // Exact XOR-MAPPED-ADDRESS bytes from RFC 5769 §2.3:
        // [2001:db8:1234:5678:11:2233:4455:6677]:32853.
        let value = [
            0x00, 0x02, 0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25,
            0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9,
        ];
        let msg = response_with(&RFC5769_TXID, ATTR_XOR_MAPPED_ADDRESS, &value);
        let got =
            parse_binding_response(&msg, &TransactionId::from_bytes(RFC5769_TXID)).unwrap();
        assert_eq!(
            got,
            "[2001:db8:1234:5678:11:2233:4455:6677]:32853".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parses_legacy_plain_mapped_address() {
        // Not XORed: 203.0.113.9:4711.
        let value = [0x00, 0x01, 0x12, 0x67, 203, 0, 113, 9];
        let msg = response_with(&RFC5769_TXID, ATTR_MAPPED_ADDRESS, &value);
        let got =
            parse_binding_response(&msg, &TransactionId::from_bytes(RFC5769_TXID)).unwrap();
        assert_eq!(got, "203.0.113.9:4711".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn xor_mapped_address_wins_over_plain_mapped_address() {
        // A response carrying both must use the XOR variant: a plain
        // MAPPED-ADDRESS is what gets mangled by NATs that rewrite payloads.
        let xor = [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43]; // 192.0.2.1:32853
        let plain = [0x00, 0x01, 0x12, 0x67, 203, 0, 113, 9]; // 203.0.113.9:4711
        let mut body = Vec::new();
        body.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        body.extend_from_slice(&8u16.to_be_bytes());
        body.extend_from_slice(&plain);
        body.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        body.extend_from_slice(&8u16.to_be_bytes());
        body.extend_from_slice(&xor);

        let mut msg = Vec::new();
        msg.extend_from_slice(&TYPE_BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&(body.len() as u16).to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&RFC5769_TXID);
        msg.extend_from_slice(&body);

        let got =
            parse_binding_response(&msg, &TransactionId::from_bytes(RFC5769_TXID)).unwrap();
        assert_eq!(got, "192.0.2.1:32853".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn unknown_attributes_are_skipped_with_padding() {
        // SOFTWARE (0x8022) with a 3-byte value forces one byte of padding; the
        // XOR-MAPPED-ADDRESS after it must still be found.
        let mut body = Vec::new();
        body.extend_from_slice(&0x8022u16.to_be_bytes());
        body.extend_from_slice(&3u16.to_be_bytes());
        body.extend_from_slice(b"abc");
        body.push(0); // padding
        body.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        body.extend_from_slice(&8u16.to_be_bytes());
        body.extend_from_slice(&[0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43]);

        let mut msg = Vec::new();
        msg.extend_from_slice(&TYPE_BINDING_SUCCESS.to_be_bytes());
        msg.extend_from_slice(&(body.len() as u16).to_be_bytes());
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&RFC5769_TXID);
        msg.extend_from_slice(&body);

        let got =
            parse_binding_response(&msg, &TransactionId::from_bytes(RFC5769_TXID)).unwrap();
        assert_eq!(got, "192.0.2.1:32853".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn rejects_wrong_transaction_id() {
        let value = [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43];
        let msg = response_with(&RFC5769_TXID, ATTR_XOR_MAPPED_ADDRESS, &value);
        let other = TransactionId::from_bytes([9u8; 12]);
        assert_eq!(parse_binding_response(&msg, &other), Err(StunError::TransactionMismatch));
    }

    #[test]
    fn rejects_bad_magic_cookie() {
        let value = [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43];
        let mut msg = response_with(&RFC5769_TXID, ATTR_XOR_MAPPED_ADDRESS, &value);
        msg[4] ^= 0xff;
        assert_eq!(
            parse_binding_response(&msg, &TransactionId::from_bytes(RFC5769_TXID)),
            Err(StunError::NotStun)
        );
        assert_eq!(peek_transaction_id(&msg), None);
    }

    #[test]
    fn rejects_non_stun_leading_bits() {
        let value = [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43];
        let mut msg = response_with(&RFC5769_TXID, ATTR_XOR_MAPPED_ADDRESS, &value);
        msg[0] |= 0x80; // e.g. a TURN ChannelData frame or plain garbage
        assert_eq!(
            parse_binding_response(&msg, &TransactionId::from_bytes(RFC5769_TXID)),
            Err(StunError::NotStun)
        );
    }

    #[test]
    fn rejects_unaligned_and_oversized_length() {
        let value = [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43];
        let txid = TransactionId::from_bytes(RFC5769_TXID);

        let mut msg = response_with(&RFC5769_TXID, ATTR_XOR_MAPPED_ADDRESS, &value);
        msg[3] = 13; // not a multiple of 4
        assert_eq!(parse_binding_response(&msg, &txid), Err(StunError::UnalignedLength(13)));

        let mut msg = response_with(&RFC5769_TXID, ATTR_XOR_MAPPED_ADDRESS, &value);
        msg[2] = 0x0f;
        msg[3] = 0xfc; // claims 4092 body bytes
        assert!(matches!(
            parse_binding_response(&msg, &txid),
            Err(StunError::BadLength { declared: 4092, .. })
        ));
    }

    #[test]
    fn rejects_attribute_longer_than_message() {
        let value = [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43];
        let mut msg = response_with(&RFC5769_TXID, ATTR_XOR_MAPPED_ADDRESS, &value);
        // Attribute length field sits at body offset 2 -> absolute offset 22.
        msg[22] = 0x00;
        msg[23] = 0xff;
        assert_eq!(
            parse_binding_response(&msg, &TransactionId::from_bytes(RFC5769_TXID)),
            Err(StunError::TruncatedAttribute { attr: ATTR_XOR_MAPPED_ADDRESS })
        );
    }

    #[test]
    fn rejects_short_address_value_and_bad_family() {
        let txid = TransactionId::from_bytes(RFC5769_TXID);

        // Claims IPv6 but only carries an IPv4-sized value.
        let short_v6 = [0x00, 0x02, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43];
        let msg = response_with(&RFC5769_TXID, ATTR_XOR_MAPPED_ADDRESS, &short_v6);
        assert!(matches!(
            parse_binding_response(&msg, &txid),
            Err(StunError::TruncatedAttribute { .. })
        ));

        let bad_family = [0x00, 0x07, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43];
        let msg = response_with(&RFC5769_TXID, ATTR_XOR_MAPPED_ADDRESS, &bad_family);
        assert_eq!(parse_binding_response(&msg, &txid), Err(StunError::BadAddressFamily(0x07)));
    }

    #[test]
    fn success_without_any_address_is_an_error() {
        let msg = response_with(&RFC5769_TXID, 0x8022, b"just software");
        assert_eq!(
            parse_binding_response(&msg, &TransactionId::from_bytes(RFC5769_TXID)),
            Err(StunError::NoMappedAddress)
        );
    }

    #[test]
    fn decodes_error_response() {
        // ERROR-CODE 400 Bad Request.
        let mut value = vec![0x00, 0x00, 0x04, 0x00];
        value.extend_from_slice(b"Bad Request");
        let mut msg = response_with(&RFC5769_TXID, ATTR_ERROR_CODE, &value);
        msg[0..2].copy_from_slice(&TYPE_BINDING_ERROR.to_be_bytes());
        let err =
            parse_binding_response(&msg, &TransactionId::from_bytes(RFC5769_TXID)).unwrap_err();
        assert_eq!(err, StunError::ErrorResponse { code: 400, reason: "Bad Request".into() });
    }

    #[test]
    fn rejects_unexpected_message_type() {
        let value = [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43];
        let mut msg = response_with(&RFC5769_TXID, ATTR_XOR_MAPPED_ADDRESS, &value);
        msg[0..2].copy_from_slice(&0x0011u16.to_be_bytes()); // binding indication
        assert_eq!(
            parse_binding_response(&msg, &TransactionId::from_bytes(RFC5769_TXID)),
            Err(StunError::UnexpectedType(0x0011))
        );
    }

    #[test]
    fn every_truncation_of_a_valid_message_is_rejected_without_panicking() {
        let value = [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43];
        let msg = response_with(&RFC5769_TXID, ATTR_XOR_MAPPED_ADDRESS, &value);
        let txid = TransactionId::from_bytes(RFC5769_TXID);
        assert!(parse_binding_response(&msg, &txid).is_ok());

        for cut in 0..msg.len() {
            let res = parse_binding_response(&msg[..cut], &txid);
            assert!(res.is_err(), "truncation to {cut} bytes was accepted");
        }
    }

    #[test]
    fn every_single_byte_corruption_is_handled_without_panicking() {
        let value = [0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43];
        let msg = response_with(&RFC5769_TXID, ATTR_XOR_MAPPED_ADDRESS, &value);
        let txid = TransactionId::from_bytes(RFC5769_TXID);

        for i in 0..msg.len() {
            for bit in 0..8u32 {
                let mut corrupt = msg.clone();
                corrupt[i] ^= 1 << bit;
                // The contract is "never panics", not "always rejects": flipping
                // a bit inside the address value yields a different but
                // perfectly valid address.
                let _ = parse_binding_response(&corrupt, &txid);
                let _ = peek_transaction_id(&corrupt);
            }
        }
    }

    #[test]
    fn arbitrary_garbage_never_panics() {
        let txid = TransactionId::random();
        let mut seed = 0x1234_5678_9abc_def0u64;
        for len in 0..80usize {
            for _ in 0..40 {
                let buf: Vec<u8> = (0..len)
                    .map(|_| {
                        // xorshift64: deterministic, no dev-dependency needed.
                        seed ^= seed << 13;
                        seed ^= seed >> 7;
                        seed ^= seed << 17;
                        (seed & 0xff) as u8
                    })
                    .collect();
                let _ = parse_binding_response(&buf, &txid);
                let _ = peek_transaction_id(&buf);
            }
        }
    }

    #[test]
    fn zero_length_attribute_does_not_stall_the_iterator() {
        // An attribute with length 0 must advance the cursor by its 4-byte
        // header, otherwise a hostile server could spin us forever.
        let mut body = Vec::new();
        for _ in 0..3 {
            body.extend_from_slice(&0x8022u16.to_be_bytes());
            body.extend_from_slice(&0u16.to_be_bytes());
        }
        let count = AttrIter::new(&body).count();
        assert_eq!(count, 3);
    }
}
