//! CTAP2 command codes, status codes and the small amount of CBOR inspection the
//! bridge needs. Requests are otherwise forwarded to the phone untouched.

use ciborium::Value;
use sha2::{Digest, Sha256};

pub mod command {
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    pub const GET_ASSERTION: u8 = 0x02;
    pub const GET_INFO: u8 = 0x04;
    pub const RESET: u8 = 0x07;
    pub const GET_NEXT_ASSERTION: u8 = 0x08;
    pub const SELECTION: u8 = 0x0b;
}

pub mod status {
    pub const OK: u8 = 0x00;
    pub const INVALID_COMMAND: u8 = 0x01;
    pub const INVALID_CBOR: u8 = 0x12;
    pub const MISSING_PARAMETER: u8 = 0x14;
    pub const OPERATION_DENIED: u8 = 0x27;
    pub const KEEPALIVE_CANCEL: u8 = 0x2d;
    pub const NO_CREDENTIALS: u8 = 0x2e;
    pub const USER_ACTION_TIMEOUT: u8 = 0x2f;
    pub const NOT_ALLOWED: u8 = 0x30;
    pub const OTHER: u8 = 0x7f;
}

/// Relying party IDs that browsers use for "blink to select this key" requests:
/// Firefox (authenticator-rs) and Chromium respectively.
pub const SELECTION_RP_IDS: &[&str] = &["make.me.blink", ".dummy"];

pub fn status_only(code: u8) -> Vec<u8> {
    vec![code]
}

pub fn ok_with(body: &Value) -> Vec<u8> {
    let mut out = vec![status::OK];
    ciborium::into_writer(body, &mut out).expect("serialising to a Vec cannot fail");
    out
}

pub struct GetInfoParams {
    pub aaguid: [u8; 16],
    pub max_msg_size: usize,
    pub max_credential_count_in_list: u32,
}

/// The authenticatorGetInfo response advertised to the browser.
///
/// We claim CTAP 2.0 with built-in user verification and no clientPin, so
/// browsers send `uv: true` directly instead of trying to negotiate a PIN/UV
/// auth token, which the phone could not use anyway.
pub fn get_info(params: &GetInfoParams) -> Vec<u8> {
    let body = Value::Map(vec![
        (int(0x01), Value::Array(vec![text("FIDO_2_0")])),
        (int(0x03), Value::Bytes(params.aaguid.to_vec())),
        (
            int(0x04),
            // CTAP2 canonical CBOR: shorter keys first, then bytewise.
            Value::Map(vec![
                (text("rk"), Value::Bool(true)),
                (text("up"), Value::Bool(true)),
                (text("uv"), Value::Bool(true)),
                (text("plat"), Value::Bool(false)),
            ]),
        ),
        (int(0x05), int(params.max_msg_size as i64)),
        (int(0x07), int(params.max_credential_count_in_list as i64)),
        (int(0x09), Value::Array(vec![text("hybrid")])),
    ]);
    ok_with(&body)
}

/// A parsed makeCredential or getAssertion request.
pub struct Request {
    pub command: u8,
    entries: Vec<(Value, Value)>,
}

impl Request {
    pub fn parse(command: u8, cbor: &[u8]) -> Result<Self, u8> {
        match ciborium::from_reader::<Value, _>(cbor) {
            Ok(Value::Map(entries)) => Ok(Self { command, entries }),
            _ => Err(status::INVALID_CBOR),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(self.entries.clone()), &mut out)
            .expect("serialising to a Vec cannot fail");
        out
    }

    fn get(&self, key: i64) -> Option<&Value> {
        self.entries
            .iter()
            .find(|(k, _)| k.as_integer() == Some(key.into()))
            .map(|(_, v)| v)
    }

    fn get_mut(&mut self, key: i64) -> Option<&mut Value> {
        self.entries
            .iter_mut()
            .find(|(k, _)| k.as_integer() == Some(key.into()))
            .map(|(_, v)| v)
    }

    pub fn rp_id(&self) -> Option<&str> {
        match self.command {
            command::GET_ASSERTION => self.get(0x01)?.as_text(),
            command::MAKE_CREDENTIAL => map_get(self.get(0x02)?, "id")?.as_text(),
            _ => None,
        }
    }

    /// Index of the credential list: allowList for getAssertion, excludeList for makeCredential.
    fn list_key(&self) -> i64 {
        if self.command == command::GET_ASSERTION {
            0x03
        } else {
            0x05
        }
    }

    pub fn credential_list(&self) -> &[Value] {
        match self.get(self.list_key()) {
            Some(Value::Array(list)) => list,
            _ => &[],
        }
    }

    pub fn set_credential_list(&mut self, list: Vec<Value>) {
        let key = self.list_key();
        match self.get_mut(key) {
            Some(slot) => *slot = Value::Array(list),
            None => {
                self.entries.push((int(key), Value::Array(list)));
                self.entries.sort_by(|(a, _), (b, _)| cmp_int_keys(a, b));
            }
        }
    }

    /// Turns a getAssertion into a discoverable-credential request.
    pub fn clear_allow_list(&mut self) {
        if self.command == command::GET_ASSERTION {
            self.entries
                .retain(|(k, _)| k.as_integer() != Some(0x03.into()));
        }
    }

    fn option(&self, name: &str) -> Option<bool> {
        map_get(self.get(self.option_key() as i64)?, name)?.as_bool()
    }

    /// True for getAssertion requests with `up: false`. The WebAuthn API cannot
    /// produce these, so they only come from the browser probing which
    /// credentials an authenticator holds ("pre-flight").
    pub fn is_silent_probe(&self) -> bool {
        self.command == command::GET_ASSERTION && self.option("up") == Some(false)
    }

    /// Rewrites the request into the form Chromium sends, which is what phones'
    /// hybrid authenticators are tested against: `up: true` is the default and
    /// Chromium only ever sends `up: false`. Firefox sends it explicitly.
    pub fn normalize_for_phone(&mut self) {
        if self.command != command::GET_ASSERTION {
            return;
        }
        let Some(Value::Map(options)) = self.get_mut(0x05) else {
            return;
        };
        options.retain(|(k, v)| !(k.as_text() == Some("up") && v.as_bool() == Some(true)));
        if options.is_empty() {
            self.entries
                .retain(|(k, _)| k.as_integer() != Some(0x05.into()));
        }
    }

    /// Shape of the request for logs: keys, list lengths and options, but no
    /// hashes, credential IDs or user data.
    pub fn summary(&self) -> String {
        self.entries
            .iter()
            .map(|(k, v)| {
                let key: i128 = k.as_integer().map(Into::into).unwrap_or(-1);
                let shape = match v {
                    Value::Array(items) => format!("[{}]", items.len()),
                    Value::Map(entries) if key == self.option_key() => entries
                        .iter()
                        .map(|(k, v)| {
                            format!(
                                "{}={}",
                                k.as_text().unwrap_or("?"),
                                v.as_bool().map_or("?".into(), |b| b.to_string())
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(","),
                    Value::Map(entries) => format!("{{{}}}", entries.len()),
                    Value::Bytes(b) => format!("b{}", b.len()),
                    Value::Text(_) => "text".into(),
                    _ => "?".into(),
                };
                format!("{key}:{shape}")
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn option_key(&self) -> i128 {
        if self.command == command::GET_ASSERTION {
            0x05
        } else {
            0x07
        }
    }

    pub fn is_selection_request(&self) -> bool {
        self.command == command::MAKE_CREDENTIAL
            && self
                .rp_id()
                .is_some_and(|id| SELECTION_RP_IDS.contains(&id))
    }
}

/// Builds a getAssertion success response for a silent probe, claiming the first
/// credential in the list. It is never shown to a relying party: browsers only use
/// it to decide which credential IDs to send in the real request.
pub fn silent_probe_response(rp_id: &str, credential: &Value) -> Vec<u8> {
    let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
    auth_data.push(0x00); // flags: no UP, no UV
    auth_data.extend_from_slice(&0u32.to_be_bytes()); // signCount
    ok_with(&Value::Map(vec![
        (int(0x01), credential.clone()),
        (int(0x02), Value::Bytes(auth_data)),
        (int(0x03), Value::Bytes(vec![0u8; 8])),
    ]))
}

pub fn credential_id(descriptor: &Value) -> Option<&[u8]> {
    match map_get(descriptor, "id")? {
        Value::Bytes(id) => Some(id),
        _ => None,
    }
}

fn map_get<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    match value {
        Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v),
        _ => None,
    }
}

fn cmp_int_keys(a: &Value, b: &Value) -> std::cmp::Ordering {
    let a: Option<i128> = a.as_integer().map(Into::into);
    let b: Option<i128> = b.as_integer().map(Into::into);
    a.cmp(&b)
}

fn int(v: i64) -> Value {
    Value::Integer(v.into())
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn descriptor(id: &[u8]) -> Value {
        Value::Map(vec![
            (text("id"), Value::Bytes(id.to_vec())),
            (text("type"), text("public-key")),
        ])
    }

    pub fn get_assertion(rp: &str, allow: Vec<Value>, up: Option<bool>) -> Vec<u8> {
        let mut entries = vec![(int(1), text(rp)), (int(2), Value::Bytes(vec![0xaa; 32]))];
        if !allow.is_empty() {
            entries.push((int(3), Value::Array(allow)));
        }
        if let Some(up) = up {
            entries.push((int(5), Value::Map(vec![(text("up"), Value::Bool(up))])));
        }
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
        out
    }

    pub fn make_credential(rp: &str, exclude: Vec<Value>) -> Vec<u8> {
        let mut entries = vec![
            (int(1), Value::Bytes(vec![0xbb; 32])),
            (int(2), Value::Map(vec![(text("id"), text(rp))])),
            (
                int(3),
                Value::Map(vec![(text("id"), Value::Bytes(vec![1]))]),
            ),
            (int(4), Value::Array(vec![])),
        ];
        if !exclude.is_empty() {
            entries.push((int(5), Value::Array(exclude)));
        }
        let mut out = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut out).unwrap();
        out
    }

    #[test]
    fn detects_probe_and_rp() {
        let req = Request::parse(
            command::GET_ASSERTION,
            &get_assertion("example.com", vec![descriptor(b"a")], Some(false)),
        )
        .unwrap();
        assert!(req.is_silent_probe());
        assert_eq!(req.rp_id(), Some("example.com"));
        assert_eq!(req.credential_list().len(), 1);

        let req = Request::parse(
            command::GET_ASSERTION,
            &get_assertion("example.com", vec![], None),
        )
        .unwrap();
        assert!(!req.is_silent_probe());
    }

    #[test]
    fn normalize_drops_default_user_presence() {
        let mut entries = Vec::new();
        ciborium::into_writer(
            &Value::Map(vec![
                (int(1), text("rp.test")),
                (int(2), Value::Bytes(vec![0; 32])),
                (
                    int(5),
                    Value::Map(vec![
                        (text("up"), Value::Bool(true)),
                        (text("uv"), Value::Bool(true)),
                    ]),
                ),
            ]),
            &mut entries,
        )
        .unwrap();
        let mut req = Request::parse(command::GET_ASSERTION, &entries).unwrap();
        req.normalize_for_phone();
        assert_eq!(req.summary(), "1:text 2:b32 5:uv=true");

        let mut req = Request::parse(
            command::GET_ASSERTION,
            &get_assertion("rp.test", vec![], Some(true)),
        )
        .unwrap();
        req.normalize_for_phone();
        assert_eq!(
            req.summary(),
            "1:text 2:b32",
            "an emptied options map is removed"
        );
    }

    #[test]
    fn detects_selection_requests() {
        for rp in SELECTION_RP_IDS {
            let req =
                Request::parse(command::MAKE_CREDENTIAL, &make_credential(rp, vec![])).unwrap();
            assert!(req.is_selection_request());
        }
        let req = Request::parse(
            command::MAKE_CREDENTIAL,
            &make_credential("example.com", vec![]),
        )
        .unwrap();
        assert!(!req.is_selection_request());
    }

    #[test]
    fn inserts_missing_list_in_key_order() {
        let mut req = Request::parse(
            command::MAKE_CREDENTIAL,
            &make_credential("example.com", vec![]),
        )
        .unwrap();
        req.set_credential_list(vec![descriptor(b"x")]);
        let reparsed = Request::parse(command::MAKE_CREDENTIAL, &req.encode()).unwrap();
        let keys: Vec<i128> = reparsed
            .entries
            .iter()
            .map(|(k, _)| k.as_integer().unwrap().into())
            .collect();
        assert_eq!(keys, vec![1, 2, 3, 4, 5]);
        assert_eq!(reparsed.credential_list().len(), 1);
    }

    #[test]
    fn get_info_is_valid_cbor() {
        let info = get_info(&GetInfoParams {
            aaguid: [7; 16],
            max_msg_size: 7609,
            max_credential_count_in_list: 64,
        });
        assert_eq!(info[0], status::OK);
        let value: Value = ciborium::from_reader(&info[1..]).unwrap();
        assert!(matches!(value, Value::Map(_)));
        assert_canonical(&value);
    }

    /// CTAP2 canonical CBOR (RFC 7049 section 3.9): map keys sorted by encoded
    /// length, then bytewise. libfido2 rejects anything else.
    fn assert_canonical(value: &Value) {
        match value {
            Value::Map(entries) => {
                let keys: Vec<Vec<u8>> = entries
                    .iter()
                    .map(|(k, _)| {
                        let mut out = Vec::new();
                        ciborium::into_writer(k, &mut out).unwrap();
                        out
                    })
                    .collect();
                let mut sorted = keys.clone();
                sorted.sort_by(|a, b| a.len().cmp(&b.len()).then(a.cmp(b)));
                assert_eq!(keys, sorted, "map keys not in canonical order");
                entries.iter().for_each(|(_, v)| assert_canonical(v));
            }
            Value::Array(items) => items.iter().for_each(assert_canonical),
            _ => {}
        }
    }

    #[test]
    fn silent_probe_response_is_canonical() {
        let reply = silent_probe_response("example.com", &descriptor(b"cred"));
        assert_eq!(reply[0], status::OK);
        assert_canonical(&ciborium::from_reader(&reply[1..]).unwrap());
    }
}
