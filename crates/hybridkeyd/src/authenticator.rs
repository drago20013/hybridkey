//! The CTAP2 authenticator presented to the browser. It answers housekeeping
//! commands itself and hands real ceremonies to a [`Backend`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ciborium::Value;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::backend::{Backend, ForwardRequest, Operation};
use crate::ctap2::{self, command, status, Request};
use crate::ctaphid::{keepalive, MAX_MESSAGE_LEN};

/// How long credential lists seen in silent probes are remembered.
const PROBE_TTL: Duration = Duration::from_secs(120);

/// Per-request state shared between the HID transport and the handler.
#[derive(Clone)]
pub struct RequestContext {
    pub cancel: CancellationToken,
    keepalive: Arc<AtomicU8>,
}

impl RequestContext {
    pub fn new() -> Self {
        Self {
            cancel: CancellationToken::new(),
            keepalive: Arc::new(AtomicU8::new(keepalive::PROCESSING)),
        }
    }

    /// Tells the browser (via CTAPHID keepalives) that we are waiting for the user.
    pub fn user_presence_needed(&self) {
        self.keepalive
            .store(keepalive::UP_NEEDED, Ordering::Relaxed);
    }

    pub fn keepalive_status(&self) -> u8 {
        self.keepalive.load(Ordering::Relaxed)
    }
}

/// What to do with silent (`up: false`) getAssertion probes, which a phone
/// reached over hybrid cannot answer.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProbePolicy {
    /// Claim a match, then send the phone the full original credential list in the
    /// real request. Works with Firefox's pre-flight filtering.
    #[default]
    Optimistic,
    /// Report "no credentials". Only discoverable-credential sign-ins will work.
    Deny,
}

/// Returns the executable names of the programs sending the current request.
pub type ClientLookup = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

pub struct Authenticator {
    backend: Arc<dyn Backend>,
    defer_to: Vec<String>,
    client_lookup: ClientLookup,
    probe_policy: ProbePolicy,
    forward_allow_list: bool,
    aaguid: [u8; 16],
    probes: Mutex<ProbeCache>,
}

impl Authenticator {
    pub fn new(backend: Arc<dyn Backend>, probe_policy: ProbePolicy, aaguid: [u8; 16]) -> Self {
        Self {
            backend,
            defer_to: Vec::new(),
            client_lookup: Arc::new(crate::client::requesting_programs),
            probe_policy,
            forward_allow_list: true,
            aaguid,
            probes: Mutex::new(ProbeCache::default()),
        }
    }

    /// When false, sign-ins are sent to the phone without the RP's credential
    /// list, so the phone offers every passkey it has for the site.
    pub fn with_allow_list_forwarding(mut self, forward: bool) -> Self {
        self.forward_allow_list = forward;
        self
    }

    /// Programs (executable names) that do hybrid themselves. Their requests are
    /// left alone, so the user only sees the program's own QR code.
    pub fn deferring_to(mut self, programs: Vec<String>, lookup: Option<ClientLookup>) -> Self {
        self.defer_to = programs;
        if let Some(lookup) = lookup {
            self.client_lookup = lookup;
        }
        self
    }

    async fn should_defer(&self) -> Option<String> {
        if self.defer_to.is_empty() {
            return None;
        }
        let lookup = self.client_lookup.clone();
        let clients = tokio::task::spawn_blocking(move || lookup())
            .await
            .unwrap_or_default();
        debug!(?clients, "request from");
        // Only defer when every holder is such a program; if, say, Firefox has
        // the key open too, the request may be Firefox's.
        let all_defer = !clients.is_empty() && clients.iter().all(|c| self.defer_to.contains(c));
        all_defer.then(|| clients.join(","))
    }

    /// Handles one CTAPHID_CBOR message (command byte followed by CBOR) and
    /// returns the response (status byte followed by CBOR).
    pub async fn handle(&self, message: &[u8], ctx: &RequestContext) -> Vec<u8> {
        let Some((&cmd, cbor)) = message.split_first() else {
            return ctap2::status_only(status::INVALID_COMMAND);
        };
        debug!(
            cmd = format!("{cmd:#04x}"),
            len = cbor.len(),
            "CTAP2 request"
        );
        match cmd {
            command::GET_INFO => ctap2::get_info(&ctap2::GetInfoParams {
                aaguid: self.aaguid,
                max_msg_size: MAX_MESSAGE_LEN,
                max_credential_count_in_list: 64,
            }),
            command::MAKE_CREDENTIAL | command::GET_ASSERTION => {
                self.ceremony(cmd, cbor, ctx).await
            }
            command::SELECTION => self.never_selected(ctx).await,
            // The hybrid session ends after one response, so there is nothing to continue.
            command::GET_NEXT_ASSERTION => ctap2::status_only(status::NOT_ALLOWED),
            command::RESET => ctap2::status_only(status::OPERATION_DENIED),
            // No clientPin, credential management, bio enrollment, config or large blobs.
            _ => ctap2::status_only(status::INVALID_COMMAND),
        }
    }

    async fn ceremony(&self, cmd: u8, cbor: &[u8], ctx: &RequestContext) -> Vec<u8> {
        let mut request = match Request::parse(cmd, cbor) {
            Ok(request) => request,
            Err(code) => return ctap2::status_only(code),
        };
        let Some(rp_id) = request.rp_id().map(str::to_owned) else {
            return ctap2::status_only(status::MISSING_PARAMETER);
        };

        if request.is_selection_request() {
            return self.never_selected(ctx).await;
        }
        if request.is_silent_probe() {
            return self.silent_probe(&rp_id, &request);
        }

        if let Some(full) = self
            .probes
            .lock()
            .unwrap()
            .take(&rp_id, request.credential_list())
        {
            debug!(
                rp_id,
                count = full.len(),
                "restoring credential list from pre-flight probe"
            );
            request.set_credential_list(full);
        }

        if let Some(client) = self.should_defer().await {
            info!(
                rp_id,
                client, "client does hybrid itself, staying out of the way"
            );
            return self.never_selected(ctx).await;
        }

        if !self.forward_allow_list {
            request.clear_allow_list();
        }
        request.normalize_for_phone();
        debug!(request = request.summary(), "request shape");

        let operation = if cmd == command::MAKE_CREDENTIAL {
            Operation::MakeCredential
        } else {
            Operation::GetAssertion
        };
        info!(
            rp_id,
            ?operation,
            backend = self.backend.name(),
            "forwarding ceremony"
        );
        ctx.user_presence_needed();

        let forward = ForwardRequest {
            command: cmd,
            cbor: request.encode(),
            operation,
            rp_id,
        };
        match self.backend.forward(forward, ctx).await {
            Ok(mut response) => {
                info!(
                    status = format!("{:#04x}", response.first().copied().unwrap_or(0xff)),
                    "ceremony finished"
                );
                // A phone declining is final. Firefox would retry OPERATION_DENIED
                // forever, taking it for a failed fingerprint on a key with built-in UV.
                if response == [status::OPERATION_DENIED] {
                    response = ctap2::status_only(status::NOT_ALLOWED);
                }
                response
            }
            Err(error) => {
                warn!(%error, "ceremony failed");
                ctap2::status_only(error.ctap_status())
            }
        }
    }

    fn silent_probe(&self, rp_id: &str, request: &Request) -> Vec<u8> {
        let list = request.credential_list();
        match (self.probe_policy, list.first()) {
            (ProbePolicy::Optimistic, Some(first)) => {
                debug!(
                    rp_id,
                    count = list.len(),
                    "answering pre-flight probe optimistically"
                );
                self.probes.lock().unwrap().record(rp_id, list);
                ctap2::silent_probe_response(rp_id, first)
            }
            _ => ctap2::status_only(status::NO_CREDENTIALS),
        }
    }

    /// Browsers ask every connected key to "blink" when several are plugged in and
    /// use the first one touched. We cannot be touched, so we wait to be cancelled
    /// and let the user pick a physical key, or none.
    async fn never_selected(&self, ctx: &RequestContext) -> Vec<u8> {
        ctx.user_presence_needed();
        ctx.cancel.cancelled().await;
        ctap2::status_only(status::KEEPALIVE_CANCEL)
    }
}

/// Remembers credential lists from silent probes so the real request can carry the
/// full list even after the browser narrowed it down to our optimistic answer.
#[derive(Default)]
struct ProbeCache {
    entries: HashMap<String, (Instant, Vec<Value>)>,
}

impl ProbeCache {
    fn record(&mut self, rp_id: &str, list: &[Value]) {
        self.entries
            .retain(|_, (seen, _)| seen.elapsed() < PROBE_TTL);
        let (seen, known) = self
            .entries
            .entry(rp_id.to_owned())
            .or_insert_with(|| (Instant::now(), Vec::new()));
        *seen = Instant::now();
        for descriptor in list {
            let id = ctap2::credential_id(descriptor);
            if !known.iter().any(|k| ctap2::credential_id(k) == id) {
                known.push(descriptor.clone());
            }
        }
    }

    /// Returns the remembered list if `narrowed` only contains credentials from it.
    fn take(&mut self, rp_id: &str, narrowed: &[Value]) -> Option<Vec<Value>> {
        let (seen, known) = self.entries.get(rp_id)?;
        if seen.elapsed() >= PROBE_TTL || narrowed.is_empty() {
            return None;
        }
        let subset = narrowed.iter().all(|d| {
            let id = ctap2::credential_id(d);
            known.iter().any(|k| ctap2::credential_id(k) == id)
        });
        if !subset {
            return None;
        }
        self.entries.remove(rp_id).map(|(_, list)| list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::BackendError;
    use crate::ctap2::tests::{descriptor, get_assertion, make_credential};
    use async_trait::async_trait;

    /// Records what reaches the phone.
    #[derive(Default)]
    struct RecordingBackend {
        seen: Mutex<Vec<ForwardRequest>>,
    }

    #[async_trait]
    impl Backend for RecordingBackend {
        fn name(&self) -> &'static str {
            "recording"
        }
        async fn forward(
            &self,
            request: ForwardRequest,
            _ctx: &RequestContext,
        ) -> Result<Vec<u8>, BackendError> {
            self.seen.lock().unwrap().push(request);
            Ok(vec![status::OK])
        }
    }

    fn message(cmd: u8, cbor: Vec<u8>) -> Vec<u8> {
        let mut out = vec![cmd];
        out.extend(cbor);
        out
    }

    fn forwarded_list(backend: &RecordingBackend) -> Vec<Value> {
        let seen = backend.seen.lock().unwrap();
        let last = seen.last().expect("a forwarded request");
        Request::parse(last.command, &last.cbor)
            .unwrap()
            .credential_list()
            .to_vec()
    }

    #[tokio::test]
    async fn firefox_preflight_keeps_full_allow_list() {
        let backend = Arc::new(RecordingBackend::default());
        let auth = Authenticator::new(backend.clone(), ProbePolicy::Optimistic, [0; 16]);
        let ctx = RequestContext::new();
        let all = vec![
            descriptor(b"key-a"),
            descriptor(b"key-b"),
            descriptor(b"key-c"),
        ];

        // Firefox probes the whole list silently...
        let probe = message(
            command::GET_ASSERTION,
            get_assertion("rp.test", all.clone(), Some(false)),
        );
        let reply = auth.handle(&probe, &ctx).await;
        assert_eq!(reply[0], status::OK);
        assert!(
            backend.seen.lock().unwrap().is_empty(),
            "probes must not reach the phone"
        );

        // ...then sends only the credential we claimed. The phone gets all three.
        let real = message(
            command::GET_ASSERTION,
            get_assertion("rp.test", vec![all[0].clone()], None),
        );
        auth.handle(&real, &ctx).await;
        assert_eq!(forwarded_list(&backend), all);
    }

    #[tokio::test]
    async fn preflight_restores_exclude_list() {
        let backend = Arc::new(RecordingBackend::default());
        let auth = Authenticator::new(backend.clone(), ProbePolicy::Optimistic, [0; 16]);
        let ctx = RequestContext::new();
        let all = vec![descriptor(b"old-1"), descriptor(b"old-2")];

        let probe = message(
            command::GET_ASSERTION,
            get_assertion("rp.test", all.clone(), Some(false)),
        );
        auth.handle(&probe, &ctx).await;
        let real = message(
            command::MAKE_CREDENTIAL,
            make_credential("rp.test", vec![all[0].clone()]),
        );
        auth.handle(&real, &ctx).await;
        assert_eq!(forwarded_list(&backend), all);
    }

    #[tokio::test]
    async fn unrelated_list_is_left_alone() {
        let backend = Arc::new(RecordingBackend::default());
        let auth = Authenticator::new(backend.clone(), ProbePolicy::Optimistic, [0; 16]);
        let ctx = RequestContext::new();

        let probe = message(
            command::GET_ASSERTION,
            get_assertion("rp.test", vec![descriptor(b"a")], Some(false)),
        );
        auth.handle(&probe, &ctx).await;
        let other = vec![descriptor(b"zzz")];
        let real = message(
            command::GET_ASSERTION,
            get_assertion("rp.test", other.clone(), None),
        );
        auth.handle(&real, &ctx).await;
        assert_eq!(forwarded_list(&backend), other);
    }

    #[tokio::test]
    async fn allow_list_can_be_withheld_from_the_phone() {
        let backend = Arc::new(RecordingBackend::default());
        let auth = Authenticator::new(backend.clone(), ProbePolicy::Optimistic, [0; 16])
            .with_allow_list_forwarding(false);
        let real = message(
            command::GET_ASSERTION,
            get_assertion("rp.test", vec![descriptor(b"a")], None),
        );
        auth.handle(&real, &RequestContext::new()).await;
        assert!(forwarded_list(&backend).is_empty());
    }

    #[tokio::test]
    async fn defers_to_browsers_with_their_own_hybrid() {
        let backend = Arc::new(RecordingBackend::default());
        let lookup: ClientLookup = Arc::new(|| vec!["chromium".to_owned()]);
        let auth = Authenticator::new(backend.clone(), ProbePolicy::Optimistic, [0; 16])
            .deferring_to(vec!["chromium".into()], Some(lookup));
        let ctx = RequestContext::new();
        let cancel = ctx.cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel.cancel();
        });
        let real = message(
            command::GET_ASSERTION,
            get_assertion("rp.test", vec![], None),
        );
        assert_eq!(
            auth.handle(&real, &ctx).await,
            vec![status::KEEPALIVE_CANCEL]
        );
        assert!(backend.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn serves_when_another_client_also_holds_the_key() {
        let backend = Arc::new(RecordingBackend::default());
        let lookup: ClientLookup = Arc::new(|| vec!["chromium".to_owned(), "firefox".to_owned()]);
        let auth = Authenticator::new(backend.clone(), ProbePolicy::Optimistic, [0; 16])
            .deferring_to(vec!["chromium".into()], Some(lookup));
        let real = message(
            command::GET_ASSERTION,
            get_assertion("rp.test", vec![], None),
        );
        auth.handle(&real, &RequestContext::new()).await;
        assert_eq!(backend.seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn deny_policy_reports_no_credentials() {
        let backend = Arc::new(RecordingBackend::default());
        let auth = Authenticator::new(backend, ProbePolicy::Deny, [0; 16]);
        let probe = message(
            command::GET_ASSERTION,
            get_assertion("rp.test", vec![descriptor(b"a")], Some(false)),
        );
        let reply = auth.handle(&probe, &RequestContext::new()).await;
        assert_eq!(reply, vec![status::NO_CREDENTIALS]);
    }

    #[tokio::test]
    async fn selection_waits_for_cancel() {
        let backend = Arc::new(RecordingBackend::default());
        let auth = Authenticator::new(backend.clone(), ProbePolicy::Optimistic, [0; 16]);
        let ctx = RequestContext::new();
        let blink = message(
            command::MAKE_CREDENTIAL,
            make_credential("make.me.blink", vec![]),
        );

        let cancel = ctx.cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel.cancel();
        });
        let reply = auth.handle(&blink, &ctx).await;
        assert_eq!(reply, vec![status::KEEPALIVE_CANCEL]);
        assert!(backend.seen.lock().unwrap().is_empty());
    }
}
