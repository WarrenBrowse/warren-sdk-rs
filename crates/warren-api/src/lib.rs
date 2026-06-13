//! Signed Warren account API client (Phase P3, not yet implemented).
//!
//! Planned surface, ported from warren-core `warren-api-client`:
//! - `WarrenApiClient` over an async HTTP backend, attaching the four
//!   `X-Warren-*` headers from [`warren_identity::WarrenIdentity::sign_request`].
//! - Endpoints: `/v1/register`, `/v1/subscription`, `/v1/check`, `/v1/exits`,
//!   `/v1/session/{open,close}`, `/v1/account` (DELETE), checkout/voucher polling,
//!   mobile payments (Apple/Google), incident and support reports.
//! - Anti-censorship fallback: primary host, alternative hosts, no-SNI attempt.
//! - Pinned API server pubkey passed through to [`warren_discovery`] for the
//!   signed relay list verification.
//!
//! The HTTP backend will be abstracted behind a trait so the FFI builds and the
//! sibling-language SDKs can plug their platform HTTP stack.

#[cfg(test)]
mod roadmap {
    #[test]
    #[ignore = "P3: implement WarrenApiClient signed endpoints + host fallback"]
    fn placeholder() {}
}
