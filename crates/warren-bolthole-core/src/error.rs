//! Error types of the gateway core.

/// Why a packet could not be read or rewritten.
///
/// Every variant is a refusal that leaves the buffer untouched: the parsers and
/// the rewriter validate the whole operation before they write a byte, so a
/// caller may retry or drop without inspecting how far the work had gone.
/// Displays carry no address, port or payload (no-log discipline).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PacketError {
    /// The buffer is shorter than the header it declares.
    #[error("packet truncated")]
    Truncated,
    /// The version nibble is neither 4 nor 6.
    #[error("not an IP packet")]
    BadVersion,
    /// An IPv4 fragment: ports live in the first fragment only, so a NAT that
    /// does not reassemble cannot translate one correctly.
    #[error("fragmented packet")]
    Fragment,
    /// An IPv6 extension header sits between the fixed header and the
    /// transport header. Ordinary stacks emit none for ordinary traffic.
    #[error("IPv6 extension header")]
    ExtensionHeader,
    /// The transport protocol is not one this gateway translates (TCP, UDP,
    /// ICMP echo and ICMP errors).
    #[error("unsupported transport protocol")]
    UnsupportedProtocol,
    /// An IPv4 address was offered for an IPv6 packet, or the reverse.
    #[error("address family mismatch")]
    FamilyMismatch,
    /// An identifier rewrite was asked of an ICMP message that carries none.
    #[error("not an ICMP echo message")]
    NotAnEcho,
    /// A quote was asked of an ICMP message that is not an error, so it quotes
    /// nothing.
    #[error("not an ICMP error message")]
    NotAnIcmpError,
}

/// Errors of the gateway core's own configuration and allocation surface.
///
/// Displays name the rule that refused, never the value that broke it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CoreError {
    /// The port is not inside the space it was asked of: outside the dynamic
    /// pool, or inside the range the gateway keeps for its own control plane.
    #[error("port outside the allocatable pool")]
    PortOutsidePool,
    /// A live flow already holds the port.
    #[error("port already in use")]
    PortInUse,
    /// The port is already pinned to a static forward.
    #[error("port already reserved")]
    PortAlreadyReserved,
    /// The endpoint a static forward points at belongs to no peer.
    #[error("forward target owned by no peer")]
    TargetNotOwned,
}
