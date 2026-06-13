//! FFI surface for the Warren SDK (Phase P9, not yet implemented).
//!
//! The boundary is designed now so the Rust public API stays FFI-friendly:
//! no generics in exported signatures, `#[non_exhaustive]` serializable error
//! enums, owned plain types across the boundary, and lifecycle events delivered
//! as a stream rather than borrowed references.
//!
//! Planned tooling: `uniffi` to generate the Dart/Flutter, Kotlin, Swift,
//! Python and Java bindings from a single Rust definition, keeping every
//! language SDK in lockstep with the same wire contracts and golden vectors.

#[cfg(test)]
mod roadmap {
    #[test]
    #[ignore = "P9: expose uniffi scaffolding and generate the first Dart binding"]
    fn placeholder() {}
}
