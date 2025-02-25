//! Enums and defaults for Argon2 configuration options (e.g. `hash_len`,
//! [`Variant`](config/enum.Variant.html), [`Version`](config/enum.Version.html), etc.)
mod backend;
pub(crate) mod defaults;
mod flags;
mod hasher_config;
mod variant;
mod verifier_config;
mod version;

pub(crate) use self::flags::Flags;
pub use self::{
    backend::Backend, defaults::*, hasher_config::HasherConfig, variant::Variant,
    verifier_config::VerifierConfig, version::Version,
};
