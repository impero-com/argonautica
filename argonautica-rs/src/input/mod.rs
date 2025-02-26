//! Type-safe structs representing data to hash (i.e.
//! [`Password`](input/struct.Password.html),
//! [`Salt`](input/struct.Salt.html),
//! [`SecretKey`](input/struct.SecretKey.html), and
//! [`AdditionalData`](input/struct.AdditionalData.html))
//!
//! All the stucts below can be constructed from
//! [`Vec<u8>`](https://doc.rust-lang.org/std/vec/struct.Vec.html),
//! [`&[u8]`](https://doc.rust-lang.org/std/primitive.slice.html),
//! [`String`](https://doc.rust-lang.org/std/string/struct.String.html),
//! [`&str`](https://doc.rust-lang.org/std/primitive.str.html), as well as
//! other types, as they all implement several versions of the
//! [`From`](https://doc.rust-lang.org/std/convert/trait.From.html) trait. Some have additional
//! constructors as well, e.g. [`Salt::random(...)`](struct.Salt.html#method.random), which
//! produces a [`Salt`](struct.Salt.html) that will create new crytographically-secure,
//! random bytes after each hash.
mod additional_data;
mod container;
mod password;
mod salt;
mod secret_key;

pub(crate) use self::container::Container;
pub use self::{
    additional_data::AdditionalData, password::Password, salt::Salt, secret_key::SecretKey,
};
