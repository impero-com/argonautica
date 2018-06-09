from enum import Enum
import multiprocessing

from argonautica.ffi import rust


class Backend(Enum):
    """
    ``Backend`` is an ``Enum`` representing the two argonautica "backends":

    * ``Backend.C``: When using this backend, the core algorithm will be performed by C code
    * ``Backend.Rust``: When using this backend, the core algorithm will be performed by Rust code

    *Note: Backend.Rust is not yet implemented (but hopefully will be soon); so, for the
    moment, if you choose this backend your program will throw an exception when calling hash
    or when calling verify*
    """
    C = rust.ARGONAUTICA_C
    Rust = rust.ARGONAUTICA_RUST


class Variant(Enum):
    """
    ``Variant`` is an ``Enum`` representing the three argon2 variants:

    * ``Variant.Argon2d``
    * ``Variant.Argon2i``
    * ``Variant.Argon2id``

    Here is how these variants are explained in the RFC: "Argon2 has one primary variant:
    Argon2id, and two supplementary variants: Argon2d and Argon2i. Argon2d uses data-dependent
    memory access, which makes it suitable for ... applications with no threats from
    side-channel timing attacks. Argon2i uses data-independent memory access, which
    is preferred for password hashing and password-based key derivation. Argon2id
    works as Argon2i for the first half of the first iteration over the memory, and
    as Argon2d for the rest, thus providing both side-channel attack protection and
    brute-force cost savings due to time-memory tradeoffs."

    If you do not know which variant to use, use the default, which is ``Variant.Argon2id``.
    """
    Argon2d = rust.ARGONAUTICA_ARGON2D
    Argon2i = rust.ARGONAUTICA_ARGON2I
    Argon2id = rust.ARGONAUTICA_ARGON2ID


class Version(Enum):
    """
    ``Version`` is an ``Enum`` representing the two argon2 versions:

    * ``Version._0x10``
    * ``Version._0x13``

    The latest version is ``Version._0x13`` (as of 5/18). Unless you have a very specific
    reason not to, use ``Version._0x13``, which is also the default.
    """
    _0x10 = rust.ARGONAUTICA_0x10
    _0x13 = rust.ARGONAUTICA_0x13


DEFAULT_BACKEND = Backend.C
DEFAULT_HASH_LENGTH = 32
DEFAULT_ITERATIONS = 192
DEFAULT_LANES = multiprocessing.cpu_count()
DEFAULT_MEMORY_SIZE = 4096
DEFAULT_THREADS = multiprocessing.cpu_count()
DEFAULT_VARIANT = Variant.Argon2id
DEFAULT_VERSION = Version._0x13