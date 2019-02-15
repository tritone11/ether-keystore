//! # Keystore files key derivation function

use super::prf::Prf;
use super::Error;
use super::Salt;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use scrypt::{scrypt, ScryptParams};
use sha2::{Sha256, Sha512};
use std::fmt;
use std::str::FromStr;

/// `PBKDF2` key derivation function name
pub const PBKDF2_KDF_NAME: &str = "pbkdf2";

/// `Scrypt` key derivation function name
pub const SCRYPT_KDF_NAME: &str = "scrypt";

/// Derived core length in bytes (by default)
pub const DEFAULT_DK_LENGTH: usize = 32;

/// Key derivation function parameters
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Key derivation function
    #[serde(flatten)]
    pub kdf: Kdf,

    /// `Kdf` length for parameters
    pub dklen: usize,

    /// Cryptographic salt for `Kdf`
    pub salt: Salt,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            kdf: Kdf::default(),
            dklen: DEFAULT_DK_LENGTH,
            salt: Salt::default(),
        }
    }
}

/// Security level for `Kdf`
#[derive(Clone, Copy, Debug)]
pub enum KdfDepthLevel {
    /// Security level used by default
    Normal = 1024,

    /// Advanced security level
    High = 8096,

    /// Top security level (consumes more CPU time)
    Ultra = 262_144,
}

impl fmt::Display for KdfDepthLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let printable = match *self {
            KdfDepthLevel::Normal => "normal",
            KdfDepthLevel::High => "high",
            KdfDepthLevel::Ultra => "ultra",
        };
        write!(f, "{}", printable)
    }
}

impl FromStr for KdfDepthLevel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "normal" => Ok(KdfDepthLevel::Normal),
            "high" => Ok(KdfDepthLevel::High),
            "ultra" => Ok(KdfDepthLevel::Ultra),
            v => Err(Error::InvalidKdfDepth(v.to_string())),
        }
    }
}

impl Default for KdfDepthLevel {
    fn default() -> Self {
        KdfDepthLevel::Normal
    }
}

/// Key derivation function
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum Kdf {
    /// PBKDF2 (not recommended, specified in (RFC 2898)[https://tools.ietf.org/html/rfc2898])
    #[serde(rename = "pbkdf2")]
    Pbkdf2 {
        /// Pseudo-Random Functions (`HMAC-SHA-256` by default)
        prf: Prf,

        /// Number of iterations (`262144` by default)
        c: u32,
    },

    /// Scrypt (by default, specified in (RPC 7914)[https://tools.ietf.org/html/rfc7914])
    #[serde(rename = "scrypt")]
    Scrypt {
        /// Number of iterations (`19201` by default)
        n: u32,

        /// Block size for the underlying hash (`8` by default)
        r: u32,

        /// Parallelization factor (`1` by default)
        p: u32,
    },
}

impl Kdf {
    /// Derive fixed size key for given salt and passphrase
    pub fn derive(&self, len: usize, kdf_salt: &[u8], passphrase: &str) -> Vec<u8> {
        let mut key = vec![0u8; len];

        match *self {
            Kdf::Pbkdf2 { prf, c } => {
                match prf {
                    Prf::HmacSha256 => {
                        let mut hmac = prf.hmac(passphrase);
                        pbkdf2::<Hmac<Sha256>>(
                            passphrase.as_bytes(),
                            kdf_salt,
                            c as usize,
                            &mut key,
                        );
                    }
                    Prf::HmacSha512 => {
                        pbkdf2::<Hmac<Sha512>>(
                            passphrase.as_bytes(),
                            kdf_salt,
                            c as usize,
                            &mut key,
                        );
                    }
                };
            }
            Kdf::Scrypt { n, r, p } => {
                let log_n = (n as f64).log2().round() as u8;
                let params = ScryptParams::new(log_n, r, p).expect("Invalid Scrypt parameters");
                scrypt(passphrase.as_bytes(), kdf_salt, &params, &mut key).expect("Scrypt failed");
            }
        }

        key
    }
}

impl Default for Kdf {
    fn default() -> Self {
        Kdf::Scrypt {
            n: 1024,
            r: 8,
            p: 1,
        }
    }
}

impl From<KdfDepthLevel> for Kdf {
    fn from(sec: KdfDepthLevel) -> Self {
        Kdf::from((sec as u32, 8, 1))
    }
}

impl From<u32> for Kdf {
    fn from(c: u32) -> Self {
        Kdf::Pbkdf2 {
            prf: Prf::default(),
            c,
        }
    }
}

impl From<(u32, u32, u32)> for Kdf {
    fn from(t: (u32, u32, u32)) -> Self {
        Kdf::Scrypt {
            n: t.0,
            r: t.1,
            p: t.2,
        }
    }
}

impl FromStr for Kdf {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            _ if s == PBKDF2_KDF_NAME => Ok(Kdf::Pbkdf2 {
                prf: Prf::default(),
                c: 262_144,
            }),
            _ if s == SCRYPT_KDF_NAME => Ok(Kdf::default()),
            _ => Err(Error::UnsupportedKdf(s.to_string())),
        }
    }
}

impl fmt::Display for Kdf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Kdf::Pbkdf2 { .. } => f.write_str(PBKDF2_KDF_NAME),
            Kdf::Scrypt { .. } => f.write_str(SCRYPT_KDF_NAME),
        }
    }
}
