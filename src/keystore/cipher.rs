//! # Advanced encryption standard (AES) cipher

use super::Error;
use aes_ctr::stream_cipher::generic_array::GenericArray;
use aes_ctr::stream_cipher::{NewFixStreamCipher, StreamCipherCore};
use aes_ctr::Aes128Ctr;
use std::fmt;
use std::str::FromStr;

/// `AES128_CRT` cipher name
pub const AES128_CTR_CIPHER_NAME: &str = "aes-128-ctr";

/// Cipher type
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    /// AES-CTR (specified in (RFC 3686)[https://tools.ietf.org/html/rfc3686])
    #[serde(rename = "aes-128-ctr")]
    Aes128Ctr,
}

impl Cipher {
    /// Encrypt given text with provided key and initial vector
    pub fn encrypt(&self, data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
        let key = GenericArray::from_slice(key);
        let iv = GenericArray::from_slice(iv);
        let mut buf = data.to_vec();
        let mut ctr = Aes128Ctr::new(key, iv);
        ctr.apply_keystream(&mut buf);
        buf
    }
}

impl Default for Cipher {
    fn default() -> Self {
        Cipher::Aes128Ctr
    }
}

impl FromStr for Cipher {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            _ if s == AES128_CTR_CIPHER_NAME => Ok(Cipher::Aes128Ctr),
            _ => Err(Error::UnsupportedCipher(s.to_string())),
        }
    }
}

impl fmt::Display for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Cipher::Aes128Ctr => f.write_str(AES128_CTR_CIPHER_NAME),
        }
    }
} 