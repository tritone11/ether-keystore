//! # Keystore files (UTC / JSON) encrypted with a passphrase module
//!
//! [Web3 Secret Storage Definition](
//! https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition)
mod cipher;
mod error;
mod kdf;
mod prf;
#[macro_use]
mod serialize;

pub use self::cipher::Cipher;
pub use self::error::Error;
pub use self::kdf::{Kdf, KdfDepthLevel, KdfParams, PBKDF2_KDF_NAME};
pub use self::prf::Prf;
pub use self::serialize::Error as SerializeError;
pub use self::serialize::{
    try_extract_address, CoreCrypto, Iv, Mac, SerializableKeyFileCore
};
use super::core::{self, Address, PrivateKey};
use super::util::{self, keccak256, to_arr, KECCAK256_BYTES,timestamp};
use rand::{OsRng, Rng};
use std::convert::From;
use std::str::FromStr;
use std::{cmp, fmt};
use std::ffi::OsStr;
use uuid::Uuid;
use std::path::{Path, PathBuf};
use std::fs::{self, read_dir, File};
use std::io::{Read, Write};
use std::io;

/// Key derivation function salt length in bytes
pub const KDF_SALT_BYTES: usize = 32;

/// Cipher initialization vector length in bytes
pub const CIPHER_IV_BYTES: usize = 16;

byte_array_struct!(Salt, KDF_SALT_BYTES);


#[derive(Debug)]
pub enum KeystoreError {
    /// General storage error
    StorageError(String),

    /// `KeyFile` not found
    NotFound(String),
}

impl From<serde_json::Error> for KeystoreError {
    fn from(err: serde_json::Error) -> Self {
        KeystoreError::StorageError(err.to_string())
    }
}

impl From<io::Error> for KeystoreError {
    fn from(err: io::Error) -> Self {
        KeystoreError::StorageError(err.to_string())
    }
}


/// Filesystem storage for `KeyFiles`
///
pub struct Keystore {
    /// Parent directory for storage
    base_path: PathBuf,
}

/// A keystore file (account private core encrypted with a passphrase)
#[derive(Deserialize, Debug, Clone, Eq)]
pub struct KeyFile {
    /// Specifies if `Keyfile` is visible
    pub visible: Option<bool>,

    /// User specified name
    pub name: Option<String>,

    /// User specified description
    pub description: Option<String>,

    /// Address
    pub address: Address,

    /// UUID v4
    pub uuid: Uuid,

    ///
    pub crypto: CryptoType,
}

/// Variants of `crypto` section in `Keyfile`
///
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum CryptoType {
    /// normal Web3 Secret Storage
    Core(CoreCrypto)
}

impl Keystore {
    /// Create new `FsStorage`
    /// Uses specified path as parent folder
    ///
    /// # Arguments:
    ///
    /// * dir - parent folder
    ///
    pub fn new<P>(dir: P) -> Keystore
    where
        P: AsRef<Path> + AsRef<OsStr>,
    {
        Keystore {
            base_path: PathBuf::from(&dir),
        }
    }

    fn build_path(&self, name: &str) -> PathBuf {
        let mut path = self.base_path.clone();
        path.push(name);
        path
    }
}

impl KeyFile {
    /// Creates a new `KeyFile` with specified passphrase at random (`rand::OsRng`)
    ///
    /// # Arguments
    ///
    /// * `passphrase` - password for key derivation function
    ///
    pub fn new(
        passphrase: &str,
        sec_level: &KdfDepthLevel,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<KeyFile, Error> {
        let mut rng = os_random();

        let kdf = if cfg!(target_os = "windows") {
            Kdf::from_str(PBKDF2_KDF_NAME)?
        } else {
            Kdf::from(*sec_level)
        };

        Self::new_custom(
            PrivateKey::gen_custom(&mut rng),
            passphrase,
            kdf,
            &mut rng,
            name,
            description,
        )
    }

    /// Creates a new `KeyFile` with specified `PrivateKey`, passphrase, key derivation function
    /// and with given custom random generator
    ///
    /// # Arguments
    ///
    /// * `pk` - a private key
    /// * `passphrase` - password for key derivation function
    /// * `kdf` - customized key derivation function
    /// * `rnd` - predefined random number generator
    ///
    pub fn new_custom<R: Rng>(
        pk: PrivateKey,
        passphrase: &str,
        kdf: Kdf,
        rng: &mut R,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<KeyFile, Error> {
        let mut kf = KeyFile {
            uuid: rng.gen::<Uuid>(),
            name,
            description,
            ..Default::default()
        };

        if let CryptoType::Core(ref mut core) = kf.crypto {
            core.kdf_params.kdf = kdf;
        }

        kf.encrypt_key_custom(pk, passphrase, rng);
        kf.address = kf.decrypt_address(passphrase)?;

        Ok(kf)
    }

    /// Decrypt public address from keystore file by a password
    pub fn decrypt_address(&self, password: &str) -> Result<Address, Error> {
        let pk = self.decrypt_key(password)?;
        pk.to_address().map_err(Error::from)
    }

    /// Decrypt private key from keystore file by a password
    pub fn decrypt_key(&self, passphrase: &str) -> Result<PrivateKey, Error> {
        match self.crypto {
            CryptoType::Core(ref core) => {
                let derived = core.kdf_params.kdf.derive(
                    core.kdf_params.dklen,
                    &core.kdf_params.salt,
                    passphrase,
                );

                let mut v = derived[16..32].to_vec();
                v.extend_from_slice(&core.cipher_text);

                let mac: [u8; KECCAK256_BYTES] = core.mac.into();
                if keccak256(&v) != mac {
                    return Err(Error::FailedMacValidation);
                }

                Ok(PrivateKey(to_arr(&core.cipher.encrypt(
                    &core.cipher_text,
                    &derived[0..16],
                    &core.cipher_params.iv,
                ))))
            }
            _ => Err(Error::InvalidCrypto(
                "HD Wallet crypto used instead of normal".to_string(),
            )),
        }
    }

    /// Encrypt a new private key for keystore file with a passphrase
    pub fn encrypt_key(&mut self, pk: PrivateKey, passphrase: &str) {
        self.encrypt_key_custom(pk, passphrase, &mut os_random());
    }

    /// Encrypt a new private key for keystore file with a passphrase
    /// and with given custom random generator
    pub fn encrypt_key_custom<R: Rng>(&mut self, pk: PrivateKey, passphrase: &str, rng: &mut R) {
        match self.crypto {
            CryptoType::Core(ref mut core) => {
                let mut buf_salt: [u8; KDF_SALT_BYTES] = [0; KDF_SALT_BYTES];
                rng.fill_bytes(&mut buf_salt);
                core.kdf_params.salt = Salt::from(buf_salt);

                let derived = core.kdf_params.kdf.derive(
                    core.kdf_params.dklen,
                    &core.kdf_params.salt,
                    passphrase,
                );

                let mut buf_iv: [u8; CIPHER_IV_BYTES] = [0; CIPHER_IV_BYTES];
                rng.fill_bytes(&mut buf_iv);
                core.cipher_params.iv = Iv::from(buf_iv);

                core.cipher_text =
                    core.cipher
                        .encrypt(&pk, &derived[0..16], &core.cipher_params.iv);

                let mut v = derived[16..32].to_vec();
                v.extend_from_slice(&core.cipher_text);
                core.mac = Mac::from(keccak256(&v));
            }
            _ => debug!("HD Wallet crypto used instead of normal"),
        }
    }
}

impl Default for KeyFile {
    fn default() -> Self {
        KeyFile {
            visible: Some(true),
            name: None,
            description: None,
            address: Address::default(),
            uuid: Uuid::default(),
            crypto: CryptoType::Core(CoreCrypto::default()),
        }
    }
}

impl From<Uuid> for KeyFile {
    fn from(uuid: Uuid) -> Self {
        KeyFile {
            uuid,
            ..Default::default()
        }
    }
}

impl PartialEq for KeyFile {
    fn eq(&self, other: &Self) -> bool {
        self.uuid == other.uuid
    }
}

impl PartialOrd for KeyFile {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KeyFile {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.uuid.cmp(&other.uuid)
    }
}

impl fmt::Display for KeyFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Keystore file: {}", self.uuid)
    }
}

/// Create random number generator
pub fn os_random() -> OsRng {
    OsRng::new().expect("Expect OS specific random number generator")
} 

pub fn generate_filename(uuid: &str) -> String {
    format!("UTC--{}Z--{}", &timestamp(), &uuid)
}  

pub fn save_keyfile(kf: KeyFile)  -> Result<(),KeystoreError>{
    let name = generate_filename(&kf.uuid.to_string());
    let json = serde_json::to_string(&kf)?;
    let ks = Keystore::new(&name);
    let path = ks.build_path(&name);
    println!("{:?}",path);
    let mut file = File::create(&path)?;
    file.write_all(json.as_ref()).ok();
    Ok(())
}
