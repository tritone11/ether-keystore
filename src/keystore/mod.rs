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
use std::fs::{self, read_dir, File,create_dir_all};
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

#[derive(Debug, Clone, Default)]
pub struct AccountInfo {
    /// File name for `KeyFile`
    pub filename: String,

    /// Address of account
    pub address: String,

    /// Optional name for account
    pub name: String,

    /// Optional description for account
    pub description: String,

    /// shows whether it is normal account or
    /// held by HD wallet
    pub is_hardware: bool,

    /// show if account hidden from 'normal' listing
    /// `normal` - not forcing to show hidden accounts
    pub is_hidden: bool,
}

impl From<KeyFile> for AccountInfo {
    fn from(kf: KeyFile) -> Self {
        let mut info = Self::default();
        info.address = kf.address.to_string();

        if let Some(name) = kf.name {
            info.name = name;
        };

        if let Some(desc) = kf.description {
            info.description = desc;
        };

        if let Some(visible) = kf.visible {
            info.is_hidden = !visible;
        };


        info
    }
}

/// Filesystem storage for `KeyFiles`
///
pub struct Keystore {
    /// Parent directory for storage
    base_path: PathBuf,
}

pub trait KeyfileStorage: Send + Sync {

    /// Lists info for `Keystore` files inside storage
    /// Can include hidden files if flag set.
    ///
    /// # Arguments
    ///
    /// * `showHidden` - flag to show hidden `Keystore` files
    ///
    /// # Return:
    ///
    /// Array of `AccountInfo` struct
    ///
    fn list_accounts(&self, show_hidden: bool) -> Result<Vec<AccountInfo>, KeystoreError>;

    
    
}

impl KeyfileStorage for Keystore {
    fn list_accounts(&self, show_hidden: bool) -> Result<Vec<AccountInfo>, KeystoreError> {
        let mut accounts = vec![];
        for e in read_dir(&self.base_path)? {
            if e.is_err() {
                continue;
            }
            let entry = e.unwrap();
            let mut content = String::new();
            if let Ok(mut keyfile) = File::open(entry.path()) {
                if keyfile.read_to_string(&mut content).is_err() {
                    continue;
                }

                match KeyFile::decode(&content) {
                    Ok(kf) => {
                        if kf.visible.is_none() || kf.visible.unwrap() || show_hidden {
                            let mut info = AccountInfo::from(kf);
                            match entry.path().file_name().and_then(|s| s.to_str()) {
                                Some(name) => {
                                    info.filename = name.to_string();
                                    accounts.push(info);
                                }
                                None => info!("Corrupted filename for: {:?}", entry.file_name()),
                            }
                        }
                    }
                    Err(_) => info!("Invalid keystore file format for: {:?}", entry.file_name()),
                }
            }
        }

        Ok(accounts)
    }
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

pub fn save_keyfile(kf: KeyFile,p_path: &str)  -> Result<(),KeystoreError>{
    let name = generate_filename(&kf.uuid.to_string());
    let json = serde_json::to_string(&kf)?;
    let ks = Keystore::new(&p_path);
    let path = ks.build_path(&name);
    println!("{:?}",path);
    if Path::new(p_path).exists() {
        let mut file = File::create(&path)?;
        file.write_all(json.as_ref()).ok();
    } else {
        let _r = fs::create_dir_all(p_path);
        let mut file = File::create(&path)?;
        file.write_all(json.as_ref()).ok();
    }
    
    Ok(())
}
