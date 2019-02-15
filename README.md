# ether-keystore
Rust crate for creation and unlocking of ethereum keystores  
This comes from emerald_rs of ETCDEV, it's just a simpler version of it with all the feature of HDWallet and db stripped, as they have heavy dependencies  
  
# Example
  
```
extern crate ethereum_keystore;

use ethereum_keystore::PrivateKey;
use ethereum_keystore::keystore::{os_random, Kdf, KeyFile, Keystore, KeyfileStorage};
use std::io::Read; 
use std::fs::File;
use std::path::{Path, PathBuf};
use std::mem;


const KEY_PATH: &str = "/home/tritone11/keystore";

fn main() {
    // Keystore creation
    let private_key = PrivateKey::gen();
    let kdf = Kdf::from((8, 2, 1));
    let mut rng = os_random();
    let s = "hello";
    let db = Keystore::new(&KEY_PATH);
    let accs = db.list_accounts(false).unwrap();
    let keyfile = KeyFile::new_custom(private_key, &s, kdf, &mut rng, None, None).unwrap();
    println!("Keyfile: {:?}",keyfile);
    let filename = save_keyfile(keyfile,keystore_path);

    // Keystore unlock
    let path = KEY_PATH.to_string()+&keyfile_path(&accs[0].filename.to_string()).to_str().unwrap().to_string();
    let mut file = File::open(path).unwrap();
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Unable to read the file");
    let keyfile = KeyFile::decode(&contents).unwrap();
    let s = "hello";
    let k = keyfile.decrypt_key(s).expect("Wrong passphrase");
    let h = KeyFile::decode(&contents).unwrap().address;

    let hex_address = h.to_string();
    let pk = string_to_static_str(k.to_string());
    println!("PRIVATE KEY: {:?}",pk);
    println!("ADDRESS: {:?}",hex_address);
    
}

pub fn keyfile_path(name: &str) -> PathBuf {
    let mut path = keystore_path();
    path.push(name);
    path
}

pub fn keystore_path() -> PathBuf {
    let mut buf = PathBuf::from("");
    buf.push("/");
    buf
}

fn string_to_static_str(s: String) -> &'static str {
    unsafe {
        let ret = mem::transmute(&s as &str);
        mem::forget(s);
        ret
    }
}
```
