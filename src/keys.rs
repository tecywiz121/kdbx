use ::Error;

use std::io::Write;

use unicode_normalization::UnicodeNormalization;
use elementtree::Element;
use hex::{FromHex,ToHex};
use openssl::hash::{Hasher, MessageDigest};
use openssl::sha;
use openssl::symm::{self,Cipher,Crypter};

use base64;

pub trait Key<'a> {
    fn bytes(&'a self) -> &'a [u8];

    fn transform(&'a self, rounds : u64, key : &Vec<u8>) -> Result<Vec<u8>, Error> {
        let mut bytes = self.bytes().to_vec();
        let key_sz = bytes.len();

        let out_sz = bytes.len() + Cipher::aes_256_ecb().block_size();

        let mut crypter = Crypter::new(Cipher::aes_256_ecb(),
                                       symm::Mode::Encrypt,
                                       key,
                                       Some(&[0u8; 16]))?;
        for _ in 0 .. rounds {
            let mut output = vec![0u8; out_sz];
            crypter.update(&bytes, &mut output)?;
            bytes.copy_from_slice(&output[0..key_sz]);
        }
        Ok(sha::sha256(&bytes).to_vec())
    }
}

pub struct CompositeKey {
    hasher : Hasher,
    bytes : Vec<u8>,
}

impl<'a> Key<'a> for CompositeKey {
    fn bytes(&'a self) -> &'a [u8] {
        // TODO: Look into using RefCell to do better caching
        &self.bytes
    }
}

impl CompositeKey {
    fn digest(&mut self) -> Result<(), Error> {
        let mut hcpy = self.hasher.clone();
        self.bytes.copy_from_slice(&*hcpy.finish2()?);
        Ok(())
    }

    pub fn new() -> Result<CompositeKey, Error> {
        let mut ck = CompositeKey {
            hasher: Hasher::new(MessageDigest::sha256())?,
            bytes: vec![0u8; 32],
        };
        ck.digest()?;
        Ok(ck)
    }

    pub fn push<'b>(&mut self, subkey : &'b Key<'b>) {
        self.hasher.write(subkey.bytes()).expect("writing to digest failed.");
        self.digest().expect("updating digest failed.");
    }
}

#[derive(Debug,PartialEq,Eq)]
pub struct PasswordKey {
    bytes : Vec<u8>,
}

impl<'a> Key<'a> for PasswordKey {
    fn bytes(&'a self) -> &'a [u8] { &self.bytes }
}

impl PasswordKey {
    pub fn from(s : &str) -> PasswordKey {
        let normalized = s.chars().nfc().collect::<String>();
        PasswordKey {
            bytes: sha::sha256(normalized.as_bytes()).to_vec()
        }
    }
}

#[derive(Debug,PartialEq,Eq)]
pub enum FileKeyFormat {
    Xml,
    Bin32,
    Hex64,
}

#[derive(Debug,PartialEq,Eq)]
pub struct FileKey {
    format : FileKeyFormat,
    bytes : Vec<u8>,
}

impl<'a> Key<'a> for FileKey {
    fn bytes(&'a self) -> &'a [u8] { &self.bytes }
}

impl FileKey {
    pub fn new(fmt: FileKeyFormat, bytes : Vec<u8>) -> FileKey {
        FileKey {
            format: fmt,
            bytes: bytes
        }
    }

    pub fn from_xml(f : &[u8]) -> Option<FileKey> {
        let root = match Element::from_reader(f) {
            Err(_)  => return None,
            Ok(x)   => x
        };

        let version = root.find("Meta")
                          .and_then(|x| x.find("Version"))
                          .map(|x| x.text().trim());


        if Some("1.00") != version {
            return None;
        }

        root.find("Key")
            .and_then(|x| x.find("Data"))
            .map(|x| x.text().trim())
            .and_then(|x| base64::decode(x).ok())
            .map(|x| FileKey::new(FileKeyFormat::Xml, x))
    }

    pub fn from_bin32(f : &[u8]) -> Option<FileKey> {
        if 32 == f.len() {
            Some(FileKey::new(FileKeyFormat::Bin32, f.to_vec()))
        } else {
            None
        }
    }

    pub fn from_hex64(f : &[u8]) -> Option<FileKey> {
        if 64 != f.len() {
            return None;
        }

        Vec::from_hex(f).ok().map(|x| FileKey::new(FileKeyFormat::Hex64, x))
    }

    pub fn from(bytes : &[u8]) -> Result<FileKey, Error> {
        FileKey::from_xml(bytes)
            .or_else(|| FileKey::from_bin32(bytes))
            .or_else(|| FileKey::from_hex64(bytes))
            .ok_or_else(|| Error::new("unable to parse key file"))
    }

    fn save_xml(&self) -> Vec<u8> {
        format!(r#"<?xml version="1.0" encoding="utf-8"?>
<KeyFile>
    <Meta>
        <Version>1.00</Version>
    </Meta>
    <Key>
        <Data>{}</Data>
    </Key>
</KeyFile>
"#, base64::encode(&self.bytes)).into_bytes()
    }

    fn save_bin32(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    fn save_hex64(&self) -> Vec<u8> {
        self.bytes.to_hex().into_bytes()
    }

    pub fn save(&self) -> Vec<u8> {
        match self.format {
            FileKeyFormat::Xml      => self.save_xml(),
            FileKeyFormat::Bin32    => self.save_bin32(),
            FileKeyFormat::Hex64    => self.save_hex64(),
        }
    }
}
