extern crate unicode_normalization;
extern crate elementtree;
extern crate byteorder;
extern crate openssl;
extern crate flate2;
extern crate base64;
extern crate hex;

pub mod keys;
mod error;
mod reader;

use std::collections::HashMap;

use elementtree::Element;

pub use error::Error;
pub use reader::Reader;

#[derive(Debug,PartialEq,Eq)]
#[repr(u8)]
pub enum Header {
    End=0u8,
    Comment=1u8,
    CipherId=2u8,
    CompressionFlags=3u8,
    MasterSeed=4u8,
    TransformSeed=5u8,
    TransformRounds=6u8,
    EncryptionIv=7u8,
    ProtectedStreamKey=8u8,
    StreamStartBytes=9u8,
    InnerRandomStreamId=10u8,
}

#[derive(Debug,PartialEq,Eq)]
pub enum Compression {
    None,
    GZip,
}

impl Compression {
    pub fn from(v : u32) -> Result<Compression, Error> {
        match v {
            0 => Ok(Compression::None),
            1 => Ok(Compression::GZip),
            _ => return Err(Error::new("unsupported compression")),
        }
    }
}

#[derive(Debug,PartialEq,Eq)]
pub enum InnerStreamCipher {
    None,
    Salsa20,
}

impl InnerStreamCipher {
    pub fn from(v : u32) -> Result<InnerStreamCipher, Error> {
        match v {
            0 => Ok(InnerStreamCipher::None),
            2 => Ok(InnerStreamCipher::Salsa20),
            _ => return Err(Error::new("unsupported inner cipher")),
        }
    }
}

#[derive(Debug,PartialEq,Eq)]
pub enum OuterCipher {
    Aes128,
}

const CIPHERID_AES128 : [u8; 16] = [0x31, 0xc1, 0xf2, 0xe6,
                                    0xbf, 0x71, 0x43, 0x50,
                                    0xbe, 0x58, 0x05, 0x21,
                                    0x6a, 0xfc, 0x5a, 0xff];

impl OuterCipher {
    pub fn from(v : &[u8]) -> Result<OuterCipher, Error> {
        if v == CIPHERID_AES128 {
            Ok(OuterCipher::Aes128)
        } else {
            Err(Error::new("unknown cipher"))
        }
    }
}

pub trait HashMapExt {
    // TODO: Look into std::borrow::Borrow. Might be able to do soemthing with
    //       that because this feels dirty.
    fn get_hdr(&self, k : Header) -> Option<&Vec<u8>>;
    fn remove_hdr(&mut self, k : Header) -> Option<Vec<u8>>;
}

impl HashMapExt for HashMap<u8, Vec<u8>> {
    fn get_hdr(&self, k : Header) -> Option<&Vec<u8>> {
        self.get(&(k as u8))
    }

    fn remove_hdr(&mut self, k : Header) -> Option<Vec<u8>> {
        self.remove(&(k as u8))
    }
}

#[derive(Debug,PartialEq,Eq)]
pub struct Version {
    pub major : u16,
    pub minor : u16,
}

#[derive(Debug)]
pub struct Database {
    pub version             : Version,
    pub compression         : Compression,
    pub outer_cipher        : OuterCipher,
    pub master_seed         : Vec<u8>,
    pub transform_seed      : Vec<u8>,
    pub transform_rounds    : u64,
    pub encryption_iv       : Vec<u8>,
    pub inner_stream_key    : Option<Vec<u8>>,
    pub inner_stream_cipher : InnerStreamCipher,
    pub stream_start_bytes  : Vec<u8>,
    pub other_headers       : Vec<(u8, Vec<u8>)>,
    xml_doc                 : Element,
}

impl Database {
}
