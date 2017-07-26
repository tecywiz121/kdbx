use ::*;
use std::io::Write;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io::Read;
use keys::{Key,CompositeKey};
use byteorder::{LittleEndian, ReadBytesExt, ByteOrder};
use elementtree::Element;
use openssl::hash::{Hasher, MessageDigest};
use openssl::sha;
use openssl::symm::{self,Cipher};
use flate2::read::GzDecoder;

pub struct Reader {
    key : CompositeKey,
}

const SIG1_N : usize = 4; // I assume I won't need this in future Rust versions.
const SIG1   : [u8; SIG1_N] = [0x03, 0xD9, 0xA2, 0x9A];

const SIG2_N : usize = 4;
const SIG2   : [u8; SIG2_N] = [0x67, 0xFB, 0x4B, 0xB5];

impl Reader {
    pub fn new(key : CompositeKey) -> Reader {
        Reader {
            key: key,
        }
    }

    fn parse_sig1(&self, r : &mut Read) -> Result<(), Error> {
        let mut buf = [0u8; SIG1_N];
        r.read_exact(&mut buf)?;

        if SIG1 == buf {
            Ok(())
        } else {
            Err(Error::new("sig1 not found"))
        }
    }

    fn parse_sig2(&self, r : &mut Read) -> Result<(), Error> {
        let mut buf = [0u8; SIG2_N];
        r.read_exact(&mut buf)?;

        if SIG2 == buf {
            Ok(())
        } else {
            Err(Error::new("sig2 not found or unsupported version"))
        }
    }

    fn parse_version(&self, r : &mut Read) -> Result<Version, Error> {
        let minor = r.read_u16::<LittleEndian>()?;
        let major = r.read_u16::<LittleEndian>()?;
        Ok(Version {
            minor: minor,
            major: major
        })
    }

    fn parse_header(&self, r : &mut Read) -> Result<(u8, Vec<u8>), Error> {
        let id = r.read_u8()?;
        let sz = r.read_u16::<LittleEndian>()?;

        let mut data = vec![0u8; sz as usize];
        r.read_exact(&mut data)?;

        Ok((id, data))
    }

    fn parse_headers(&self, r : &mut Read) -> Result<HashMap<u8, Vec<u8>>, Error> {
        let mut headers : HashMap<u8, Vec<u8>> = HashMap::new();
        loop {
            let (id, bytes) = self.parse_header(r)?;

            // TODO: Support duplicate headers.
            match headers.entry(id) {
                Entry::Vacant(x)    => { x.insert(bytes); }
                _                   => return Err(Error::new("duplicate header")),
            }

            if 0 == id {
                break;
            }
        }

        Ok(headers)
    }

    fn read_u32(v : &Vec<u8>) -> Result<u32, Error> {
        match v.len() {
            4 => Ok(LittleEndian::read_u32(v)),
            _ => Err(Error::new("malformed u32 header")),
        }
    }

    fn read_u64(v : &Vec<u8>) -> Result<u64, Error> {
        match v.len() {
            8 => Ok(LittleEndian::read_u64(v)),
            _ => Err(Error::new("malformed u64 header")),
        }
    }

    fn take_compression(hdrs : &mut HashMap<u8, Vec<u8>>)
                        -> Result<Compression, Error> {
        hdrs.remove_hdr(Header::CompressionFlags)
            .ok_or_else(|| Error::new("missing compression flags"))
            .and_then(|ref x| Reader::read_u32(x))
            .and_then(Compression::from)
    }

    fn take_outer_cipher(hdrs : &mut HashMap<u8, Vec<u8>>)
                         -> Result<OuterCipher, Error> {
        hdrs.remove_hdr(Header::CipherId)
            .ok_or_else(|| Error::new("missing outer cipher"))
            .and_then(|ref x| OuterCipher::from(x))
    }

    fn take_master_seed(hdrs : &mut HashMap<u8, Vec<u8>>)
                        -> Result<Vec<u8>, Error> {
        let seed = hdrs.remove_hdr(Header::MasterSeed)
                   .ok_or_else(|| Error::new("missing master seed"))?;

        if 32 != seed.len() {
            Err(Error::new("invalid master seed"))
        } else {
            Ok(seed)
        }
    }

    fn take_encryption_iv(hdrs : &mut HashMap<u8, Vec<u8>>)
                          -> Result<Vec<u8>, Error> {
        hdrs.remove_hdr(Header::EncryptionIv)
            .ok_or_else(|| Error::new("missing encryption iv"))
    }

    fn take_inner_stream_key(hdrs : &mut HashMap<u8, Vec<u8>>)
                             -> Option<Vec<u8>> {
        hdrs.remove_hdr(Header::ProtectedStreamKey)
    }

    fn take_inner_stream_cipher(hdrs : &mut HashMap<u8, Vec<u8>>)
                                -> Result<InnerStreamCipher, Error> {
        hdrs.remove_hdr(Header::InnerRandomStreamId)
            .ok_or_else(|| Error::new("missing inner random stream id"))
            .and_then(|ref x| Reader::read_u32(x))
            .and_then(|x| InnerStreamCipher::from(x))
    }

    fn take_stream_start_bytes(hdrs : &mut HashMap<u8, Vec<u8>>) -> Vec<u8> {
        hdrs.remove_hdr(Header::StreamStartBytes).unwrap_or(vec![])
    }

    fn take_transform_rounds(hdrs : &mut HashMap<u8, Vec<u8>>)
                             -> Result<u64, Error> {
        hdrs.remove_hdr(Header::TransformRounds)
            .ok_or_else(|| Error::new("missing transform rounds"))
            .and_then(|ref x| Reader::read_u64(x))
    }

    fn take_transform_seed(hdrs : &mut HashMap<u8, Vec<u8>>)
                           -> Result<Vec<u8>, Error> {
        hdrs.remove_hdr(Header::TransformSeed)
            .ok_or_else(|| Error::new("missing transform seed"))
    }

    fn read_payload(&self,
                    db : &Database,
                    r : &mut Read) -> Result<Element, Error> {
        println!("original_key: {:?}", self.key.bytes());
        println!("transform_seed: {:?}", db.transform_seed);
        let transformed_key = self.key.transform(db.transform_rounds,
                                                 &db.transform_seed)?;

        println!("transformed_key: {:?}", transformed_key);
        let mut hasher = Hasher::new(MessageDigest::sha256())?;
        hasher.write(&db.master_seed)?;
        hasher.write(&transformed_key)?;

        let master_key = hasher.finish2()?;
        println!("master_key: {:?}", master_key);

        let mut ciphertext : Vec<u8> = Vec::new();

        r.read_to_end(&mut ciphertext)?;

        let mut plaintext = symm::decrypt(Cipher::aes_256_cbc(),
                                          &master_key.to_vec(),
                                          Some(&db.encryption_iv),
                                          &ciphertext)?;

        let sbytes = &db.stream_start_bytes;

        if sbytes[..] == plaintext[0..sbytes.len()] {
            plaintext.drain(0..sbytes.len()).take(0).count();
        }

        let data1 : &[u8] = &plaintext;
        Ok(Reader::read_xml(data1, db)?)
    }

    fn read_xml<R : Read>(mut plaintext : R, db : &Database) -> Result<Element, Error> {
        let mut bytes : Vec<u8> = Vec::new();
        loop {
            plaintext.read_u32::<LittleEndian>()?;

            let mut hash = [0u8; 32];
            plaintext.read_exact(&mut hash)?;

            let size = plaintext.read_u32::<LittleEndian>()?;

            if 0 == size {
                break;
            }

            let mut data = vec![0u8; size as usize];
            plaintext.read_exact(&mut data)?;

            if sha::sha256(&data) != hash {
                return Err(Error::new("bad hash"));
            }

            bytes.extend_from_slice(&data[..]);
        }

        let data : &[u8] = &bytes;
        match db.compression {
            Compression::None => Ok(Element::from_reader(data)?),
            Compression::GZip => Ok(Element::from_reader(GzDecoder::new(data).unwrap())?),
        }
    }

    pub fn read_from(&self, r : &mut Read) -> Result<Database, Error> {
        self.parse_sig1(r)?;
        self.parse_sig2(r)?;
        let version = self.parse_version(r)?;
        let mut hdrs = self.parse_headers(r)?;

        let mut db = Database {
            version             : version,
            compression         : Reader::take_compression(&mut hdrs)?,
            outer_cipher        : Reader::take_outer_cipher(&mut hdrs)?,
            encryption_iv       : Reader::take_encryption_iv(&mut hdrs)?,
            inner_stream_key    : Reader::take_inner_stream_key(&mut hdrs),
            inner_stream_cipher : Reader::take_inner_stream_cipher(&mut hdrs)?,
            master_seed         : Reader::take_master_seed(&mut hdrs)?,
            stream_start_bytes  : Reader::take_stream_start_bytes(&mut hdrs),
            transform_rounds    : Reader::take_transform_rounds(&mut hdrs)?,
            transform_seed      : Reader::take_transform_seed(&mut hdrs)?,
            other_headers       : hdrs.drain().collect(),
            xml_doc             : Element::new("Banana")
        };

        db.xml_doc = self.read_payload(&db, r)?;

        Ok(db)
    }
}
