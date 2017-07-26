extern crate kdbx;

use std::io::Cursor;

use kdbx::*;
use kdbx::keys::{PasswordKey,CompositeKey};

const DB_AES256_PLAIN : &'static [u8] =
    include_bytes!("samples/AES256.Uncompressed.kdbx");

const DB_AES256_GZIP : &'static [u8] =
    include_bytes!("samples/AES256.GZIP.kdbx");

const PASSWORD : &'static str = "hello world";

const MASTER_SEED : [u8; 32] = [40,  215, 236, 234, 103, 116, 90,  171,
                                53,  193, 163, 166, 170, 62,  127, 31,
                                61,  139, 138, 198, 176, 193, 181, 72,
                                187, 142, 50,  154, 20,  77,  154, 100];

const TRANSFORM_SEED : [u8; 32] = [240, 19,  209, 51,  227, 250, 143, 108,
                                   62,  72,  79,  163, 34,  133, 29,  212,
                                   122, 77,  173, 130, 48,  241, 181, 60,
                                   223, 205, 217, 130, 139, 32,  47,  184];

const ENCRYPTION_IV : [u8; 16] = [205, 123, 176, 66,  25,  82,  46,  239,
                                  98,  228, 106, 209, 250, 154, 49,  121];

const INNER_KEY : [u8; 32] = [22,  158, 170, 27,  10,  99,  54,  152,
                              148, 221, 163, 120, 240, 149, 104, 195,
                              54,  152, 74,  34,  201, 134, 212, 21,
                              160, 221, 43,  171, 23,  240, 197, 71];

const START_BYTES : [u8; 32] = [126, 195, 159, 196, 230, 112, 32,  16,
                                251, 13,  232, 236, 249, 49,  10,  157,
                                161, 231, 191, 74,  196, 104, 124, 31,
                                18,  251, 145, 25,  99,  63,  198, 210];
#[test]
fn read_kdbx_plain() {
    let pw = PasswordKey::from(PASSWORD);
    let mut cm = CompositeKey::new().unwrap();
    cm.push(&pw);

    let r = Reader::new(cm);
    let db = r.read_from(&mut Cursor::new(DB_AES256_PLAIN)).unwrap();

    assert_eq!(db.version, Version { major: 3, minor: 1});
    assert_eq!(db.compression, Compression::None);
    assert_eq!(db.outer_cipher, OuterCipher::Aes128);
    assert_eq!(db.master_seed, MASTER_SEED);
    assert_eq!(db.transform_seed, TRANSFORM_SEED);
    assert_eq!(db.transform_rounds, 10u64);
    assert_eq!(db.encryption_iv, ENCRYPTION_IV);
    assert_eq!(db.inner_stream_key.unwrap(), INNER_KEY);
    assert_eq!(db.inner_stream_cipher, InnerStreamCipher::Salsa20);
    assert_eq!(db.stream_start_bytes, START_BYTES);
    assert_eq!(db.other_headers, vec![(0u8, vec![0x0D, 0x0A, 0x0D, 0x0A])]);
}

#[test]
fn read_kdbx_gzip() {
    let pw = PasswordKey::from(PASSWORD);
    let mut cm = CompositeKey::new().unwrap();
    cm.push(&pw);

    let r = Reader::new(cm);
    let db = r.read_from(&mut Cursor::new(DB_AES256_GZIP)).unwrap();

    assert_eq!(db.version, Version { major: 3, minor: 1});
    assert_eq!(db.compression, Compression::GZip);
}
