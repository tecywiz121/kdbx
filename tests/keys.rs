extern crate kdbx;
extern crate hex;
use kdbx::keys::*;
use hex::FromHex;

////
//// FileKey
////

const XML_KEY_IN : &'static [u8] = include_bytes!("sample-key.xml");
const XML_KEY : &'static [u8] = &[168, 23,  169, 208, 204, 105, 201, 160,
                                  222, 124, 109, 7,   20,  212, 65,  47,
                                  226, 216, 9,   94,  120, 127, 103, 48,
                                  163, 148, 139, 112, 201, 241, 5,   233];

#[test]
fn file_key_from_xml() {
    assert_eq!(FileKey::from_xml(XML_KEY_IN),
               Some(FileKey::new(FileKeyFormat::Xml, XML_KEY.to_vec())));
}

#[test]
fn file_key_from_detect_xml() {
    assert_eq!(FileKey::from(XML_KEY_IN).ok(),
               Some(FileKey::new(FileKeyFormat::Xml, XML_KEY.to_vec())));
}

const BIN32_KEY : &'static [u8] = &[1,  2,  3,  4,  5,  6,  7,  8,
                                    9,  10, 11, 12, 13, 14, 15, 16,
                                    17, 18, 19, 20, 21, 22, 23, 24,
                                    25, 26, 27, 28, 29, 30, 31, 32];

#[test]
fn file_key_from_bin32() {
    assert_eq!(FileKey::from_bin32(BIN32_KEY),
               Some(FileKey::new(FileKeyFormat::Bin32, BIN32_KEY.to_vec())));
}

#[test]
fn file_key_from_detect_bin32() {
    assert_eq!(FileKey::from(BIN32_KEY).ok(),
               Some(FileKey::new(FileKeyFormat::Bin32, BIN32_KEY.to_vec())));
}

const HEX64_KEY_IN : &'static [u8] =
    b"2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40";

const HEX64_KEY : &'static [u8] = &[0x21, 0x22, 0x23, 0x24,
                                    0x25, 0x26, 0x27, 0x28,
                                    0x29, 0x2a, 0x2b, 0x2c,
                                    0x2d, 0x2e, 0x2f, 0x30,
                                    0x31, 0x32, 0x33, 0x34,
                                    0x35, 0x36, 0x37, 0x38,
                                    0x39, 0x3a, 0x3b, 0x3c,
                                    0x3d, 0x3e, 0x3f, 0x40];

#[test]
fn file_key_from_hex64() {
    assert_eq!(FileKey::from_hex64(HEX64_KEY_IN),
               Some(FileKey::new(FileKeyFormat::Hex64, HEX64_KEY.to_vec())));
}

#[test]
fn file_key_from_detect_hex64() {
    assert_eq!(FileKey::from(HEX64_KEY_IN).ok(),
               Some(FileKey::new(FileKeyFormat::Hex64, HEX64_KEY.to_vec())));
}

#[test]
fn file_key_bytes() {
    let fkey = FileKey::new(FileKeyFormat::Bin32, BIN32_KEY.to_vec());
    assert_eq!(fkey.bytes(), BIN32_KEY);
}

#[test]
fn file_key_save_xml() {
    let to_save = FileKey::new(FileKeyFormat::Xml, XML_KEY.to_vec());
    assert_eq!(FileKey::from(&to_save.save()).ok(), Some(to_save));
}

#[test]
fn file_key_save_bin32() {
    let to_save = FileKey::new(FileKeyFormat::Bin32, XML_KEY.to_vec());
    let saved = to_save.save();
    assert_eq!(saved.len(), 32);
    assert_eq!(FileKey::from(&saved).ok(), Some(to_save));
}

#[test]
fn file_key_save_hex64() {
    let to_save = FileKey::new(FileKeyFormat::Hex64, XML_KEY.to_vec());
    let saved = to_save.save();
    assert_eq!(saved.len(), 64);
    assert_eq!(FileKey::from(&saved).ok(), Some(to_save));
}

////
//// CompositeKey
////

#[test]
fn composite_key_empty() {
    let expected : Vec<u8> =
        Vec::from_hex(concat!("e3b0c44298fc1c149afbf4c8996fb924",
                              "27ae41e4649b934ca495991b7852b855")).unwrap();

    let ck = CompositeKey::new();
    assert_eq!(ck.unwrap().bytes().to_vec(), expected);
}

const HELLO_WORLD_SHA256 : &'static [u8] =
    b"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

const HELLO_WORLD_SHA256_SHA256 : &'static str =
    "bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423";

#[test]
fn composite_key_push_one() {
    let expected : Vec<u8> = Vec::from_hex(HELLO_WORLD_SHA256_SHA256).unwrap();
    let fk = FileKey::from_hex64(HELLO_WORLD_SHA256).unwrap();
    let mut ck = CompositeKey::new().unwrap();
    ck.push(&fk);
    assert_eq!(ck.bytes().to_vec(), expected);
}

const HELLO_WORLD_SHA256_TWICE_SHA256 : &'static str =
    "47a8c6f8b634e4d94a9da33e182c270fe3571f1a550d20fd93735583180c3c32";

#[test]
fn composite_key_push_two() {
    let expected : Vec<u8> =
        Vec::from_hex(HELLO_WORLD_SHA256_TWICE_SHA256).unwrap();

    let fk = FileKey::from_hex64(HELLO_WORLD_SHA256).unwrap();
    let mut ck = CompositeKey::new().unwrap();
    ck.push(&fk);
    ck.push(&fk);
    assert_eq!(ck.bytes().to_vec(), expected);
}
