//#![feature(extern_crate_item_prelude)]
#![allow(dead_code)]
#![allow(unused_imports)]

use ring::signature;
use ring::rand;
use ring::aead::*;
use ring::pbkdf2::*;
use ring::pbkdf2;
use ring::digest;
use ring::rand::SecureRandom;
use hex_literal::hex;

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const CREDENTIAL_LEN: usize = digest::SHA256_OUTPUT_LEN;

fn enc_dec() {
    println!("Starting enc_dec");
// The password will be used to generate a key
    let password = b"This is a very nice password";

// Usually the salt has some random data and something that relates to the user
// like an username
    let salt = [0, 1, 2, 3, 4, 5, 6, 7, 8];

// Keys are sent as &[T] and must have 32 bytes
    let mut key = [0u8; CREDENTIAL_LEN];
    let iter : std::num::NonZeroU32 = std::num::NonZeroU32::new(1000).unwrap();
    derive(PBKDF2_ALG, iter, &salt, &password[..], &mut key);

// Your private data
    let src ="This is a message to encrypt";
    println!("Input data : {:?}", src.to_string());
    let content = src.as_bytes().to_vec();
    //let content1 = b"my content is here to be encrypted and tested".to_vec();
    //let s: &str = content.iter().collect();
    let s = match String::from_utf8(content.clone()) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };

    println!("result: {}", s);
    println!("String to encrypt {}",s);
    println!("Content to encrypt's size {}", content.len());

// Additional data that you would like to send and it would not be encrypted but it would
// be signed
    let additional_data = hex!("21222324252627282930ffddaaee44");
    let mut ad_data = hex!("21222324252627282930ffddaaee44"); //[0;32];

// Ring uses the same input variable as output
    let mut in_out = content.clone();

// The input/output variable need some space for a suffix
    println!("Tag len {}", CHACHA20_POLY1305.tag_len());
    for _ in 0..CHACHA20_POLY1305.tag_len() {
        in_out.push(0);
    }
// TODO Corriger avec https://docs.rs/ring/0.16.20
// Opening key used to decrypt data
    let opening_key = OpeningKey::new(&CHACHA20_POLY1305, &key).unwrap();

// Sealing key used to encrypt data
    let sealing_key = SealingKey::new(&CHACHA20_POLY1305, &key).unwrap();

// Random data must be used only once per encryption
    let mut nonce = vec![0; 12];

// Fill nonce with random data
    let rnd = rand::SystemRandom::new();
    rnd.fill(&mut nonce).unwrap();
// Encrypt data into in_out variable
    let output_size = OpeningKey::seal_in_place_append_tag(&sealing_key, &nonce, &additional_data, &mut in_out,
                                    CHACHA20_POLY1305.tag_len()).unwrap();

    println!("Encrypted data's size {}", output_size);

    let decrypted_data = OpeningKey::open_in_place(&opening_key, &nonce, &ad_data,
                                       0, &mut in_out).unwrap();

    println!("Decrypted data : {:?}", String::from_utf8(decrypted_data.to_vec()).unwrap());
    println!("Decrypted data len : {}",decrypted_data.len());
    assert_eq!(content, decrypted_data);
}

fn main() {
    enc_dec();
}

