//#![feature(extern_crate_item_prelude)]
#![allow(dead_code)]
#![allow(unused_imports)]

extern crate jsonwebtoken as jwt;
#[macro_use]
extern crate serde_derive;
extern crate ring;
extern crate untrusted;
extern crate reqwest;

use jwt::errors::ErrorKind;
use jwt::{decode, encode, Header, Validation};
use ring::signature;
use ring::rand;
//use ring::rand::SystemRandom;
use ring::aead::*;
use ring::pbkdf2::*;
use ring::digest;

use reqwest::get;
use reqwest::{Client, RequestBuilder, Method, Result, Response};
use reqwest::header;
use reqwest::header::{HeaderMap, HeaderValue};

use std::fs::File;
use std::io::Read;
use ring::rand::SecureRandom;


#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
    other: String
}


// check https://jwt.io
fn run1() {
    println!("Starting run1");
    let my_claims =
        Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned(), exp: 10000000000, other: "MyData".to_owned() };
    let key = "my_secret";
    let token = match encode(&Header::default(), &my_claims, key.as_ref()) {
        Ok(t) => t,
        Err(_) => panic!(), // in practice you would return the error
    };
    println!("{:?}", token);
    let validation = Validation { sub: Some("b@b.com".to_string()), ..Validation::default() };
    let token_data = match decode::<Claims>(&token, key.as_ref(), &validation) {
        Ok(c) => c,
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => panic!("Token is invalid"), // Example on how to handle a specific error
            ErrorKind::InvalidIssuer => panic!("Issuer is invalid"), // Example on how to handle a specific error
            _ => panic!("Some other errors"),
        },
    };
    println!("{:?}", token_data.claims);
    println!("{:?}", token_data.header);
    println!("Signature test");
    // Generate a key pair in PKCS#8 (v2) format.
    let rng = rand::SystemRandom::new();
    //let rng1 =
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("Error in key pair generation step 1");

// Normally the application would store the PKCS#8 file persistently. Later
// it would read the PKCS#8 file from persistent storage to use it.

    let key_pair = signature::Ed25519KeyPair::from_pkcs8(untrusted::Input::from(&pkcs8_bytes)).expect("Error in key pair generation step 2");

    // Sign the message "hello, world".
    const MESSAGE: &[u8] = b"hello, world";
    let sig = key_pair.sign(MESSAGE);

// Normally an application would extract the bytes of the signature and
// send them in a protocol message to the peer(s). Here we just get the
// public key key directly from the key pair.
    let peer_public_key_bytes = key_pair.public_key_bytes();
    let sig_bytes = sig.as_ref();

// Verify the signature of the message using the public key. Normally the
// verifier of the message would parse the inputs to `signature::verify`
// out of the protocol message(s) sent by the signer.
    let peer_public_key = untrusted::Input::from(peer_public_key_bytes);
    let msg = untrusted::Input::from(MESSAGE);
    let sig = untrusted::Input::from(sig_bytes);

    signature::verify(&signature::ED25519, peer_public_key, msg, sig).expect("Error while verify signature");
    println!("Signature verify OK.")
}


fn display_status(r: Result<reqwest::Response>) -> String {
    let ans = match r {
        Err(_e) => "Error found",
        Ok(_x) => "OK"
    };
    return ans.to_string();
}

fn run3(url: String) {
    println!("Starting run3 with {}", url);
    let client = Client::new();
    let req_builder1 = client.request(Method::GET, &url)
        .basic_auth("bruno", Some("xyzt"))
        .query(&[("lang", "rust")]);
//    let res = reqBuilder.build().expect("Error while building request");

    let r = req_builder1.send();
    println!("Execute returned : {}", display_status(r));
}

//#[cfg(feature = "default-tls")]
fn run4(url: String) -> String {
    println!("Starting run4 with <{}>", url);

    // Step 1 : create client_builder
    let c_builder = Client::builder();
    let mut buf = Vec::new();

    let f = File::open("c:/dvlpt/rust/hello-rust/bruno_orange.p12");
    if let Err(e_f) = f { return e_f.to_string(); }
    if let Err(e_b) = f.unwrap().read_to_end(&mut buf) { return e_b.to_string(); }

    // Step 2 : create identity
    let pkcs12 = reqwest::Identity::from_pkcs12_der(&buf, "br31415926;");
    if let Err(e_p) = pkcs12 { return e_p.to_string(); }
    let good_pkcs12 = pkcs12.unwrap();

    // Step 3 : create client by adding identity to client_builder
    let clt = c_builder.identity(good_pkcs12).build();
    if let Err(e_clt) = clt { return e_clt.to_string(); }
    let good_clt = clt.unwrap();

    // Step 4 : attach request to client => req builder then config and build
    let req_res = good_clt.request(Method::GET, &url)
        .basic_auth("bruno", Some("xyzt"))
        .query(&[("lang", "rust")])
        .header(header::COOKIE, "xyzt; path=/; HttpOnly")
        .header(header::ACCEPT_CHARSET, "UTF-8")
        .build();

    if let Err(e2) = req_res { return e2.to_string(); }

    // Step 5 : launch client execution and get result
    let final_result = good_clt.execute(req_res.unwrap());
    if let Err(e_fr) = final_result { return e_fr.to_string(); }
    println!("========== Connect....");

    // Step 6 : get info from execution result
    let mut response = final_result.expect("First request Execution Error");
    println!("=================> Execution returned : {}", response.status());
    let mut buf = String::new();

    // Step 7 : get and print body
    let read_status = response.read_to_string(&mut buf);
    if let Err(r_r) = read_status { return r_r.to_string(); }
    //.expect("Failed to read response");
    //println!("Response : {}",buf);

    let mut cookies: Vec<String> = vec!();

    // Step 8 : export cookies from headers into new header map
    let mut hdrs = HeaderMap::new();
    for (k, v) in response.headers().iter() {
        //println!("{:?}: {:?}", k, v);
        if k == header::SET_COOKIE {
            cookies.push(v.to_str().unwrap().to_string());
            println!("Add cookie {:?} with value {:?}", k, v);
            hdrs.insert(header::COOKIE, HeaderValue::from(v));
            //req_bldr.header(header::COOKIE,v);
        }
    }
    println!("Cookies : length = {} => {:?}", cookies.len(), cookies);

    // New request ( restart at step 4 without building)
    let req_bldr = good_clt.request(Method::GET, &url)
        .basic_auth("bruno", Some("xyzt"))
        .query(&[("lang", "rust")]);

    // Step add new header map to req builder and build
    let req_b2 = req_bldr.headers(hdrs);
    let req_res2 = req_b2.build();
    if let Err(e_r2) = req_res2 { return e_r2.to_string(); }

    println!("========== Connect....");

    let final_result2 = good_clt.execute(req_res2.unwrap());
    if let Err(e_fr2) = final_result2 { return e_fr2.to_string(); }
    let response2 = final_result2.expect("Second request Execution Error");
    println!("=================> Execution returned : {}", response2.status());
    "OK".to_string()
}

// TODO AJouter les fonctions pour envois POST
fn send_post_form_encoded() {
    /*
    pub fn form<T: Serialize + ?Sized>(self, form: &T) -> RequestBuilder

    Send a form body.

    Sets the body to the url encoded serialization of the passed value, and also sets the Content-Type: application/x-www-form-urlencoded header.

    let mut params = HashMap::new();
    params.insert("lang", "rust");

    let client = reqwest::Client::new();
    let res = client.post("http://httpbin.org")
        .form(&params)
        .send()?;
    */
}

fn send_post_multipart() {
    /*
    pub fn multipart(self, multipart: Form) -> RequestBuilder

    Sends a multipart/form-data body.

    let client = reqwest::Client::new();
    let form = reqwest::multipart::Form::new()
        .text("key3", "value3")
        .file("file", "/path/to/field")?;

    let response = client.post("your url")
        .multipart(form)
        .send()?;
    */
}

fn run5() {
    println!("Starting run5");
// The password will be used to generate a key
    let password = b"This is a very nice password";

// Usually the salt has some random data and something that relates to the user
// like an username
    let salt = [0, 1, 2, 3, 4, 5, 6, 7];

// Keys are sent as &[T] and must have 32 bytes
    let mut key = [0; 32];
    derive(&digest::SHA256, 100, &salt, &password[..], &mut key);

// Your private data
    let content = b"my content is here to be encrypted and tested".to_vec();
    //println!("Input data : {:?}", content.to_);

    println!("Content to encrypt's size {}", content.len());

// Additional data that you would like to send and it would not be encrypted but it would
// be signed
    let additional_data: [u8; 0] = [];

// Ring uses the same input variable as output
    let mut in_out = content.clone();

// The input/output variable need some space for a suffix
    println!("Tag len {}", CHACHA20_POLY1305.tag_len());
    for _ in 0..CHACHA20_POLY1305.tag_len() {
        in_out.push(0);
    }

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
    let output_size = seal_in_place(&sealing_key, &nonce, &additional_data, &mut in_out,
                                    CHACHA20_POLY1305.tag_len()).unwrap();

    println!("Encrypted data's size {}", output_size);

    let decrypted_data = open_in_place(&opening_key, &nonce, &additional_data,
                                       0, &mut in_out).unwrap();

    println!("Decrypted data : {:?}", String::from_utf8(decrypted_data.to_vec()).unwrap());
    assert_eq!(content, decrypted_data);
}

fn main() {
    let good_url = "https://www.cecurity.com".to_string();

    let _s = run4(good_url.clone());
    println!("run4 return {}", _s);
    run1();
    run5();
}
