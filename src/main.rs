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

use reqwest::get;
use reqwest::{Client, RequestBuilder, Method, Result, Response};

use std::fs::File;
use std::io::Read;


#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    company: String,
    exp: usize,
}


// check https://jwt.io
fn run1() {
    println!("Starting run1");
    let my_claims =
        Claims { sub: "b@b.com".to_owned(), company: "ACME".to_owned(), exp: 10000000000 };
    let key = "secret";
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

fn run2() {
    println!("Starting run2");
    //let mut buf = Vec::new();
    //let fopen = File::open("my-ident.pem");
    //fopen.read_to_end(&mut buf).unwrap();
    //let id = reqwest::Identity::from_pem(&buf).unwrap();
    let mut response = reqwest::get("https://www.cecurity.com").expect("Failed to get response from URL");
    println!("Status is {}", response.status());

    for (k, v) in response.headers().iter() {
        println!("{:?}: {:?}", k, v);

        //println!("Read {:?}",header);
    }

    let mut buf = String::new();
    response.read_to_string(&mut buf).expect("Failed to read response");
    //println!("{}", buf);
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
    let client = Client::new();
    let mut buf = Vec::new();

    let f = File::open("c:/dvlpt/rust/hello-rust/bruno_orange.p12");
    if let Err(_) = f {
        //println!("Unable to open p12");
        return "Cannot open p12".to_string();
    }
    let b = f.unwrap().read_to_end(&mut buf);
    if let Err(e1) = b {
        //println!("Unable to read p12");
        return e1.to_string();
    }

    let _pkcs12 = reqwest::Identity::from_pkcs12_der(&buf, "br31415926;;");
    let req_res = client.request(Method::GET, &url)
        .basic_auth("bruno", Some("xyzt"))
        .query(&[("lang", "rust")])
        .build();
    if let Err(e2) = req_res {
        //println!("Cannot execute request");
        return e2.to_string();
    }
    let final_result = client.execute(req_res.unwrap());
    if let Err(e3) = final_result {
        //println!("Error while executing: {:?}",e3);
        return e3.to_string();
    }
    let mut response = final_result.expect("Bad");
    println!("Execute returned : {}", response.status());
    for (k, v) in response.headers().iter() {
        println!("{:?}: {:?}", k, v);
    }

    let mut buf = String::new();
    response.read_to_string(&mut buf).expect("Failed to read response");
    //println!("{}", buf);

    "OK".to_string()
}

fn main() {
    let good_url = "https://www.cecurity.com".to_string();
//    let bad_url  = "https://xyz.cecurity.com".to_string();
    let bad_url = "https://www.cecurity.com/xyzt".to_string();
    // run1();
    // run2();
    //run3(good_url.clone());
    //run3(bad_url.clone());
    let _s = run4(good_url.clone());
    println!("run4 return {}",_s);
    let _t = run4(bad_url.clone());
    println!("run4 return {}",_t);
    let _t = run4("".to_string());
    println!("run4 return {}",_t);
}
