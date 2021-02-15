extern crate tokio;

//use tokio::io;
use tokio::prelude::*;

//use futures::prelude::*;
//use futures::future;

fn run1() {
    let future = future::ok::<u32,u32>(1);
    let new_future = future.map(|x| x+ 4);
    let res = new_future.wait();
    let result = match  res {
        Ok(x) =>  x,
        _ => 0 };
    println!("Result is {}", result);
}

fn main() {
    run1();
}