use sgx_isa::{Report, Targetinfo};
use std::net::TcpStream;
use std::io::{Write};

fn main() {
    match TcpStream::connect("localhost:1025") {
        Ok(mut stream) => {
            println!("\nSuccessfully connected to server on port 1025\n");

            let report = Report::for_self();
            let targetinfo = Targetinfo::from(Report::for_self());
            println!("{:?}\n", report);
            println!("{:?}", targetinfo);

            stream.write(targetinfo.as_ref()).unwrap();
            println!("Sent Targetinfo...");
        
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }
    
    println!("Terminated.");
}
