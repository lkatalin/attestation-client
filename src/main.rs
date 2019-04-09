use sgx_isa::{Report, Targetinfo, Keyrequest, Keyname};
use std::net::{TcpStream};
use std::io::{self, Read, Write};
use crypto_mac::Mac;
use cmac::Cmac;
use aes::Aes128;

// verify that attesting enclave is on same CPU as this enclave
// based on 
// https://gist.github.com/Vinc0682/10c074202c995e4f87b4edf278ec4cae
fn verify_report(report: &Report) -> bool {

    // create a key request containing keyname and keyid
    let key_request = Keyrequest {
        keyname: Keyname::Report as _,
        keyid: report.keyid.clone(),
        ..Default::default()
    };

    // call EGETKEY with key_request parameters to get report's key
    let key = key_request.egetkey().expect("failed to get key");
    
    // extract the MAC from the report
    let report_ref: &[u8] = report.as_ref();
    let mut mac_from_report = &report_ref[0..Report::UNPADDED_SIZE-48];

    // compute the MAC for the EGETKEY result
    let mut mac_computed = Cmac::<Aes128>::new_varkey(&key[..]).unwrap();
    mac_computed.input(&mut mac_from_report);

    // verify that computed MAC matches MAC from report
    mac_computed.verify(&report.mac).is_ok()
}

fn main() -> io::Result<()> {

    // find targetinfo for current enclave
    let targetinfo = Targetinfo::from(Report::for_self());
    
    // connect to server or 'attesting' enclave
    match TcpStream::connect("localhost:1035") {
        Ok(mut stream) => {

            println!("\nSuccessfully connected to server on port 1035.\n");

            // send current enclave's targetinfo to attesting enclave
            stream.write(targetinfo.as_ref()).unwrap();
            
            // read report that attesting enclave created for 
            // target info that was sent
            let mut data = [0; Report::UNPADDED_SIZE];
            match stream.read_exact(&mut data) {
                Ok(_) => {
                    let rep_back = Report::try_copy_from(&data).unwrap();

                    // calculate MAC for report key and verify that
                    // it matches MAC in report
                    let does_match = verify_report(&rep_back);

                    println!("MAC matches: {}\n", does_match);
                },

                Err(e) => {
                    println!("Failed to receive data: {}", e);
                }
            }
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
        
    }
    Ok(())
}
