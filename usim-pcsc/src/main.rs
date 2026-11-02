//! Small hardware bring-up tool for the PC/SC USIM channel.
//!
//! ```sh
//! usim-pcsc list
//! usim-pcsc atr [--reader NAME]
//! usim-pcsc apdu 00A40004023F00 [--reader NAME]
//! usim-pcsc auth RAND_HEX AUTN_HEX [--reader NAME]
//! ```

use usim::{AkaOutput, Usim as _, UsimCard};
use usim_pcsc::{PcscChannel, PcscError};

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err("hex length must be even".into());
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|_| format!("bad hex byte {:?}", &cleaned[i..i + 2]))
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn die(e: PcscError) -> ! {
    eprintln!("usim-pcsc: {e}");
    std::process::exit(1);
}

fn parse_reader(args: &[String]) -> (Option<String>, Vec<String>) {
    let mut reader = None;
    let mut rest = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--reader" {
            reader = args.get(i + 1).cloned();
            i += 2;
        } else {
            rest.push(args[i].clone());
            i += 1;
        }
    }
    (reader, rest)
}

fn main() {
    let (reader, args) = parse_reader(&std::env::args().skip(1).collect::<Vec<_>>());
    let Some(command) = args.first().map(String::as_str) else {
        eprintln!("usage: usim-pcsc list|atr|apdu HEX|auth RAND_HEX AUTN_HEX [--reader NAME]");
        std::process::exit(2);
    };
    match command {
        "list" => match usim_pcsc::list_readers() {
            Ok(readers) => {
                if readers.is_empty() {
                    println!("no PC/SC readers");
                } else {
                    for name in readers {
                        println!("{name}");
                    }
                }
            }
            Err(e) => die(e),
        },
        "atr" => {
            let channel = PcscChannel::open(reader.as_deref()).unwrap_or_else(|e| die(e));
            println!("reader={}", channel.reader());
            match channel.atr() {
                Ok(atr) => println!("atr={}", hex(&atr)),
                Err(e) => die(e),
            }
        }
        "apdu" => {
            let Some(raw) = args.get(1) else {
                eprintln!("usage: usim-pcsc apdu HEX [--reader NAME]");
                std::process::exit(2);
            };
            let apdu = hex_decode(raw).unwrap_or_else(|e| {
                eprintln!("usim-pcsc: {e}");
                std::process::exit(2);
            });
            use usim::ApduChannel;
            let mut channel = PcscChannel::open(reader.as_deref()).unwrap_or_else(|e| die(e));
            match channel.transmit(&apdu) {
                Ok(response) => {
                    println!("data={}", hex(&response.data));
                    println!("sw={:02x}{:02x}", response.sw1, response.sw2);
                }
                Err(e) => {
                    eprintln!("usim-pcsc: {e}");
                    std::process::exit(1);
                }
            }
        }
        "auth" => {
            let (Some(rand_hex), Some(autn_hex)) = (args.get(1), args.get(2)) else {
                eprintln!("usage: usim-pcsc auth RAND_HEX AUTN_HEX [--reader NAME]");
                std::process::exit(2);
            };
            let rand = hex_decode(rand_hex).unwrap_or_else(|e| {
                eprintln!("usim-pcsc: {e}");
                std::process::exit(2);
            });
            let autn = hex_decode(autn_hex).unwrap_or_else(|e| {
                eprintln!("usim-pcsc: {e}");
                std::process::exit(2);
            });
            let (Ok(rand), Ok(autn)) = (
                <[u8; 16]>::try_from(rand.as_slice()),
                <[u8; 16]>::try_from(autn.as_slice()),
            ) else {
                eprintln!("usim-pcsc: RAND and AUTN must each be 16 bytes");
                std::process::exit(2);
            };
            let channel = PcscChannel::open(reader.as_deref()).unwrap_or_else(|e| die(e));
            let mut card = UsimCard::new(channel);
            match card.authenticate(&rand, &autn) {
                Ok(AkaOutput::Success { res, ck, ik }) => {
                    println!("res={}", hex(&res));
                    println!("ck={}", hex(&ck));
                    println!("ik={}", hex(&ik));
                }
                Ok(AkaOutput::SyncFailure { auts }) => {
                    println!("auts={}", hex(&auts));
                }
                Err(e) => {
                    eprintln!("usim-pcsc: {e}");
                    std::process::exit(1);
                }
            }
        }
        other => {
            eprintln!("usim-pcsc: unknown command {other:?}");
            std::process::exit(2);
        }
    }
}
