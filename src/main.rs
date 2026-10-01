mod sample;
mod sample_signing;

fn main() {
    let result = match std::env::args().nth(1).as_deref() {
        Some("sample") => sample::run(),
        Some("-h" | "--help" | "help") | None => {
            println!("usage: crowsi-independent-verifier sample");
            Ok(())
        }
        Some(_) => Err("unsupported command".into()),
    };
    if let Err(error) = result {
        eprintln!("crowsi independent verifier sample failed: {error}");
        std::process::exit(1);
    }
}
