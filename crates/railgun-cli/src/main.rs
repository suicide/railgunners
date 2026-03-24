//! Thin command-line surface for the RAILGUN workspace.

use railgun_core::sdk_info;

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("version") => print_version(),
        Some("scaffold-info") => print_scaffold_info(),
        _ => print_help(),
    }
}

fn print_version() {
    let info = sdk_info();
    println!("{} {}", info.name, info.version);
}

fn print_scaffold_info() {
    println!("The RAILGUN workspace scaffold is in place.");
    println!("Core crates define typed protocol models and capability traits.");
    println!("Adapter crates are reserved for concrete external integrations.");
    println!("The CLI is intentionally thin and will grow through public SDK APIs.");
}

fn print_help() {
    println!("railgun-cli");
    println!();
    println!("Commands:");
    println!("  version        Show the workspace version");
    println!("  scaffold-info  Describe the current scaffold");
}
