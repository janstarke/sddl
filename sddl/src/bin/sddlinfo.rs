use anyhow::Result;
use clap::Parser;
use getset::Getters;
use sddl::SecurityDescriptor;

/// parse an SDDL string and print its meaning
#[derive(Parser, Debug, Getters)]
#[clap(name="sddlinfo", author, version, about, long_about = None)]
#[getset(get="pub")]
struct Cli {
    sddl_string: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let sd = SecurityDescriptor::from_sddl(cli.sddl_string(), None)?;
    println!("{}", serde_json::to_string_pretty(&sd)?);
    Ok(())
}