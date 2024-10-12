use lazy_regex::regex_captures;
use std::env;
use std::fs;
use std::io;
use std::io::BufRead;
use std::io::Write;
use std::path::Path;

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let reader = io::BufReader::new(fs::File::open("misc/sddl.h").unwrap());
    let mut out_file = io::BufWriter::new(
        fs::File::create(Path::new(&out_dir).join("sddl_h.rs")).unwrap(),
    );

    writeln!(out_file, "#[allow(unused)]").unwrap();
    writeln!(out_file, "pub (crate) mod sddl_constants {{").unwrap();

    for line in reader.lines() {
        let line = line.unwrap();
        if let Some((_, id, value, comment)) = regex_captures!(
            r#"#define\s+(SDDL_[a-zA-Z0-9_]+)\s+TEXT\('([^']+)'\)(?:\s+//\s*(.+)?)?"#,
            &line
        ) {
            if !comment.is_empty() {
                writeln!(out_file, "/// {comment}").unwrap();
            }
            writeln!(out_file, "pub const {id}: char = \'{value}\';").unwrap();
        } else if let Some((_, id, value, comment)) = regex_captures!(
            r#"#define\s+(SDDL_[a-zA-Z0-9_]+)\s+TEXT\("([^"]+)"\)(?:\s+//\s*(.+)?)?"#,
            &line
        ) {
            if !comment.is_empty() {
                writeln!(out_file, "/// {comment}").unwrap();
            }
            writeln!(out_file, "pub const {id}: &str = \"{value}\";").unwrap();
        }
    }
    writeln!(out_file, "}}").unwrap();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=misc/sddl.h");
}
