use lazy_regex::regex_captures;
use std::env;
use std::fs;
use std::io;
use std::io::BufRead;
use std::io::Write;
use std::path::Path;

#[derive(Copy, Clone, Default, Eq, PartialEq)]
enum HeaderSection {
    UserAliases,
    IntegrityLabels,

    #[default]
    Other,
}

#[derive(Default, Eq, PartialEq)]
enum LineVariant {
    BeginSectionHeader,
    SectionTitle(HeaderSection),
    EndSectionHeader(HeaderSection),

    #[default]
    Other,
}

fn main() {
    let mut section = HeaderSection::default();
    let mut line_variant = LineVariant::default();

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let reader = io::BufReader::new(fs::File::open("misc/sddl.h").unwrap());
    let mut out_file =
        io::BufWriter::new(fs::File::create(Path::new(&out_dir).join("sddl_h.rs")).unwrap());

    writeln!(out_file, "#[allow(unused,non_upper_case_globals)]").unwrap();
    writeln!(out_file, "pub (crate) mod sddl_constants {{").unwrap();

    for line in reader.lines() {
        let line = line.unwrap();

        match line_variant {
            LineVariant::BeginSectionHeader => {
                if let Some((_, name)) = regex_captures!(r#"^// ([a-zA-Z ]+)"#, &line) {
                    let s = match name {
                        "SDDL User aliases" => HeaderSection::UserAliases,
                        "Integrity Labels" => HeaderSection::IntegrityLabels,
                        _ => HeaderSection::Other,
                    };
                    line_variant = LineVariant::SectionTitle(s);
                }
            }
            LineVariant::SectionTitle(header_section) => {
                if line == "//" {
                    line_variant = LineVariant::EndSectionHeader(header_section);
                    section = header_section;
                } else {
                    line_variant = LineVariant::Other;
                }
            }
            LineVariant::EndSectionHeader(header_section) => {
                line_variant = LineVariant::Other;
                section = header_section;
            }
            LineVariant::Other => {
                if line == "//" {
                    line_variant = LineVariant::BeginSectionHeader;
                }
            }
        }

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

            match section {
                HeaderSection::UserAliases | HeaderSection::IntegrityLabels => {
                    writeln!(
                        out_file,
                        "pub const {id}: crate::SidAlias = crate::SidAlias::{value};"
                    )
                    .unwrap();
                }
                HeaderSection::Other => {
                    writeln!(out_file, "pub const {id}: &str = \"{value}\";").unwrap();
                }
            }
        }
    }
    writeln!(out_file, "}}").unwrap();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=misc/sddl.h");
    println!("cargo:rerun-if-changed=src/parser.lalrpop");

    lalrpop::process_root().unwrap();
}
