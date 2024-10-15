//! ![GitHub License](https://img.shields.io/github/license/janstarke/sddl)
//! [![Crates.io Version](https://img.shields.io/crates/v/sddl)](https://crates.io/crates/sddl)
//! 
//! `sddl` is a library created to forensically analyze Windows Security Descriptors
//! 
//! # Usage example
//! 
//! ```rust
//! use std::io::Cursor;
//! use binrw::BinReaderExt;
//! use sddl::{ControlFlags, SecurityDescriptor, Acl};
//! 
//! let mut binary_data = Cursor::new([0x01, 0x00, 0x14, 0xb0, 0x90, 0x00, 0x00,
//!     0x00, 0xa0, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00,
//!     0x00, 0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x80, 0x14,
//!     0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x60, 0x00, 0x04, 0x00, 0x00,
//!     0x00, 0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x01, 0x02, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x21, 0x02, 0x00,
//!     0x00, 0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x02, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00,
//!     0x00, 0x00, 0x03, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, 0x00, 0x03, 0x14,
//!     0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00, 0x01, 0x02, 0x00,
//!     0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00,
//!     0x00]);
//! let security_descriptor: SecurityDescriptor = binary_data.read_le().unwrap();
//! assert_eq!(*security_descriptor.flags(),
//!     ControlFlags::DiscretionaryAclPresent |
//!     ControlFlags::SystemAclPresent |
//!     ControlFlags::DiscretionaryAclProtected |
//!     ControlFlags::SystemAclProtected |
//!     ControlFlags::SelfRelative);
//! 
//! assert_eq!(security_descriptor.sacl().unwrap(), &Acl::from_sddl("S:P(AU;FA;GR;;;WD)", None).unwrap());
//! assert_eq!(security_descriptor.dacl().unwrap(), &Acl::from_sddl("D:P(A;CIOI;GRGX;;;BU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)", None).unwrap());
//! ``` 

lalrpop_mod!(pub parser);

mod control_flags;
mod security_descriptor;
mod sid;
mod acl;
mod ace;
mod ace_header;
mod access_mask;
mod guid;
mod offset;
mod sddl_h;
mod error;
mod raw_size;
pub (crate) mod parsing;


pub use control_flags::*;
use lalrpop_util::lalrpop_mod;
pub use security_descriptor::*;
pub use sid::*;
pub use acl::*;
pub use ace::*;
pub use ace_header::*;
pub use access_mask::AccessMask;
pub use guid::*;
pub use error::*;
pub use raw_size::*;
pub(crate) use offset::*;

pub mod constants {
    pub use crate::access_mask::constants::*;
    pub use crate::sid::constants::*;
}