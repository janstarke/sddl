# sddl

![GitHub License](https://img.shields.io/github/license/janstarke/sddl)
[![Crates.io Version](https://img.shields.io/crates/v/sddl)](https://crates.io/crates/sddl)

`sddl` is a library created to forensically analyze Windows Security Descriptors

## Usage example

```rust
use sddl::{Acl, ControlFlags, SecurityDescriptor};

let mut binary_data = [0x01, 0x00, 0x14, 0xb0, 0x90, 0x00, 0x00,
    0x00, 0xa0, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x80, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x60, 0x00, 0x04, 0x00, 0x00,
    0x00, 0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x01, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x21, 0x02, 0x00,
    0x00, 0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00,
    0x00, 0x00, 0x03, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, 0x00, 0x03, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00, 0x01, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00,
    0x00];
let security_descriptor = SecurityDescriptor::try_from(&binary_data[..]).unwrap();
println!("{:?}", security_descriptor.flags());
assert!(security_descriptor.flags().contains(ControlFlags::DiscretionaryAclPresent));
assert!(security_descriptor.flags().contains(ControlFlags::SystemAclPresent));
assert!(security_descriptor.flags().contains(ControlFlags::DiscretionaryAclProtected));
assert!(security_descriptor.flags().contains(ControlFlags::SystemAclProtected));
assert!(security_descriptor.flags().contains(ControlFlags::SelfRelative));

assert_eq!(security_descriptor.sacl().unwrap(),
            &Acl::from_sddl("S:P(AU;FA;GR;;;WD)", None).unwrap());
assert_eq!(security_descriptor.dacl().unwrap(),
            &Acl::from_sddl("D:P(A;CIOI;GRGX;;;BU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)", None).unwrap());
```

License: GPL-3.0
