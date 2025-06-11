use sddl::SecurityDescriptor;

/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2918391b-75b9-4eeb-83f0-7fdc04a5c6c9>
#[test]
fn testcase1() {
    let sddl_string = "O:BAG:BAD:P(A;CIOI;GRGX;;;BU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)S:P(AU;FA;GR;;;WD)";
    let domain_rid = [1,2,3];
    let _ = SecurityDescriptor::from_sddl(sddl_string, Some(&domain_rid)).unwrap();
}

#[test]
fn testcase1_reversed() {
    let sddl_string = "O:BAG:BAS:P(AU;FA;GR;;;WD)D:P(A;CIOI;GRGX;;;BU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)";
    let domain_rid = [1,2,3];
    let _ = SecurityDescriptor::from_sddl(sddl_string, Some(&domain_rid)).unwrap();
}
