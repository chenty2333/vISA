use contract_core::canonical_bytes;
use visa_profile::ProfileVersion;

#[test]
fn cooperative_profile_version_1_0_is_exact() {
    let id = "cooperative-profile-version-1.0";
    let bytes = canonical_bytes(&ProfileVersion::new(1, 0)).unwrap();
    assert_eq!(bytes.as_slice(), &[0x01, 0x00], "{id} Postcard bytes drifted");
    assert_eq!(hex(&bytes), "0100", "{id} manifest vector drifted");
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("String writes do not fail");
    }
    output
}
