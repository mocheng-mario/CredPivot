use ovb1_structure::{parse_layout, StructureError};

#[test]
fn rejects_truncated() {
    let data = b"OVB1";
    assert!(matches!(parse_layout(data), Err(StructureError::TooShort)));
}

#[test]
fn accepts_minimal_header_no_ciphertext() {
    let mut data = Vec::new();
    data.extend_from_slice(b"OVB1");
    data.push(1); // major
    data.push(0); // minor
    data.extend_from_slice(&[0u8; 16]); // vault_id
    data.extend_from_slice(&[0u8; 32]); // archive_id
    data.push(1); // cipher
    data.extend_from_slice(&[0u8; 12]); // nonce
    data.extend_from_slice(&0u32.to_be_bytes()); // slots_len = 0
    data.extend_from_slice(&0u32.to_be_bytes()); // ct_len = 0
    let parsed = parse_layout(&data).expect("layout");
    assert_eq!(parsed.ciphertext_len, 0);
}
