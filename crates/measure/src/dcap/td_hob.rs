//! TD HOB digest for GCP c3-standard TDX VMs

use anyhow::{Result, ensure};
use sha2::{Digest, Sha384};

const TEMPLATE: &[u8; HASH_LEN] = include_bytes!("../../assets/td_hob_template.bin");
const HASH_LEN: usize = 0x248;
const RESOURCE_LENGTH_OFFSET: usize = 0x240;
const GIB: u64 = 1 << 30;

pub fn digest(ram_bytes: u64) -> Result<[u8; 48]> {
    ensure!(ram_bytes > 3 * GIB, "RAM must be > 3 GiB, got {ram_bytes} B");
    let above_4g = ram_bytes - 3 * GIB;
    let mut buf = *TEMPLATE;
    buf[RESOURCE_LENGTH_OFFSET..HASH_LEN].copy_from_slice(&above_4g.to_le_bytes());
    Ok(Sha384::digest(buf).into())
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn matches_known_gcp_machine_digests() {
        let cases = [
            (16, hex!("458994daa60deac8dea19dba79748f6ff93fd0aebb8e3e0be5a65eb12309d342c3ce31cc67af7bbd22af1a44e7d9fe21")),
            (32, hex!("aa9e81feeb58a9eb3a9f4110cc7b5696240437ea4c1a9c30518cfc44fa305183e6473e6bc02ddc4de09d0c49c49fadb5")),
            (88, hex!("a5be8ecd74020972e328fbbe94d2886817ef0d2e8a4e94e9572e8e1b221f3f608cddc868cf8b08e8e645e4aaeba68279")),
            (176, hex!("21092eadb73948aebb405b826354c23c3025635c89a8d91f85905afb120b7d98025a6c3083e8e82b5320695b253ce341")),
        ];
        for (gib, expected) in cases {
            assert_eq!(digest(gib * GIB).unwrap(), expected, "ram={gib} GiB");
        }
    }
}
