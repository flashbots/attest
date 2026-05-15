//! GCP TDX expected register rebuild

use hex_literal::hex;
use pccs::Pccs;
use types::{DcapImageHashes, PlatformMetadata};

use crate::{VerifyError, dcap, report_mismatch};

// TODO: replace with verified GCE endorsement lookup
const KNOWN_MRTD: [u8; 48] = hex!(
    "feb7486608382c1ff0e15b4648ddc0acea6ca974eb53e3529f4c4bd5ffbaa20bf335cb75965cea65fe473aed9647c162"
);
const KNOWN_CFV: [u8; 48] = hex!(
    "9cb6bf09aea7b4acb8549e328d0edd6f15defc0b00d744bb9fb5bab0962bc5c70f69d233e96dbc7c1105ba085781dc88"
);

pub fn verify_portable(
    image_hashes: &DcapImageHashes,
    platform: &PlatformMetadata,
    quote: &[u8],
    pccs: &Pccs,
    time: u64,
    debug: bool,
) -> Result<[u8; 64], VerifyError> {
    let raw = dcap::validate_quote_at(quote, pccs, time)?;
    let acpi = platform.acpi.as_ref().ok_or(VerifyError::MissingAcpi)?;
    let PlatformMetadata { num_disks, ram_bytes, .. } = platform;

    let expected_rtmr0 = measure::dcap::gcp::build_rtmr0(*ram_bytes, KNOWN_CFV, acpi, *num_disks)?;
    let expected_rtmr1 = measure::dcap::gcp::build_rtmr1(image_hashes);
    let expected_rtmr2 = measure::dcap::build_rtmr2(image_hashes);

    let mut mismatches = Vec::new();
    if raw.mrtd != KNOWN_MRTD {
        report_mismatch(debug, "MRTD", &raw.mrtd, &KNOWN_MRTD);
        mismatches.push("MRTD");
    }
    for (name, actual, expected) in [
        ("RTMR0", raw.rtmr0, &expected_rtmr0),
        ("RTMR1", raw.rtmr1, &expected_rtmr1),
        ("RTMR2", raw.rtmr2, &expected_rtmr2),
    ] {
        if actual != expected.value() {
            report_mismatch(debug, name, &actual, &expected.value());
            if debug {
                eprintln!("  events:   {:#?}", expected.debug_json());
            }
            mismatches.push(name);
        }
    }
    if !mismatches.is_empty() {
        return Err(VerifyError::RegisterMismatch(mismatches));
    }
    Ok(raw.report_data)
}
