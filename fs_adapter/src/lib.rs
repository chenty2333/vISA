use std::io::{Cursor, Read, Seek, SeekFrom, Write};

pub const FAT_ADAPTER_IMPLEMENTATION: &str = "fatfs";
pub const FAT_ADAPTER_VERSION: &str = "0.3.6";
pub const FAT_ADAPTER_PROFILE: &str = "fatfs-read-write-demo-v1";
pub const FAT_ADAPTER_VOLUME_LABEL: &str = "VMOSFAT";
pub const FAT_ADAPTER_IMAGE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FatAdapterConfig {
    pub image_bytes: usize,
    pub file_path: &'static str,
    pub volume_label: &'static str,
}

impl FatAdapterConfig {
    pub const fn default_vmos() -> Self {
        Self {
            image_bytes: FAT_ADAPTER_IMAGE_BYTES,
            file_path: "DEMO.TXT",
            volume_label: FAT_ADAPTER_VOLUME_LABEL,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FatAdapterEvidence {
    pub implementation: &'static str,
    pub version: &'static str,
    pub profile: &'static str,
    pub volume_label: &'static str,
    pub image_bytes: usize,
    pub file_path: &'static str,
    pub bytes_written: u64,
    pub bytes_read: u64,
    pub write_digest: u64,
    pub read_digest: u64,
    pub roundtrip_ok: bool,
}

pub fn build_fat_read_write_evidence(
    config: FatAdapterConfig,
    payload: &[u8],
) -> Result<FatAdapterEvidence, &'static str> {
    if config.image_bytes < FAT_ADAPTER_IMAGE_BYTES {
        return Err("fat adapter image is too small");
    }
    if config.file_path.is_empty()
        || config.file_path.as_bytes().contains(&b'/')
        || payload.is_empty()
    {
        return Err("fat adapter config is invalid");
    }
    let volume_label = fat_volume_label(config.volume_label)?;

    let mut image = Cursor::new(vec![0u8; config.image_bytes]);
    fatfs::format_volume(
        &mut image,
        fatfs::FormatVolumeOptions::new().volume_label(volume_label),
    )
    .map_err(|_| "fat adapter format failed")?;
    image
        .seek(SeekFrom::Start(0))
        .map_err(|_| "fat adapter seek failed")?;

    let fs = fatfs::FileSystem::new(image, fatfs::FsOptions::new())
        .map_err(|_| "fat adapter mount failed")?;
    let observed_label = fs
        .read_volume_label_from_root_dir()
        .map_err(|_| "fat adapter volume label read failed")?
        .ok_or("fat adapter volume label missing")?;
    if observed_label != config.volume_label {
        return Err("fat adapter volume label mismatch");
    }
    {
        let root = fs.root_dir();
        let mut file = root
            .create_file(config.file_path)
            .map_err(|_| "fat adapter create file failed")?;
        file.write_all(payload)
            .map_err(|_| "fat adapter write failed")?;
        file.flush().map_err(|_| "fat adapter flush failed")?;
    }
    {
        let root = fs.root_dir();
        let mut file = root
            .open_file(config.file_path)
            .map_err(|_| "fat adapter open file failed")?;
        let mut read_back = Vec::new();
        file.read_to_end(&mut read_back)
            .map_err(|_| "fat adapter read failed")?;
        let write_digest = stable_digest(payload);
        let read_digest = stable_digest(&read_back);
        return Ok(FatAdapterEvidence {
            implementation: FAT_ADAPTER_IMPLEMENTATION,
            version: FAT_ADAPTER_VERSION,
            profile: FAT_ADAPTER_PROFILE,
            volume_label: config.volume_label,
            image_bytes: config.image_bytes,
            file_path: config.file_path,
            bytes_written: payload.len() as u64,
            bytes_read: read_back.len() as u64,
            write_digest,
            read_digest,
            roundtrip_ok: payload == read_back.as_slice() && write_digest == read_digest,
        });
    }
}

fn fat_volume_label(label: &str) -> Result<[u8; 11], &'static str> {
    let bytes = label.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 11
        || bytes.iter().any(|byte| !(0x21..=0x7e).contains(byte))
    {
        return Err("fat adapter config is invalid");
    }
    let mut encoded = [b' '; 11];
    encoded[..bytes.len()].copy_from_slice(bytes);
    Ok(encoded)
}

pub fn stable_digest(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fat_adapter_formats_writes_and_reads_back_file() {
        let payload = b"vmos fat adapter read write payload";
        let evidence =
            build_fat_read_write_evidence(FatAdapterConfig::default_vmos(), payload).unwrap();

        assert_eq!(evidence.implementation, FAT_ADAPTER_IMPLEMENTATION);
        assert_eq!(evidence.version, FAT_ADAPTER_VERSION);
        assert_eq!(evidence.profile, FAT_ADAPTER_PROFILE);
        assert_eq!(evidence.volume_label, FAT_ADAPTER_VOLUME_LABEL);
        assert_eq!(evidence.file_path, "DEMO.TXT");
        assert_eq!(evidence.bytes_written, payload.len() as u64);
        assert_eq!(evidence.bytes_read, payload.len() as u64);
        assert_eq!(evidence.write_digest, stable_digest(payload));
        assert_eq!(evidence.read_digest, evidence.write_digest);
        assert!(evidence.roundtrip_ok);
    }

    #[test]
    fn fat_adapter_rejects_invalid_config_or_empty_payload() {
        assert_eq!(
            build_fat_read_write_evidence(
                FatAdapterConfig {
                    image_bytes: 512,
                    ..FatAdapterConfig::default_vmos()
                },
                b"x"
            ),
            Err("fat adapter image is too small")
        );
        assert_eq!(
            build_fat_read_write_evidence(
                FatAdapterConfig {
                    file_path: "DIR/DEMO.TXT",
                    ..FatAdapterConfig::default_vmos()
                },
                b"x"
            ),
            Err("fat adapter config is invalid")
        );
        assert_eq!(
            build_fat_read_write_evidence(
                FatAdapterConfig {
                    volume_label: "LABEL-TOO-LONG",
                    ..FatAdapterConfig::default_vmos()
                },
                b"x"
            ),
            Err("fat adapter config is invalid")
        );
        assert_eq!(
            build_fat_read_write_evidence(FatAdapterConfig::default_vmos(), b""),
            Err("fat adapter config is invalid")
        );
    }
}
