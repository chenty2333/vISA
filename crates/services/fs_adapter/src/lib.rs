use std::io::{Cursor, Read, Seek, SeekFrom, Write};

pub const FAT_ADAPTER_IMPLEMENTATION: &str = "fatfs";
pub const FAT_ADAPTER_VERSION: &str = "0.3.6";
pub const FAT_ADAPTER_PROFILE: &str = "fatfs-read-write-demo-v1";
pub const FAT_ADAPTER_VOLUME_LABEL: &str = "VMOSFAT";
pub const FAT_ADAPTER_IMAGE_BYTES: usize = 1024 * 1024;
pub const EXT4_ADAPTER_IMPLEMENTATION: &str = "ext4-view";
pub const EXT4_ADAPTER_VERSION: &str = "0.9.3";
pub const EXT4_ADAPTER_PROFILE: &str = "ext4-read-only-demo-v1";
pub const EXT4_ADAPTER_VOLUME_LABEL: &str = "VMOSEXT4";
pub const EXT4_ADAPTER_IMAGE_BYTES: usize = 32 * 1024;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ext4AdapterConfig {
    pub image_bytes: usize,
    pub file_path: &'static str,
    pub volume_label: &'static str,
}

impl Ext4AdapterConfig {
    pub const fn default_vmos() -> Self {
        Self {
            image_bytes: EXT4_ADAPTER_IMAGE_BYTES,
            file_path: "/demo.txt",
            volume_label: EXT4_ADAPTER_VOLUME_LABEL,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ext4AdapterEvidence {
    pub implementation: &'static str,
    pub version: &'static str,
    pub profile: &'static str,
    pub volume_label: &'static str,
    pub image_bytes: usize,
    pub file_path: &'static str,
    pub bytes_read: u64,
    pub read_digest: u64,
    pub directory_entries: u64,
    pub read_only_enforced: bool,
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
    fatfs::format_volume(&mut image, fatfs::FormatVolumeOptions::new().volume_label(volume_label))
        .map_err(|_| "fat adapter format failed")?;
    image.seek(SeekFrom::Start(0)).map_err(|_| "fat adapter seek failed")?;

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
        let mut file =
            root.create_file(config.file_path).map_err(|_| "fat adapter create file failed")?;
        file.write_all(payload).map_err(|_| "fat adapter write failed")?;
        file.flush().map_err(|_| "fat adapter flush failed")?;
    }
    {
        let root = fs.root_dir();
        let mut file =
            root.open_file(config.file_path).map_err(|_| "fat adapter open file failed")?;
        let mut read_back = Vec::new();
        file.read_to_end(&mut read_back).map_err(|_| "fat adapter read failed")?;
        let write_digest = stable_digest(payload);
        let read_digest = stable_digest(&read_back);
        Ok(FatAdapterEvidence {
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
        })
    }
}

pub fn build_ext4_read_only_evidence(
    config: Ext4AdapterConfig,
    payload: &[u8],
) -> Result<Ext4AdapterEvidence, &'static str> {
    if config.image_bytes < EXT4_ADAPTER_IMAGE_BYTES
        || !config.file_path.starts_with('/')
        || config.file_path.as_bytes().contains(&b'\0')
        || payload.is_empty()
        || payload.len() > 1024
    {
        return Err("ext4 adapter config is invalid");
    }
    validate_ext4_label(config.volume_label)?;

    let image = build_minimal_ext4_image(
        config.image_bytes,
        config.volume_label,
        config.file_path,
        payload,
    )?;
    let fs = ext4_view::Ext4::load(Box::new(image)).map_err(|_| "ext4 adapter load failed")?;
    let observed_label = fs.label().to_str().map_err(|_| "ext4 adapter label decode failed")?;
    if observed_label != config.volume_label {
        return Err("ext4 adapter volume label mismatch");
    }
    let metadata = fs.metadata(config.file_path).map_err(|_| "ext4 adapter metadata failed")?;
    if !metadata.file_type().is_regular_file() || metadata.len() != payload.len() as u64 {
        return Err("ext4 adapter metadata mismatch");
    }
    let read_back = fs.read(config.file_path).map_err(|_| "ext4 adapter read failed")?;
    if read_back != payload {
        return Err("ext4 adapter read mismatch");
    }
    let mut directory_entries = 0u64;
    let mut found_file = false;
    for entry in fs.read_dir("/").map_err(|_| "ext4 adapter readdir failed")? {
        let entry = entry.map_err(|_| "ext4 adapter readdir entry failed")?;
        directory_entries = directory_entries.saturating_add(1);
        if entry.file_name().as_str().ok() == Some("demo.txt") {
            found_file = true;
        }
    }
    if !found_file {
        return Err("ext4 adapter directory entry missing");
    }

    Ok(Ext4AdapterEvidence {
        implementation: EXT4_ADAPTER_IMPLEMENTATION,
        version: EXT4_ADAPTER_VERSION,
        profile: EXT4_ADAPTER_PROFILE,
        volume_label: config.volume_label,
        image_bytes: config.image_bytes,
        file_path: config.file_path,
        bytes_read: read_back.len() as u64,
        read_digest: stable_digest(&read_back),
        directory_entries,
        read_only_enforced: true,
    })
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

fn validate_ext4_label(label: &str) -> Result<(), &'static str> {
    let bytes = label.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 16
        || bytes.iter().any(|byte| !(0x21..=0x7e).contains(byte))
    {
        return Err("ext4 adapter config is invalid");
    }
    Ok(())
}

fn build_minimal_ext4_image(
    image_bytes: usize,
    volume_label: &str,
    file_path: &str,
    payload: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let file_name = file_path.strip_prefix('/').ok_or("ext4 adapter config is invalid")?;
    if file_name.is_empty() || file_name.as_bytes().contains(&b'/') || file_name.len() > 255 {
        return Err("ext4 adapter config is invalid");
    }
    let block_size = 1024usize;
    let block_count = image_bytes / block_size;
    if !image_bytes.is_multiple_of(block_size) || block_count < 32 {
        return Err("ext4 adapter image is too small");
    }
    if u32::try_from(block_count).is_err() {
        return Err("ext4 adapter image is too large");
    }

    let mut image = vec![0u8; image_bytes];
    write_superblock(&mut image[block_size..block_size * 2], block_count as u32, volume_label);
    write_group_descriptor(&mut image[block_size * 2..block_size * 2 + 32]);
    write_block_bitmap(&mut image[block_size * 3..block_size * 4]);
    write_inode_bitmap(&mut image[block_size * 4..block_size * 5]);
    write_inode(&mut image, 2, 0x4000 | 0o755, block_size as u32, 7, true);
    write_inode(&mut image, 12, 0x8000 | 0o644, payload.len() as u32, 8, false);
    write_root_directory(&mut image[block_size * 7..block_size * 8], file_name)?;
    image[block_size * 8..block_size * 8 + payload.len()].copy_from_slice(payload);
    Ok(image)
}

fn write_superblock(block: &mut [u8], block_count: u32, volume_label: &str) {
    write_u32(block, 0x00, 16);
    write_u32(block, 0x04, block_count);
    write_u32(block, 0x0c, block_count.saturating_sub(9));
    write_u32(block, 0x10, 4);
    write_u32(block, 0x14, 1);
    write_u32(block, 0x18, 0);
    write_u32(block, 0x1c, 0);
    write_u32(block, 0x20, block_count);
    write_u32(block, 0x24, block_count);
    write_u32(block, 0x28, 16);
    write_u16(block, 0x38, 0xef53);
    write_u16(block, 0x3a, 1);
    write_u16(block, 0x3c, 1);
    write_u32(block, 0x54, 11);
    write_u16(block, 0x58, 128);
    write_u32(block, 0x60, 0x2);
    write_u16(block, 0xfe, 32);
    let label = volume_label.as_bytes();
    block[0x78..0x78 + label.len()].copy_from_slice(label);
}

fn write_group_descriptor(bytes: &mut [u8]) {
    write_u32(bytes, 0x00, 3);
    write_u32(bytes, 0x04, 4);
    write_u32(bytes, 0x08, 5);
    write_u16(bytes, 0x0c, 23);
    write_u16(bytes, 0x0e, 4);
    write_u16(bytes, 0x10, 2);
}

fn write_block_bitmap(block: &mut [u8]) {
    for bit in 0..=8 {
        block[bit / 8] |= 1 << (bit % 8);
    }
}

fn write_inode_bitmap(block: &mut [u8]) {
    block[0] = 0b0000_0011;
    block[1] = 0b0000_1000;
}

fn write_inode(
    image: &mut [u8],
    inode: usize,
    mode: u16,
    size: u32,
    data_block: u32,
    is_dir: bool,
) {
    let inode_table_offset = 5 * 1024;
    let offset = inode_table_offset + (inode - 1) * 128;
    let bytes = &mut image[offset..offset + 128];
    write_u16(bytes, 0x00, mode);
    write_u32(bytes, 0x04, size);
    write_u32(bytes, 0x1c, 2);
    write_u32(bytes, 0x28, data_block);
    write_u32(bytes, 0x64, inode as u32);
    if is_dir {
        write_u16(bytes, 0x1a, 2);
    } else {
        write_u16(bytes, 0x1a, 1);
    }
}

fn write_root_directory(block: &mut [u8], file_name: &str) -> Result<(), &'static str> {
    write_dir_entry(block, 0, 2, 12, 2, ".");
    write_dir_entry(block, 12, 2, 12, 2, "..");
    let name_len = file_name.len();
    let rec_len = 1024usize.checked_sub(24).ok_or("ext4 adapter directory overflow")?;
    if rec_len > u16::MAX as usize || name_len > 255 {
        return Err("ext4 adapter directory entry invalid");
    }
    write_dir_entry(block, 24, 12, rec_len as u16, 1, file_name);
    Ok(())
}

fn write_dir_entry(
    block: &mut [u8],
    offset: usize,
    inode: u32,
    rec_len: u16,
    file_type: u8,
    name: &str,
) {
    write_u32(block, offset, inode);
    write_u16(block, offset + 4, rec_len);
    block[offset + 6] = name.len() as u8;
    block[offset + 7] = file_type;
    block[offset + 8..offset + 8 + name.len()].copy_from_slice(name.as_bytes());
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
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
                FatAdapterConfig { image_bytes: 512, ..FatAdapterConfig::default_vmos() },
                b"x"
            ),
            Err("fat adapter image is too small")
        );
        assert_eq!(
            build_fat_read_write_evidence(
                FatAdapterConfig { file_path: "DIR/DEMO.TXT", ..FatAdapterConfig::default_vmos() },
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

    #[test]
    fn ext4_adapter_reads_deterministic_read_only_image() {
        let payload = b"vmos ext4 adapter read only payload";
        let evidence =
            build_ext4_read_only_evidence(Ext4AdapterConfig::default_vmos(), payload).unwrap();

        assert_eq!(evidence.implementation, EXT4_ADAPTER_IMPLEMENTATION);
        assert_eq!(evidence.version, EXT4_ADAPTER_VERSION);
        assert_eq!(evidence.profile, EXT4_ADAPTER_PROFILE);
        assert_eq!(evidence.volume_label, EXT4_ADAPTER_VOLUME_LABEL);
        assert_eq!(evidence.file_path, "/demo.txt");
        assert_eq!(evidence.bytes_read, payload.len() as u64);
        assert_eq!(evidence.read_digest, stable_digest(payload));
        assert!(evidence.directory_entries >= 1);
        assert!(evidence.read_only_enforced);
    }

    #[test]
    fn ext4_adapter_rejects_invalid_config_or_empty_payload() {
        assert_eq!(
            build_ext4_read_only_evidence(
                Ext4AdapterConfig { image_bytes: 1024, ..Ext4AdapterConfig::default_vmos() },
                b"x"
            ),
            Err("ext4 adapter config is invalid")
        );
        assert_eq!(
            build_ext4_read_only_evidence(
                Ext4AdapterConfig { file_path: "demo.txt", ..Ext4AdapterConfig::default_vmos() },
                b"x"
            ),
            Err("ext4 adapter config is invalid")
        );
        assert_eq!(
            build_ext4_read_only_evidence(
                Ext4AdapterConfig {
                    volume_label: "LABEL-TOO-LONG-FOR-EXT4",
                    ..Ext4AdapterConfig::default_vmos()
                },
                b"x"
            ),
            Err("ext4 adapter config is invalid")
        );
        assert_eq!(
            build_ext4_read_only_evidence(Ext4AdapterConfig::default_vmos(), b""),
            Err("ext4 adapter config is invalid")
        );
    }
}
