use super::*;

pub(crate) fn record_block_runtime_b13_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let file = semantic.apply_envelope(CommandEnvelope::new(
        268,
        "target-executor-b13",
        SemanticCommand::RecordFileObject {
            file_object: 20_073,
            buffer_cache_object: 20_069,
            buffer_cache_object_generation: 1,
            namespace: "rootfs".to_owned(),
            file_key: "demo-file".to_owned(),
            path: "/demo/file.txt".to_owned(),
            file_offset: 0,
            byte_len: 4096,
            file_size: 4096,
            content_digest: 0xB13,
            state: FileObjectState::Dirty,
            note: "b13-materialize-file-object-from-buffer-cache".to_owned(),
        },
    ));
    if file.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b13 file object command {} ({}) failed: status={} violations={:?}",
            file.command_id,
            file.command,
            file.status.as_str(),
            file.violations
        )
        .into());
    }

    let stale_cache = semantic.apply_envelope(CommandEnvelope::new(
        269,
        "target-executor-b13",
        SemanticCommand::RecordFileObject {
            file_object: 20_074,
            buffer_cache_object: 20_069,
            buffer_cache_object_generation: 2,
            namespace: "rootfs".to_owned(),
            file_key: "demo-file".to_owned(),
            path: "/demo/file.txt".to_owned(),
            file_offset: 0,
            byte_len: 4096,
            file_size: 4096,
            content_digest: 0xB13,
            state: FileObjectState::Dirty,
            note: "b13-reject-stale-buffer-cache-generation".to_owned(),
        },
    ));
    if stale_cache.status != CommandStatus::Rejected
        || !stale_cache
            .violations
            .iter()
            .any(|violation| violation.contains("buffer cache generation"))
    {
        return Err(format!(
            "block runtime b13 stale cache command {} ({}) was not rejected: status={} violations={:?}",
            stale_cache.command_id,
            stale_cache.command,
            stale_cache.status.as_str(),
            stale_cache.violations
        )
        .into());
    }

    let oversized = semantic.apply_envelope(CommandEnvelope::new(
        270,
        "target-executor-b13",
        SemanticCommand::RecordFileObject {
            file_object: 20_075,
            buffer_cache_object: 20_069,
            buffer_cache_object_generation: 1,
            namespace: "rootfs".to_owned(),
            file_key: "demo-file".to_owned(),
            path: "/demo/file.txt".to_owned(),
            file_offset: 0,
            byte_len: 4097,
            file_size: 4097,
            content_digest: 0xB13,
            state: FileObjectState::Dirty,
            note: "b13-reject-oversized-cache-range".to_owned(),
        },
    ));
    if oversized.status != CommandStatus::Rejected
        || !oversized.violations.iter().any(|violation| violation.contains("byte range exceeds"))
    {
        return Err(format!(
            "block runtime b13 oversized command {} ({}) was not rejected: status={} violations={:?}",
            oversized.command_id,
            oversized.command,
            oversized.status.as_str(),
            oversized.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        271,
        "target-executor-b13",
        SemanticCommand::RecordFileObject {
            file_object: 20_076,
            buffer_cache_object: 20_069,
            buffer_cache_object_generation: 1,
            namespace: "rootfs".to_owned(),
            file_key: "demo-file".to_owned(),
            path: "/demo/file.txt".to_owned(),
            file_offset: 1024,
            byte_len: 1024,
            file_size: 4096,
            content_digest: 0xB13,
            state: FileObjectState::Dirty,
            note: "b13-reject-overlapping-file-range".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("range already materialized"))
    {
        return Err(format!(
            "block runtime b13 duplicate command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b14_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let directory = semantic.apply_envelope(CommandEnvelope::new(
        272,
        "target-executor-b14",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 20_077,
            file_object: 20_073,
            file_object_generation: 1,
            namespace: "rootfs".to_owned(),
            directory_key: "demo-dir".to_owned(),
            directory_path: "/demo".to_owned(),
            entry_name: "file.txt".to_owned(),
            child_file_key: "demo-file".to_owned(),
            child_path: "/demo/file.txt".to_owned(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Cached,
            note: "b14-record-directory-entry-for-file-object".to_owned(),
        },
    ));
    if directory.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b14 directory object command {} ({}) failed: status={} violations={:?}",
            directory.command_id,
            directory.command,
            directory.status.as_str(),
            directory.violations
        )
        .into());
    }

    let stale_file = semantic.apply_envelope(CommandEnvelope::new(
        273,
        "target-executor-b14",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 20_078,
            file_object: 20_073,
            file_object_generation: 2,
            namespace: "rootfs".to_owned(),
            directory_key: "demo-dir".to_owned(),
            directory_path: "/demo".to_owned(),
            entry_name: "stale.txt".to_owned(),
            child_file_key: "demo-file".to_owned(),
            child_path: "/demo/file.txt".to_owned(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Cached,
            note: "b14-reject-stale-file-object-generation".to_owned(),
        },
    ));
    if stale_file.status != CommandStatus::Rejected
        || !stale_file.violations.iter().any(|violation| violation.contains("file generation"))
    {
        return Err(format!(
            "block runtime b14 stale file command {} ({}) was not rejected: status={} violations={:?}",
            stale_file.command_id,
            stale_file.command,
            stale_file.status.as_str(),
            stale_file.violations
        )
        .into());
    }

    let mismatch = semantic.apply_envelope(CommandEnvelope::new(
        274,
        "target-executor-b14",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 20_079,
            file_object: 20_073,
            file_object_generation: 1,
            namespace: "rootfs".to_owned(),
            directory_key: "demo-dir".to_owned(),
            directory_path: "/demo".to_owned(),
            entry_name: "wrong.txt".to_owned(),
            child_file_key: "demo-file".to_owned(),
            child_path: "/demo/wrong.txt".to_owned(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Cached,
            note: "b14-reject-directory-file-identity-mismatch".to_owned(),
        },
    ));
    if mismatch.status != CommandStatus::Rejected
        || !mismatch.violations.iter().any(|violation| violation.contains("file identity mismatch"))
    {
        return Err(format!(
            "block runtime b14 mismatch command {} ({}) was not rejected: status={} violations={:?}",
            mismatch.command_id,
            mismatch.command,
            mismatch.status.as_str(),
            mismatch.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        275,
        "target-executor-b14",
        SemanticCommand::RecordDirectoryObject {
            directory_object: 20_080,
            file_object: 20_073,
            file_object_generation: 1,
            namespace: "rootfs".to_owned(),
            directory_key: "demo-dir".to_owned(),
            directory_path: "/demo".to_owned(),
            entry_name: "file.txt".to_owned(),
            child_file_key: "demo-file".to_owned(),
            child_path: "/demo/file.txt".to_owned(),
            entry_kind: DirectoryEntryKind::File,
            file_size: 4096,
            content_digest: 0xB13,
            state: DirectoryObjectState::Cached,
            note: "b14-reject-duplicate-directory-entry".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("entry already materialized"))
    {
        return Err(format!(
            "block runtime b14 duplicate command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b15_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let payload = b"visa fat adapter read write payload";
    let evidence = build_fat_read_write_evidence(FatAdapterConfig::default_visa(), payload)
        .map_err(|error| format!("block runtime b15 fat adapter evidence failed: {error}"))?;

    let adapter = semantic.apply_envelope(CommandEnvelope::new(
        276,
        "target-executor-b15",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 20_081,
            directory_object: 20_077,
            directory_object_generation: 1,
            file_object: 20_073,
            file_object_generation: 1,
            block_device: 20_002,
            block_device_generation: 1,
            implementation: evidence.implementation.to_owned(),
            version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            volume_label: evidence.volume_label.to_owned(),
            image_bytes: evidence.image_bytes as u64,
            adapter_path: evidence.file_path.to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_written: evidence.bytes_written,
            bytes_read: evidence.bytes_read,
            write_digest: evidence.write_digest,
            read_digest: evidence.read_digest,
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Verified,
            note: "b15-verify-fatfs-read-write-adapter".to_owned(),
        },
    ));
    if adapter.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b15 fat adapter command {} ({}) failed: status={} violations={:?}",
            adapter.command_id,
            adapter.command,
            adapter.status.as_str(),
            adapter.violations
        )
        .into());
    }

    let stale_directory = semantic.apply_envelope(CommandEnvelope::new(
        277,
        "target-executor-b15",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 20_082,
            directory_object: 20_077,
            directory_object_generation: 2,
            file_object: 20_073,
            file_object_generation: 1,
            block_device: 20_002,
            block_device_generation: 1,
            implementation: evidence.implementation.to_owned(),
            version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            volume_label: evidence.volume_label.to_owned(),
            image_bytes: evidence.image_bytes as u64,
            adapter_path: evidence.file_path.to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_written: evidence.bytes_written,
            bytes_read: evidence.bytes_read,
            write_digest: evidence.write_digest,
            read_digest: evidence.read_digest,
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Verified,
            note: "b15-reject-stale-directory-generation".to_owned(),
        },
    ));
    if stale_directory.status != CommandStatus::Rejected
        || !stale_directory
            .violations
            .iter()
            .any(|violation| violation.contains("directory generation"))
    {
        return Err(format!(
            "block runtime b15 stale directory command {} ({}) was not rejected: status={} violations={:?}",
            stale_directory.command_id,
            stale_directory.command,
            stale_directory.status.as_str(),
            stale_directory.violations
        )
        .into());
    }

    let digest_mismatch = semantic.apply_envelope(CommandEnvelope::new(
        278,
        "target-executor-b15",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 20_083,
            directory_object: 20_077,
            directory_object_generation: 1,
            file_object: 20_073,
            file_object_generation: 1,
            block_device: 20_002,
            block_device_generation: 1,
            implementation: evidence.implementation.to_owned(),
            version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            volume_label: evidence.volume_label.to_owned(),
            image_bytes: evidence.image_bytes as u64,
            adapter_path: "BROKEN.TXT".to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_written: evidence.bytes_written,
            bytes_read: evidence.bytes_read,
            write_digest: evidence.write_digest,
            read_digest: evidence.read_digest.wrapping_add(1),
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Verified,
            note: "b15-reject-read-write-digest-mismatch".to_owned(),
        },
    ));
    if digest_mismatch.status != CommandStatus::Rejected
        || !digest_mismatch
            .violations
            .iter()
            .any(|violation| violation.contains("roundtrip mismatch"))
    {
        return Err(format!(
            "block runtime b15 digest mismatch command {} ({}) was not rejected: status={} violations={:?}",
            digest_mismatch.command_id,
            digest_mismatch.command,
            digest_mismatch.status.as_str(),
            digest_mismatch.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        279,
        "target-executor-b15",
        SemanticCommand::RecordFatAdapterObject {
            fat_adapter_object: 20_084,
            directory_object: 20_077,
            directory_object_generation: 1,
            file_object: 20_073,
            file_object_generation: 1,
            block_device: 20_002,
            block_device_generation: 1,
            implementation: evidence.implementation.to_owned(),
            version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            volume_label: evidence.volume_label.to_owned(),
            image_bytes: evidence.image_bytes as u64,
            adapter_path: evidence.file_path.to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_written: evidence.bytes_written,
            bytes_read: evidence.bytes_read,
            write_digest: evidence.write_digest,
            read_digest: evidence.read_digest,
            file_content_digest: 0xB13,
            state: FatAdapterObjectState::Verified,
            note: "b15-reject-duplicate-fat-adapter-binding".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("binding already verified"))
    {
        return Err(format!(
            "block runtime b15 duplicate command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    Ok(())
}

pub(crate) fn record_block_runtime_b16_evidence(
    semantic: &mut SemanticGraph,
) -> Result<(), Box<dyn Error>> {
    let payload = b"visa ext4 adapter read only payload";
    let evidence = build_ext4_read_only_evidence(Ext4AdapterConfig::default_visa(), payload)
        .map_err(|error| format!("block runtime b16 ext4 adapter evidence failed: {error}"))?;

    let adapter = semantic.apply_envelope(CommandEnvelope::new(
        280,
        "target-executor-b16",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 20_085,
            directory_object: 20_077,
            directory_object_generation: 1,
            file_object: 20_073,
            file_object_generation: 1,
            block_device: 20_002,
            block_device_generation: 1,
            implementation: evidence.implementation.to_owned(),
            version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            volume_label: evidence.volume_label.to_owned(),
            image_bytes: evidence.image_bytes as u64,
            adapter_path: evidence.file_path.to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_read: evidence.bytes_read,
            read_digest: evidence.read_digest,
            file_content_digest: 0xB13,
            directory_entries: evidence.directory_entries,
            read_only_enforced: evidence.read_only_enforced,
            state: Ext4AdapterObjectState::Verified,
            note: "b16-verify-ext4-read-only-adapter".to_owned(),
        },
    ));
    if adapter.status != CommandStatus::Applied {
        return Err(format!(
            "block runtime b16 ext4 adapter command {} ({}) failed: status={} violations={:?}",
            adapter.command_id,
            adapter.command,
            adapter.status.as_str(),
            adapter.violations
        )
        .into());
    }

    let stale_directory = semantic.apply_envelope(CommandEnvelope::new(
        281,
        "target-executor-b16",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 20_086,
            directory_object: 20_077,
            directory_object_generation: 2,
            file_object: 20_073,
            file_object_generation: 1,
            block_device: 20_002,
            block_device_generation: 1,
            implementation: evidence.implementation.to_owned(),
            version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            volume_label: evidence.volume_label.to_owned(),
            image_bytes: evidence.image_bytes as u64,
            adapter_path: evidence.file_path.to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_read: evidence.bytes_read,
            read_digest: evidence.read_digest,
            file_content_digest: 0xB13,
            directory_entries: evidence.directory_entries,
            read_only_enforced: evidence.read_only_enforced,
            state: Ext4AdapterObjectState::Verified,
            note: "b16-reject-stale-directory-generation".to_owned(),
        },
    ));
    if stale_directory.status != CommandStatus::Rejected
        || !stale_directory
            .violations
            .iter()
            .any(|violation| violation.contains("directory generation"))
    {
        return Err(format!(
            "block runtime b16 stale directory command {} ({}) was not rejected: status={} violations={:?}",
            stale_directory.command_id,
            stale_directory.command,
            stale_directory.status.as_str(),
            stale_directory.violations
        )
        .into());
    }

    let not_read_only = semantic.apply_envelope(CommandEnvelope::new(
        282,
        "target-executor-b16",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 20_087,
            directory_object: 20_077,
            directory_object_generation: 1,
            file_object: 20_073,
            file_object_generation: 1,
            block_device: 20_002,
            block_device_generation: 1,
            implementation: evidence.implementation.to_owned(),
            version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            volume_label: evidence.volume_label.to_owned(),
            image_bytes: evidence.image_bytes as u64,
            adapter_path: "/demo-rw.txt".to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_read: evidence.bytes_read,
            read_digest: evidence.read_digest,
            file_content_digest: 0xB13,
            directory_entries: evidence.directory_entries,
            read_only_enforced: false,
            state: Ext4AdapterObjectState::Verified,
            note: "b16-reject-non-read-only-adapter".to_owned(),
        },
    ));
    if not_read_only.status != CommandStatus::Rejected
        || !not_read_only
            .violations
            .iter()
            .any(|violation| violation.contains("read-only evidence"))
    {
        return Err(format!(
            "block runtime b16 read-only command {} ({}) was not rejected: status={} violations={:?}",
            not_read_only.command_id,
            not_read_only.command,
            not_read_only.status.as_str(),
            not_read_only.violations
        )
        .into());
    }

    let duplicate = semantic.apply_envelope(CommandEnvelope::new(
        283,
        "target-executor-b16",
        SemanticCommand::RecordExt4AdapterObject {
            ext4_adapter_object: 20_088,
            directory_object: 20_077,
            directory_object_generation: 1,
            file_object: 20_073,
            file_object_generation: 1,
            block_device: 20_002,
            block_device_generation: 1,
            implementation: evidence.implementation.to_owned(),
            version: evidence.version.to_owned(),
            profile: evidence.profile.to_owned(),
            volume_label: evidence.volume_label.to_owned(),
            image_bytes: evidence.image_bytes as u64,
            adapter_path: evidence.file_path.to_owned(),
            semantic_path: "/demo/file.txt".to_owned(),
            bytes_read: evidence.bytes_read,
            read_digest: evidence.read_digest,
            file_content_digest: 0xB13,
            directory_entries: evidence.directory_entries,
            read_only_enforced: evidence.read_only_enforced,
            state: Ext4AdapterObjectState::Verified,
            note: "b16-reject-duplicate-ext4-adapter-binding".to_owned(),
        },
    ));
    if duplicate.status != CommandStatus::Rejected
        || !duplicate
            .violations
            .iter()
            .any(|violation| violation.contains("binding already verified"))
    {
        return Err(format!(
            "block runtime b16 duplicate command {} ({}) was not rejected: status={} violations={:?}",
            duplicate.command_id,
            duplicate.command,
            duplicate.status.as_str(),
            duplicate.violations
        )
        .into());
    }

    Ok(())
}
