use alloc::{vec, vec::Vec};

use substrate_api::{PageTableAuthority, SubstrateError, SubstrateResult};

pub const PAGE_TABLE_BACKEND_PROVIDER: &str = "substrate_virtio";
pub const PAGE_TABLE_BACKEND_PROFILE: &str = "in-memory-page-table-backend-v1";
pub const PAGE_TABLE_BACKEND_MODEL: &str = "page-table";
pub const PAGE_SIZE: usize = 4096;
const DEFAULT_FRAME_BASE: u64 = 0x10_0000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageFrameRecord {
    pub phys: u64,
    bytes: Vec<u8>,
}

impl PageFrameRecord {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageMappingRecord {
    pub va: u64,
    pub phys: u64,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageTableBackendEvidence {
    pub provider: &'static str,
    pub profile: &'static str,
    pub model: &'static str,
    pub frame_count: usize,
    pub mapping_count: usize,
    pub tlb_flush_count: usize,
}

pub struct InMemoryPageTableBackend {
    next_phys: u64,
    frames: Vec<PageFrameRecord>,
    mappings: Vec<PageMappingRecord>,
    tlb_flushes: Vec<u64>,
}

impl InMemoryPageTableBackend {
    pub const fn new() -> Self {
        Self {
            next_phys: DEFAULT_FRAME_BASE,
            frames: Vec::new(),
            mappings: Vec::new(),
            tlb_flushes: Vec::new(),
        }
    }

    pub fn evidence(&self) -> PageTableBackendEvidence {
        PageTableBackendEvidence {
            provider: PAGE_TABLE_BACKEND_PROVIDER,
            profile: PAGE_TABLE_BACKEND_PROFILE,
            model: PAGE_TABLE_BACKEND_MODEL,
            frame_count: self.frames.len(),
            mapping_count: self.mappings.len(),
            tlb_flush_count: self.tlb_flushes.len(),
        }
    }

    pub fn frame(&self, phys: u64) -> Option<&PageFrameRecord> {
        self.frames.iter().find(|frame| frame.phys == phys)
    }

    pub fn frame_mut(&mut self, phys: u64) -> Option<&mut PageFrameRecord> {
        self.frames.iter_mut().find(|frame| frame.phys == phys)
    }

    pub fn mapping(&self, va: u64) -> Option<PageMappingRecord> {
        self.mappings.iter().copied().find(|mapping| mapping.va == va)
    }

    pub fn tlb_flushes(&self) -> &[u64] {
        &self.tlb_flushes
    }

    fn frame_index(&self, phys: u64) -> Option<usize> {
        self.frames.iter().position(|frame| frame.phys == phys)
    }

    fn mapping_index(&self, va: u64) -> Option<usize> {
        self.mappings.iter().position(|mapping| mapping.va == va)
    }
}

impl Default for InMemoryPageTableBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl PageTableAuthority for InMemoryPageTableBackend {
    fn alloc_frame(&mut self) -> SubstrateResult<u64> {
        let phys = self.next_phys;
        self.next_phys = self.next_phys.checked_add(PAGE_SIZE as u64).ok_or(
            SubstrateError::ContractViolation { detail: "page frame physical address overflow" },
        )?;
        self.frames.push(PageFrameRecord { phys, bytes: vec![0; PAGE_SIZE] });
        Ok(phys)
    }

    fn map_page(
        &mut self,
        va: u64,
        phys: u64,
        writable: bool,
        executable: bool,
    ) -> SubstrateResult<()> {
        validate_page_aligned(va, "page")?;
        validate_page_aligned(phys, "page-frame")?;
        if self.frame_index(phys).is_none() {
            return Err(SubstrateError::InvalidObject { object: "page-frame" });
        }
        if self.mapping_index(va).is_some() {
            return Err(SubstrateError::ContractViolation {
                detail: "virtual page already mapped",
            });
        }
        self.mappings.push(PageMappingRecord { va, phys, writable, executable });
        Ok(())
    }

    fn unmap_page(&mut self, va: u64) -> SubstrateResult<()> {
        validate_page_aligned(va, "page")?;
        let Some(index) = self.mapping_index(va) else {
            return Err(SubstrateError::InvalidObject { object: "page-mapping" });
        };
        self.mappings.remove(index);
        Ok(())
    }

    fn protect_page(&mut self, va: u64, writable: bool, executable: bool) -> SubstrateResult<()> {
        validate_page_aligned(va, "page")?;
        let Some(index) = self.mapping_index(va) else {
            return Err(SubstrateError::InvalidObject { object: "page-mapping" });
        };
        self.mappings[index].writable = writable;
        self.mappings[index].executable = executable;
        Ok(())
    }

    fn copy_frame(&mut self, src_phys: u64, dst_phys: u64, len: usize) -> SubstrateResult<()> {
        validate_page_aligned(src_phys, "page-frame")?;
        validate_page_aligned(dst_phys, "page-frame")?;
        if len > PAGE_SIZE {
            return Err(SubstrateError::ContractViolation {
                detail: "page frame copy exceeds frame size",
            });
        }
        let Some(src_index) = self.frame_index(src_phys) else {
            return Err(SubstrateError::InvalidObject { object: "source-page-frame" });
        };
        let Some(dst_index) = self.frame_index(dst_phys) else {
            return Err(SubstrateError::InvalidObject { object: "destination-page-frame" });
        };
        if src_index == dst_index || len == 0 {
            return Ok(());
        }
        let copy = self.frames[src_index].bytes[..len].to_vec();
        self.frames[dst_index].bytes[..len].copy_from_slice(&copy);
        Ok(())
    }

    fn flush_tlb(&mut self, va: u64) -> SubstrateResult<()> {
        validate_page_aligned(va, "page")?;
        if self.mapping_index(va).is_none() {
            return Err(SubstrateError::InvalidObject { object: "page-mapping" });
        }
        self.tlb_flushes.push(va);
        Ok(())
    }
}

fn validate_page_aligned(value: u64, object: &'static str) -> SubstrateResult<()> {
    if value == 0 || value % PAGE_SIZE as u64 != 0 {
        Err(SubstrateError::InvalidObject { object })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use substrate_api::{
        PageTableAuthority,
        conformance::{ConformanceFixtures, page_table_map_protect_copy_unmap_smoke},
    };

    use super::*;

    #[test]
    fn page_table_backend_passes_substrate_api_smoke() {
        let mut backend = InMemoryPageTableBackend::default();
        let fixtures = ConformanceFixtures::default();

        page_table_map_protect_copy_unmap_smoke(&mut backend, &fixtures).unwrap();

        assert_eq!(backend.mapping(fixtures.page_va), None);
        assert_eq!(backend.tlb_flushes(), &[fixtures.page_va]);
        let evidence = backend.evidence();
        assert_eq!(evidence.provider, PAGE_TABLE_BACKEND_PROVIDER);
        assert_eq!(evidence.profile, PAGE_TABLE_BACKEND_PROFILE);
        assert_eq!(evidence.frame_count, 2);
        assert_eq!(evidence.mapping_count, 0);
        assert_eq!(evidence.tlb_flush_count, 1);
    }

    #[test]
    fn page_table_backend_copies_frame_bytes() {
        let mut backend = InMemoryPageTableBackend::default();
        let src = backend.alloc_frame().unwrap();
        let dst = backend.alloc_frame().unwrap();
        backend.frame_mut(src).unwrap().bytes_mut()[..4].copy_from_slice(b"VMOS");

        backend.copy_frame(src, dst, 4).unwrap();

        assert_eq!(&backend.frame(dst).unwrap().bytes()[..4], b"VMOS");
    }

    #[test]
    fn page_table_backend_rejects_invalid_operations() {
        let mut backend = InMemoryPageTableBackend::default();
        let frame = backend.alloc_frame().unwrap();
        assert_eq!(
            backend.map_page(1, frame, true, false),
            Err(SubstrateError::InvalidObject { object: "page" })
        );
        assert_eq!(
            backend.map_page(0x4000, 0x20_0000, true, false),
            Err(SubstrateError::InvalidObject { object: "page-frame" })
        );

        backend.map_page(0x4000, frame, true, false).unwrap();
        assert_eq!(
            backend.map_page(0x4000, frame, true, false),
            Err(SubstrateError::ContractViolation { detail: "virtual page already mapped" })
        );
        assert_eq!(
            backend.flush_tlb(0x8000),
            Err(SubstrateError::InvalidObject { object: "page-mapping" })
        );
        assert_eq!(
            backend.copy_frame(frame, frame, PAGE_SIZE + 1),
            Err(SubstrateError::ContractViolation { detail: "page frame copy exceeds frame size" })
        );
    }
}
