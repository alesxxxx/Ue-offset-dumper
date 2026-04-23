import logging
from typing import Callable, Optional, Dict, List

from src.core.memory import read_u64, read_u32, read_u16, read_u8, read_string

logger = logging.getLogger(__name__)

class CUtlTSHashParser:
    def __init__(self, handle: int, address: int):
        self.handle = handle
        self.address = address
        
        # CUtlTSHash layout generally used in CS2:
        # We have 256 list elements (buckets)
        # 0x00: struct { m_pFirst, m_pFirstUncommited, m_uiAllocationCount, m_uiGrowSize, m_uiBlockSize, ... }
        
        # According to a2x/cs2-dumper utl_ts_hash.rs:
        # UtlTsHash<T, 256> has:
        # pub buckets: UtlMemoryPool;  (at 0x0 offset)
        
        # UtlMemoryPool layout:
        # pub start_offset: i32
        # pub bytes_per_blob: i32
        # pub blob_count: i32
        # pub peak_alloc: i32
        # pub unallocated_size: i32
        # pub base: Pointer64<[u8]>
        
        # In actual memory terms for CS2 UtlTsHash struct:
        # +0x0: unallocated_data (int)
        # +0x4: allocation_count (int)
        # +0x8: peak_allocation_count (int)
        # +0xC: block_size (int)
        # +0x10: pBlocks (Pointer64)
        pass

    def iter_elements(self, block_size: int = 0x10) -> List[int]:
        # Implementation via memory pool 
        elements = []
        
        pool_unallocated_data = read_u32(self.handle, self.address + 0x0)
        pool_allocation_count = read_u32(self.handle, self.address + 0x4)
        pool_peak_alloc = read_u32(self.handle, self.address + 0x8)
        pool_pBlocks = read_u64(self.handle, self.address + 0x10)
        
        if not pool_pBlocks or pool_allocation_count == 0:
            return elements

        block_ptr = pool_pBlocks
        while block_ptr:
            # HashFixedData_t pointers actually contain the array of unallocated elements
            # The actual allocated elements are in the array directly up to uiBlockSize
            
            # The elements start directly at block_ptr + 0x10 (some arrays have offset to elements)
            # Actually, per memflow / source2 reversed structs:
            # class UtlTsHash:
            # 0x0 unallocated_data : i32
            # 0x4 allocation_count : i32
            # 0x8 peak_allocation_count : i32
            # 0xC block_size : i32
            # 0x10 pBlocks (ptr)
            
            # CUtlMemoryPool / HashAllocatedBlob_t:
            # pBlocks -> Blob
            # Blob:
            # 0x0 pNext (ptr)
            # 0x8 data (array)
            data_ptr = block_ptr + 0x10 # The start of the blob data

            for i in range(self.m_uiBlockSize):
                # Each element sizes:
                # 0x0 uiKey (u64)
                # 0x8 pNext (ptr)
                # 0x10 Data (ptr)
                
                element_addr = data_ptr + (i * 0x18) 
                # ^ Assuming 0x18 stride. However, 0x20 is common. We'll read the data ptr anyway:
                uiKey = read_u64(self.handle, element_addr)
                # Next element ptr is used for collision. If we read the blob arrays, we don't need to walk pNext for the same bucket.
                
                # Check active
                obj_ptr = read_u64(self.handle, element_addr + 0x10)
                if obj_ptr:
                    elements.append(obj_ptr)
            
            block_ptr = read_u64(self.handle, block_ptr + 0x0) # pNext
        
        return elements

def get_type_scope_classes(handle: int, type_scope_ptr: int) -> List[int]:
    """Extract SchemaClassInfoData pointers from CSchemaSystemTypeScope."""
    # class_bindings: UtlTsHash<SchemaClassBinding> -> 0x560
    hash_parser = CUtlTSHashParser(handle, type_scope_ptr + 0x560)
    return hash_parser.iter_elements()
