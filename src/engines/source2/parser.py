import logging
from typing import Callable, Optional, Dict, List

from src.core.memory import read_uint64, read_uint32, read_uint16, read_bytes, read_string

def _read_u8(handle: int, addr: int) -> int:
    data = read_bytes(handle, addr, 1)
    return data[0] if data else 0

logger = logging.getLogger(__name__)

class CUtlTSHashParser:
    def __init__(self, handle: int, address: int):
        self.handle = handle
        self.address = address
        
        # CUtlMemoryPool layout (at the start of CUtlTSHash):
        # +0x0: unallocated_data (int)
        # +0x4: allocation_count (int)
        # +0x8: peak_allocation_count (int)
        # +0xC: block_size (int)
        # +0x10: pBlocks (Pointer64)
        self.m_uiBlockSize = read_uint32(handle, address + 0xC)

    def iter_elements(self, block_size: int = 0x10) -> List[int]:
        # Implementation via memory pool 
        elements = []
        
        pool_unallocated_data = read_uint32(self.handle, self.address + 0x0)
        pool_allocation_count = read_uint32(self.handle, self.address + 0x4)
        pool_peak_alloc = read_uint32(self.handle, self.address + 0x8)
        pool_pBlocks = read_uint64(self.handle, self.address + 0x10)
        
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
                uiKey = read_uint64(self.handle, element_addr)
                # Next element ptr is used for collision. If we read the blob arrays, we don't need to walk pNext for the same bucket.
                
                # Check active
                obj_ptr = read_uint64(self.handle, element_addr + 0x10)
                if obj_ptr:
                    elements.append(obj_ptr)
            
            block_ptr = read_uint64(self.handle, block_ptr + 0x0) # pNext
        
        return elements

def get_type_scope_classes(handle: int, type_scope_ptr: int) -> List[int]:
    """Extract SchemaClassInfoData pointers from CSchemaSystemTypeScope."""
    # class_bindings: UtlTsHash<SchemaClassBinding> -> 0x560
    hash_parser = CUtlTSHashParser(handle, type_scope_ptr + 0x560)
    return hash_parser.iter_elements()
