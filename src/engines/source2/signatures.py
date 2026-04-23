import logging
from typing import Optional

from src.core.memory import read_u32, read_u64, read_bytes

logger = logging.getLogger(__name__)

def find_schema_system_ptr(handle: int, module_base: int, module_size: int) -> Optional[int]:
    """Finds the global CSchemaSystem pointer via signature scan."""
    # Common signature for CSchemaSystem in schemasystem.dll (CS2):
    # "\x48\x89\x05\x00\x00\x00\x00\x4c\x8d\x45\x00\x48\x8d\x15\x00\x00\x00\x00\x48\x8d\x4c\x24\x00\xe8\x00\x00\x00\x00\x33\xf6"
    # Actually, a simpler one widely used: "48 89 05 ? ? ? ? 4C 8D 45" inside schemasystem.dll
    
    # We will implement a basic external byte scanner or use the pattern if known.
    # Ue-offset-dumper already has a memory reading function `read_bytes`
    
    chunk_size = 4096 * 256
    
    signature = bytes.fromhex("488905")
    # For performance and simplicity, since schemasystem.dll is small, we read it:
    
    try:
        buffer = read_bytes(handle, module_base, module_size)
    except Exception as e:
        logger.error(f"Failed to read schemasystem.dll memory: {e}")
        return None
        
    offset = 0
    # Signature: 48 89 05 ? ? ? ? 4C 8D 45
    while offset < len(buffer) - 10:
        idx = buffer.find(signature, offset)
        if idx == -1:
            break
            
        if buffer[idx+7] == 0x4C and buffer[idx+8] == 0x8D and buffer[idx+9] == 0x45:
            # We found the instruction: mov cs:SchemaSystem, rax
            # The next 4 bytes are the relative offset
            
            rel_acc = int.from_bytes(buffer[idx+3:idx+7], byteorder='little', signed=True)
            # RIP is instruction address + instruction length (7).
            rip = module_base + idx + 7
            schema_sys_ptr = rip + rel_acc
            return schema_sys_ptr
            
        offset = idx + 1
        
    return None
