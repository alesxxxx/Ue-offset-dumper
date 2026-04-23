import logging
from typing import Callable, Optional, Dict

from src.core.memory import read_u64, read_u32, read_string, read_u16, read_u8, get_module_info, get_pid_by_name
from src.core.models import SDKDump, StructInfo, MemberInfo
from src.engines.source2.parser import get_type_scope_classes

logger = logging.getLogger(__name__)

def dump_source2(
    handle: int,
    process_name: str,
    progress_callback: Optional[Callable[[str], None]] = None,
    log_fn: Optional[Callable[[str], None]] = None,
) -> SDKDump:

    def _log(msg: str) -> None:
        logger.info(msg)
        if log_fn:
            log_fn(msg)

    pid = get_pid_by_name(process_name)
    if not pid:
        raise RuntimeError(f"Process {process_name!r} not found")

    _log(f"[Source2] Dumping CS2 Schemas...")

    # For Source 2, the schema system is in schemasystem.dll
    schema_base, schema_size = get_module_info(pid, "schemasystem.dll")
    if not schema_base:
        raise RuntimeError(f"Could not find schemasystem.dll in {process_name}")

    if progress_callback:
        progress_callback("Scanning schemasystem.dll for CSchemaSystem...")

    # Pattern scan for CSchemaSystem
    from src.engines.source2.signatures import find_schema_system_ptr
    schema_sys_ptr = find_schema_system_ptr(handle, schema_base, schema_size)
    
    if not schema_sys_ptr:
        raise RuntimeError("Could not find CSchemaSystem pointer.")

    schema_sys = read_u64(handle, schema_sys_ptr)
    if not schema_sys:
        raise RuntimeError("Could not dereference CSchemaSystem.")

    _log(f"[Source2] CSchemaSystem: 0x{schema_sys:X}")

    if progress_callback:
        progress_callback("Reading Schema System Scopes...")

    # SchemaSystemTypeScopes are at +0x190 in CSchemaSystem 
    # CUtlVector type_scopes
    scopes_size = read_u32(handle, schema_sys + 0x190 + 0x10) # m_Size
    scopes_data = read_u64(handle, schema_sys + 0x190 + 0x0)  # m_Memory
    
    if scopes_size == 0 or not scopes_data:
        raise RuntimeError("No type scopes found in schema system.")

    _log(f"[Source2] Found {scopes_size} type scopes")

    structs = []
    total_props = 0

    for i in range(scopes_size):
        # Array of pointers to CSchemaSystemTypeScope
        scope_ptr = read_u64(handle, scopes_data + (i * 8))
        if not scope_ptr:
            continue
            
        scope_name_ptr = scope_ptr + 0x8 
        scope_name = read_string(handle, scope_name_ptr, size=256)
        
        # Only dump client.dll types for this typical dumper
        if scope_name != "client.dll":
            continue
            
        _log(f"  -> Found scope: {scope_name}")
        
        classes_ptrs = get_type_scope_classes(handle, scope_ptr)
        _log(f"     => Found {len(classes_ptrs)} classes in scope")
        
        for class_ptr in classes_ptrs:
            # Parse SchemaClassInfoData
            class_name_ptr = read_u64(handle, class_ptr + 0x8)
            class_name = read_string(handle, class_name_ptr)
            
            # base class
            base_class_ptr = read_u64(handle, class_ptr + 0x40)
            base_class_name = ""
            if base_class_ptr:
                b_info = read_u64(handle, base_class_ptr + 0x8) # ptr to SchemaClassInfoData
                if b_info:
                    b_name_ptr = read_u64(handle, b_info + 0x8)
                    base_class_name = read_string(handle, b_name_ptr)

            fields_count = read_u16(handle, class_ptr + 0x24)
            fields_ptr = read_u64(handle, class_ptr + 0x30)
            
            members = []
            for f in range(fields_count):
                # SchemaClassFieldData_t size is 0x20
                f_addr = fields_ptr + (f * 0x20)
                
                f_name_ptr = read_u64(handle, f_addr + 0x0)
                f_name = read_string(handle, f_name_ptr)
                
                schema_type_ptr = read_u64(handle, f_addr + 0x8)
                type_name = "Unknown"
                if schema_type_ptr:
                    # SchemaType_t : name is at +0x8
                    t_name_ptr = read_u64(handle, schema_type_ptr + 0x8)
                    type_name = read_string(handle, t_name_ptr)
                    
                offset = read_u32(handle, f_addr + 0x10)
                
                members.append(
                    MemberInfo(
                        name=f_name,
                        offset=offset,
                        size=0, # not provided easily in schema type, it's complex
                        type_name=type_name,
                        array_dim=1,
                        flags=0,
                        metadata={}
                    )
                )
                total_props += 1
                
            structs.append(
                StructInfo(
                    name=class_name,
                    full_name=f"Source2.{scope_name}.{class_name}",
                    address=0,
                    size=read_u32(handle, class_ptr + 0x20),
                    super_name=base_class_name,
                    is_class=True,
                    package=scope_name,
                    members=members,
                    metadata={}
                )
            )

    _log(f"[Source2] Walk complete. {len(structs)} structs, {total_props} properties.")
    
    if progress_callback:
        progress_callback(f"Walk complete. {len(structs)} structs, {total_props} properties.")

    return SDKDump(
        structs=structs,
        metadata={}
    )
