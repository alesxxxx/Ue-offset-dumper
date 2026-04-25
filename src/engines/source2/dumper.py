import logging
from typing import Callable, Optional, Dict

from src.core.memory import read_uint64, read_uint32, read_string, read_uint16, read_bytes, get_module_info, get_pid_by_name
from src.core.models import SDKDump, StructInfo, MemberInfo
from src.engines.source2.parser import get_type_scope_classes

logger = logging.getLogger(__name__)

_MAX_SCHEMA_CLASS_NAME_LEN = 128
_MAX_SCHEMA_TYPE_NAME_LEN = 256
_MAX_REASONABLE_CLASS_SIZE = 1024 * 1024
_MAX_REASONABLE_CLASS_FIELDS = 512


def _is_reasonable_schema_text(value: str, *, max_len: int) -> bool:
    if not value or len(value) > max_len:
        return False
    return all(0x20 <= ord(ch) <= 0x7E for ch in value)

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
    schema_sys = find_schema_system_ptr(handle, schema_base, schema_size)
    
    if not schema_sys:
        raise RuntimeError("Could not find CSchemaSystem pattern in schemasystem.dll.")

    # Sanity check: the primary pattern (lea) resolves directly to the struct.
    # If the address looks like a valid pointer (very high value), it might be the
    # struct itself. If the first qword at the address looks like another pointer,
    # we may need to dereference. We try reading the type_scopes count at +0x1A0
    # to validate which interpretation is correct.
    test_count = read_uint32(handle, schema_sys + 0x190 + 0x10)
    if test_count == 0 or test_count > 256:
        # Maybe we got a pointer TO the struct, not the struct itself — dereference
        deref = read_uint64(handle, schema_sys)
        if deref:
            test2 = read_uint32(handle, deref + 0x190 + 0x10)
            if 0 < test2 <= 256:
                schema_sys = deref
                _log(f"[Source2] CSchemaSystem (dereferenced): 0x{schema_sys:X}")
            else:
                _log(f"[Source2] CSchemaSystem: 0x{schema_sys:X} (direct)")
        else:
            _log(f"[Source2] CSchemaSystem: 0x{schema_sys:X} (direct, unvalidated)")
    else:
        _log(f"[Source2] CSchemaSystem: 0x{schema_sys:X}")

    if progress_callback:
        progress_callback("Reading Schema System Scopes...")

    # SchemaSystemTypeScopes are at +0x190 in CSchemaSystem 
    # UtlVector layout (from a2x/cs2-dumper utl_vector.rs):
    #   0x0000: count  (i32)
    #   0x0004: pad    (4 bytes)
    #   0x0008: data   (Pointer64<[T]>)
    scopes_size = read_uint32(handle, schema_sys + 0x190 + 0x0)  # count
    scopes_data = read_uint64(handle, schema_sys + 0x190 + 0x8)  # data ptr
    
    if scopes_size == 0 or not scopes_data:
        raise RuntimeError("No type scopes found in schema system.")

    _log(f"[Source2] Found {scopes_size} type scopes (data @ 0x{scopes_data:X})")

    structs = []
    total_props = 0
    skipped_invalid_classes = 0
    skipped_invalid_fields = 0

    for i in range(scopes_size):
        # Array of pointers to CSchemaSystemTypeScope
        scope_ptr = read_uint64(handle, scopes_data + (i * 8))
        if not scope_ptr:
            _log(f"  [Scope {i}] null pointer — skipped")
            continue
            
        scope_name_ptr = scope_ptr + 0x8 
        scope_name = read_string(handle, scope_name_ptr, max_len=256)
        
        if not scope_name:
            _log(f"  [Scope {i}] empty name at 0x{scope_ptr:X} — skipped")
            continue
            
        _log(f"  -> Scope: {scope_name}")
        
        classes_ptrs = get_type_scope_classes(handle, scope_ptr)
        _log(f"     => {len(classes_ptrs)} classes")
        
        for class_ptr in classes_ptrs:
            # Parse SchemaClassInfoData
            class_name_ptr = read_uint64(handle, class_ptr + 0x8)
            class_name = read_string(handle, class_name_ptr, max_len=_MAX_SCHEMA_CLASS_NAME_LEN)
            size = read_uint32(handle, class_ptr + 0x20)
            fields_count = read_uint16(handle, class_ptr + 0x24)
            fields_ptr = read_uint64(handle, class_ptr + 0x30)

            if not _is_reasonable_schema_text(class_name, max_len=_MAX_SCHEMA_CLASS_NAME_LEN):
                skipped_invalid_classes += 1
                continue
            if size > _MAX_REASONABLE_CLASS_SIZE:
                skipped_invalid_classes += 1
                continue
            if fields_count > _MAX_REASONABLE_CLASS_FIELDS:
                skipped_invalid_classes += 1
                continue
            if fields_count and not fields_ptr:
                skipped_invalid_classes += 1
                continue
            
            # base class
            base_class_ptr = read_uint64(handle, class_ptr + 0x40)
            base_class_name = ""
            if base_class_ptr:
                b_info = read_uint64(handle, base_class_ptr + 0x8) # ptr to SchemaClassInfoData
                if b_info:
                    b_name_ptr = read_uint64(handle, b_info + 0x8)
                    candidate = read_string(handle, b_name_ptr, max_len=_MAX_SCHEMA_CLASS_NAME_LEN)
                    if _is_reasonable_schema_text(candidate, max_len=_MAX_SCHEMA_CLASS_NAME_LEN):
                        base_class_name = candidate
            
            members = []
            for f in range(fields_count):
                # SchemaClassFieldData_t size is 0x20
                f_addr = fields_ptr + (f * 0x20)
                
                f_name_ptr = read_uint64(handle, f_addr + 0x0)
                f_name = read_string(handle, f_name_ptr, max_len=_MAX_SCHEMA_CLASS_NAME_LEN)
                if not _is_reasonable_schema_text(f_name, max_len=_MAX_SCHEMA_CLASS_NAME_LEN):
                    skipped_invalid_fields += 1
                    continue
                
                schema_type_ptr = read_uint64(handle, f_addr + 0x8)
                type_name = "Unknown"
                if schema_type_ptr:
                    # SchemaType_t : name is at +0x8
                    t_name_ptr = read_uint64(handle, schema_type_ptr + 0x8)
                    candidate = read_string(handle, t_name_ptr, max_len=_MAX_SCHEMA_TYPE_NAME_LEN)
                    if _is_reasonable_schema_text(candidate, max_len=_MAX_SCHEMA_TYPE_NAME_LEN):
                        type_name = candidate
                    
                offset = read_uint32(handle, f_addr + 0x10)
                if size and offset > size + 0x1000:
                    skipped_invalid_fields += 1
                    continue
                
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
                    size=size,
                    super_name=base_class_name,
                    is_class=True,
                    package=scope_name,
                    members=members,
                    metadata={}
                )
            )

    if skipped_invalid_classes:
        _log(f"[Source2] Skipped {skipped_invalid_classes} invalid class bindings.")
    if skipped_invalid_fields:
        _log(f"[Source2] Skipped {skipped_invalid_fields} invalid fields.")
    _log(f"[Source2] Walk complete. {len(structs)} structs, {total_props} properties.")
    
    if progress_callback:
        progress_callback(f"Walk complete. {len(structs)} structs, {total_props} properties.")

    return SDKDump(
        structs=structs,
        metadata={}
    )
