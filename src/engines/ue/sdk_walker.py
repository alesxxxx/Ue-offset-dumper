
import logging
import struct
from typing import Dict, List, Optional, Tuple

from src.core.memory import (
    read_bytes,
    read_uint64,
    read_uint32,
    read_int32,
    read_uint16,
    scatter_read_multiple,
)

logger = logging.getLogger(__name__)
from src.core.models import (
    MemberInfo,
    StructInfo,
    EnumInfo,
    SDKDump,
    FunctionInfo,
    FunctionParamInfo,
)
from src.engines.ue.gnames import read_fname
from src.engines.ue.version_matrix import (
    is_pre_425,
    is_pre_423,
    get_ffield_layout,
    get_version_config,
)
from src.engines.ue.gobjects import (
    read_uobject,
    get_object_count,
    get_gobjects_objects_ptr,
    get_object_class_name,
    UOBJECT_CLASS,
    UOBJECT_NAME,
    UOBJECT_OUTER,
    FUOBJECTITEM_SIZE_NORMAL,
    OBJECTS_PER_CHUNK,
)

USTRUCT_SUPER = 0x40
USTRUCT_CHILDREN = 0x48
USTRUCT_CHILD_PROPS = 0x50
USTRUCT_PROPERTIES_SIZE = 0x58
USTRUCT_MIN_ALIGNMENT = 0x5C

USTRUCT_SUPER_LEGACY = 0x30
USTRUCT_CHILDREN_LEGACY = 0x38
USTRUCT_PROPERTIES_SIZE_LEGACY = 0x40
USTRUCT_MIN_ALIGNMENT_LEGACY = 0x44

UPROPERTY_NEXT = 0x28
UPROPERTY_ARRAY_DIM = 0x30
UPROPERTY_ELEMENT_SIZE = 0x34
UPROPERTY_PROPERTY_FLAGS = 0x38
UPROPERTY_REP_INDEX = 0x40
UPROPERTY_OFFSET_INTERNAL = 0x44

FFIELD_CLASS_PRIVATE = 0x08
FFIELD_NEXT = 0x20
FFIELD_NAME = 0x28

FPROPERTY_ARRAY_DIM = 0x38
FPROPERTY_ELEMENT_SIZE = 0x3C
FPROPERTY_FLAGS = 0x40
FPROPERTY_OFFSET = 0x4C

FFIELDCLASS_NAME = 0x00

_ffield_class_name_cache: dict = {}

_uobject_name_cache: dict = {}

_super_chain_cache: dict = {}

UENUM_NAMES_OFFSET = 0x40
_UENUM_NAMES_PROBE_OFFSETS = (0x40, 0x48, 0x50)

_UFUNCTION_FLAGS_PROBE_OFFSETS = (0x88, 0x80, 0x78, 0x70, 0x68, 0x90, 0xA0, 0xB0)

_ufunction_flags_offset_cache: Dict[str, int] = {}

def _plausible_uobject_class_ptr(value: int) -> bool:
    return 0x1000000 < value < 0x7FFFFFFFFFFF

def _plausible_runtime_ptr(value: int, floor: int = 0x10000) -> bool:
    return floor <= value < 0x7FFFFFFFFFFF

def _pointer_floor_from_chunks(chunk_ptrs: List[int]) -> int:
    vals = [p for p in chunk_ptrs if p and p >= 0x10000]
    if not vals:
        return 0x10000
    return max(0x10000, min(vals) - 0x4000000000)

def _is_pre_425_ue(ue_version: str) -> bool:
    return is_pre_425(ue_version)

def _is_pre_423_ue(ue_version: str) -> bool:
    return is_pre_423(ue_version)

def get_ffield_offsets(ue_version: str = "4.27") -> dict:
    layout = get_ffield_layout(ue_version)
    logger.debug(
        "get_ffield_offsets: ue_version=%r layout=%r (from version_matrix)",
        ue_version,
        layout,
    )

    if layout == "ue52plus":
        return {
            "FFIELD_CLASS_PRIVATE": 0x08,
            "FFIELD_NEXT": 0x18,
            "FFIELD_NAME": 0x20,
            "FPROPERTY_ARRAY_DIM": 0x30,
            "FPROPERTY_ELEMENT_SIZE": 0x34,
            "FPROPERTY_FLAGS": 0x38,
            "FPROPERTY_OFFSET": 0x44,
            "FFIELDCLASS_NAME": 0x00,
            "UENUM_NAMES_OFFSET": UENUM_NAMES_OFFSET,
        }
    else:
        return {
            "FFIELD_CLASS_PRIVATE": FFIELD_CLASS_PRIVATE,
            "FFIELD_NEXT": FFIELD_NEXT,
            "FFIELD_NAME": FFIELD_NAME,
            "FPROPERTY_ARRAY_DIM": FPROPERTY_ARRAY_DIM,
            "FPROPERTY_ELEMENT_SIZE": FPROPERTY_ELEMENT_SIZE,
            "FPROPERTY_FLAGS": FPROPERTY_FLAGS,
            "FPROPERTY_OFFSET": FPROPERTY_OFFSET,
            "FFIELDCLASS_NAME": FFIELDCLASS_NAME,
            "UENUM_NAMES_OFFSET": UENUM_NAMES_OFFSET,
        }

def _scatter_walk_ffield_chains(
    struct_ptrs: list,
    handle: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    offsets: dict,
    legacy_names: bool,
) -> dict:
    import struct as _struct

    if not struct_ptrs:
        return {}

    if offsets is None:
        offsets = get_ffield_offsets(ue_version)

    _fn_name      = offsets["FFIELD_NAME"]
    _fn_cls_priv  = offsets["FFIELD_CLASS_PRIVATE"]
    _fn_next      = offsets["FFIELD_NEXT"]
    _fn_arr_dim   = offsets["FPROPERTY_ARRAY_DIM"]
    _fn_elem_sz   = offsets["FPROPERTY_ELEMENT_SIZE"]
    _fn_flags     = offsets["FPROPERTY_FLAGS"]
    _fn_prop_off  = offsets["FPROPERTY_OFFSET"]
    _fn_fc_name   = offsets["FFIELDCLASS_NAME"]
    _NODE         = 0x50

    results: dict = {ptr: [] for ptr in struct_ptrs}

    reqs = [(ptr + USTRUCT_CHILD_PROPS, 8) for ptr in struct_ptrs]
    child_prop_results = scatter_read_multiple(handle, reqs)

    active: dict = {}
    for ptr, raw in zip(struct_ptrs, child_prop_results):
        if raw and len(raw) >= 8:
            first = _struct.unpack_from("<Q", raw)[0]
            if first and 0x10000 <= first <= 0x7FFFFFFFFFFF:
                active[ptr] = (first, set())

    max_per_struct = 500

    while active:
        items = list(active.items())
        reqs = [(curr, _NODE) for _, (curr, _) in items]
        raw_nodes = scatter_read_multiple(handle, reqs)

        next_active: dict = {}
        consecutive_wave_fails = 0
        for (struct_ptr, (curr_ptr, vis)), raw in zip(items, raw_nodes):
            if not raw:
                consecutive_wave_fails += 1
                breaker_limit = 1000000 if len(struct_ptrs) > 1000 else 5000
                if consecutive_wave_fails >= breaker_limit:
                    raise RuntimeError(f"Smart Circuit Breaker Tripped: {breaker_limit} consecutive wave property reads failed. Check CR3/PID.")
                continue
            
            consecutive_wave_fails = 0
            if len(raw) < _NODE:
                continue
            
            if curr_ptr in vis:
                continue
            vis.add(curr_ptr)
            if not (0x10000 <= curr_ptr <= 0x7FFFFFFFFFFF):
                continue

            name_idx   = _struct.unpack_from("<I", raw, _fn_name)[0]
            class_priv = _struct.unpack_from("<Q", raw, _fn_cls_priv)[0]
            next_ptr   = _struct.unpack_from("<Q", raw, _fn_next)[0]
            array_dim  = _struct.unpack_from("<i", raw, _fn_arr_dim)[0]
            elem_size  = _struct.unpack_from("<i", raw, _fn_elem_sz)[0]
            prop_off   = _struct.unpack_from("<i", raw, _fn_prop_off)[0]
            prop_flags = _struct.unpack_from("<Q", raw, _fn_flags)[0]

            type_name = _ffield_class_name_cache.get(class_priv)
            if type_name is None and _plausible_uobject_class_ptr(class_priv):
                type_idx  = read_uint32(handle, class_priv + _fn_fc_name)
                type_name = (
                    read_fname(
                        handle, gnames_ptr, type_idx, ue_version,
                        case_preserving, legacy=legacy_names,
                    )
                    or "Unknown"
                )
                _ffield_class_name_cache[class_priv] = type_name
            type_name = type_name or "Unknown"

            name = read_fname(
                handle, gnames_ptr, name_idx, ue_version,
                case_preserving, legacy=legacy_names,
            )

            if name and prop_off >= 0 and elem_size > 0:
                results[struct_ptr].append(
                    MemberInfo(
                        name=name,
                        offset=prop_off,
                        size=elem_size * max(array_dim, 1),
                        type_name=type_name,
                        array_dim=max(array_dim, 1),
                        flags=prop_flags,
                    )
                )

            member_count = len(results[struct_ptr])
            if (
                member_count < max_per_struct
                and next_ptr
                and 0x10000 <= next_ptr <= 0x7FFFFFFFFFFF
                and next_ptr not in vis
            ):
                next_active[struct_ptr] = (next_ptr, vis)

        active = next_active

    return results

def _probe_ufunction_flags_from_blob(raw: bytes, ue_version: str = "") -> int:
    import struct as _struct

    _COMMON_BITS = 0x04020400

    if ue_version and ue_version in _ufunction_flags_offset_cache:
        cached_off = _ufunction_flags_offset_cache[ue_version]
        if len(raw) >= cached_off + 4:
            val = _struct.unpack_from("<I", raw, cached_off)[0]
            if val and 0 < val <= 0xFFFFFFFF and (val & _COMMON_BITS):
                return val

    for off in _UFUNCTION_FLAGS_PROBE_OFFSETS:
        if len(raw) < off + 4:
            continue
        val = _struct.unpack_from("<I", raw, off)[0]
        if val and 0 < val <= 0xFFFFFFFF and (val & _COMMON_BITS):
            if ue_version:
                _ufunction_flags_offset_cache[ue_version] = off
                logger.debug(
                    "UFunction flags offset cached from preread blob: 0x%X for UE %s",
                    off,
                    ue_version,
                )
            return val
    return 0

def _scan_exec_ptr_from_blob(
    raw: bytes,
    base: int,
    size: int,
    ue_version: str = "",
) -> Tuple[int, int]:
    import struct as _struct

    if not base or not size:
        return 0, 0

    cached_attr = f"_cached_{ue_version}_exec_off"
    if hasattr(_read_ufunction, cached_attr):
        exec_off = getattr(_read_ufunction, cached_attr)
        if len(raw) >= exec_off + 8:
            ptr = _struct.unpack_from("<Q", raw, exec_off)[0]
            if base <= ptr < base + size:
                return ptr, exec_off

    cached_flags_off = _ufunction_flags_offset_cache.get(ue_version)
    scan_start = (cached_flags_off - 0x20) if cached_flags_off else 0x40
    scan_end = (cached_flags_off + 0x40) if cached_flags_off else 0xC0
    for off in range(max(0, scan_start), min(len(raw) - 7, scan_end), 8):
        ptr = _struct.unpack_from("<Q", raw, off)[0]
        if base <= ptr < base + size:
            setattr(_read_ufunction, cached_attr, off)
            return ptr, off
    return 0, 0

def _batch_preread_function_info(
    func_ptrs: List[int],
    handle: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    legacy_names: bool = False,
    base: int = 0,
    size: int = 0,
) -> dict:
    import struct as _struct

    unique_func_ptrs: List[int] = []
    seen: set = set()
    for ptr in func_ptrs:
        if ptr and ptr not in seen:
            seen.add(ptr)
            unique_func_ptrs.append(ptr)

    if not unique_func_ptrs:
        return {}

    _HEADER_SIZE = 0xC0
    header_reqs = [(ptr, _HEADER_SIZE) for ptr in unique_func_ptrs]
    header_results = scatter_read_multiple(handle, header_reqs)

    func_info_map: dict = {}
    for ptr, raw in zip(unique_func_ptrs, header_results):
        if not raw or len(raw) < UOBJECT_NAME + 4:
            continue

        name_idx = _struct.unpack_from("<I", raw, UOBJECT_NAME)[0]
        name = ""
        if name_idx:
            name = read_fname(
                handle,
                gnames_ptr,
                name_idx,
                ue_version,
                case_preserving,
                legacy=legacy_names,
            )
            if name:
                _uobject_name_cache[ptr] = name

        flags = _probe_ufunction_flags_from_blob(raw, ue_version)
        exec_func = 0
        rva = 0
        if base and size:
            exec_func, _ = _scan_exec_ptr_from_blob(raw, base, size, ue_version)
            if exec_func:
                rva = exec_func - base

        func_info_map[ptr] = {
            "name": name,
            "flags": flags,
            "exec_func": exec_func,
            "rva": rva,
        }

    return func_info_map

def _prebuild_super_chain_cache(
    handle: int,
    struct_header_map: dict,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    legacy_names: bool = False,
) -> None:
    import struct as _struct

    if not struct_header_map:
        return

    next_off = USTRUCT_SUPER
    frontier = {
        _struct.unpack_from("<Q", raw, USTRUCT_SUPER)[0]
        for raw in struct_header_map.values()
        if raw and len(raw) >= USTRUCT_SUPER + 8
    }
    frontier = {
        ptr for ptr in frontier if 0x10000 <= ptr <= 0x7FFFFFFFFFFF and ptr not in _super_chain_cache
    }
    if not frontier:
        return

    adjacency: dict = {}
    all_ptrs = set(frontier)

    for _ in range(50):
        current = [ptr for ptr in frontier if ptr not in adjacency]
        if not current:
            break

        next_results = scatter_read_multiple(handle, [(ptr + next_off, 8) for ptr in current])
        next_frontier = set()
        for ptr, raw in zip(current, next_results):
            if not raw or len(raw) < 8:
                continue
            next_ptr = _struct.unpack_from("<Q", raw)[0]
            adjacency[ptr] = next_ptr
            if 0x10000 <= next_ptr <= 0x7FFFFFFFFFFF:
                all_ptrs.add(next_ptr)
                if next_ptr not in adjacency and next_ptr not in _super_chain_cache:
                    next_frontier.add(next_ptr)
        frontier = next_frontier
        if not frontier:
            break

    unresolved_name_ptrs = [ptr for ptr in all_ptrs if ptr not in _uobject_name_cache]
    if unresolved_name_ptrs:
        name_results = scatter_read_multiple(handle, [(ptr + UOBJECT_NAME, 4) for ptr in unresolved_name_ptrs])
        for ptr, raw in zip(unresolved_name_ptrs, name_results):
            if raw and len(raw) >= 4:
                name_idx = _struct.unpack_from("<I", raw)[0]
                name = read_fname(
                    handle,
                    gnames_ptr,
                    name_idx,
                    ue_version,
                    case_preserving,
                    legacy=legacy_names,
                )
                if name:
                    _uobject_name_cache[ptr] = name

    def _build_chain(ptr: int) -> Tuple[List[str], bool]:
        if ptr in _super_chain_cache:
            return list(_super_chain_cache[ptr]), True

        chain: List[str] = []
        seen_ptrs = set()
        curr = ptr
        while curr and curr > 0x10000 and len(chain) < 50:
            if curr in seen_ptrs:
                return chain, False
            if curr in _super_chain_cache:
                chain.extend(_super_chain_cache[curr])
                return chain, True
            if curr not in adjacency:
                return chain, False
            seen_ptrs.add(curr)
            curr_name = _uobject_name_cache.get(curr, "")
            if curr_name:
                chain.append(curr_name)
            curr = adjacency[curr]
        return chain, curr == 0 or curr <= 0x10000

    for ptr in list(all_ptrs):
        chain, complete = _build_chain(ptr)
        if complete and ptr not in _super_chain_cache:
            _super_chain_cache[ptr] = chain

def walk_sdk(
    handle: int,
    gobjects_ptr: int,
    gnames_ptr: int,
    ue_version: str = "4.27",
    case_preserving: bool = False,
    legacy_names: bool = False,
    item_size: int = FUOBJECTITEM_SIZE_NORMAL,
    base: int = 0,
    size: int = 0,
    progress_callback=None,
) -> SDKDump:
    import struct
    from src.core.memory import USE_DRIVER
    if USE_DRIVER:
        from src.core.memory import TARGET_PID
        logger.debug("Starting SDK walk with PID %s", TARGET_PID)
    else:
        logger.debug("Starting SDK walk with handle %s", handle)

    _ffield_class_name_cache.clear()
    _uobject_name_cache.clear()
    _super_chain_cache.clear()

    dump = SDKDump()
    dump.gobjects_ptr = gobjects_ptr
    dump.gnames_ptr = gnames_ptr

    offsets = get_ffield_offsets(ue_version)

    num_elements = get_object_count(handle, gobjects_ptr)
    dump.object_count = num_elements

    objects_ptr = get_gobjects_objects_ptr(handle, gobjects_ptr)

    num_chunks = (num_elements + OBJECTS_PER_CHUNK - 1) // OBJECTS_PER_CHUNK
    chunk_ptrs = []
    if objects_ptr and num_chunks > 0:
        raw_chunks = read_bytes(handle, objects_ptr, num_chunks * 8)
        if raw_chunks and len(raw_chunks) >= num_chunks * 8:
            fmt = f"<{num_chunks}Q"
            chunk_ptrs = list(struct.unpack_from(fmt, raw_chunks))

    from src.core.memory import clear_memory_snapshots, USE_DRIVER
    ptr_floor = _pointer_floor_from_chunks(chunk_ptrs)

    last_progress_current = -1

    def _emit_progress_fraction(fraction: float) -> None:
        nonlocal last_progress_current
        if not progress_callback or num_elements <= 0:
            return
        frac = max(0.0, min(1.0, float(fraction)))
        current = int(frac * num_elements)
        if current == last_progress_current:
            return
        if current < last_progress_current and current != num_elements:
            return
        last_progress_current = current
        progress_callback(current, num_elements)

    _emit_progress_fraction(0.0)

    _bulk_ctx = None
    if USE_DRIVER:
        from src.core.driver import bulk_read_mode
        _bulk_ctx = bulk_read_mode()
        _bulk_ctx.__enter__()

    try:
        from src.engines.ue.gnames import cache_all_fnames

        def _fname_cache_progress(done_blocks: int, total_blocks: int) -> None:
            if total_blocks <= 0:
                return
            block_frac = max(0.0, min(1.0, float(done_blocks) / float(total_blocks)))
            _emit_progress_fraction(0.01 + (0.04 * block_frac))

        cache_all_fnames(
            handle,
            gnames_ptr,
            ue_version,
            case_preserving,
            legacy=legacy_names,
            progress_callback=_fname_cache_progress,
            max_snapshot_blocks=8192,
            max_snapshot_seconds=120.0,
        )
        _emit_progress_fraction(0.05)

        global_obj_fields = []

        def _collect_global_obj_fields(active_item_size: int) -> Tuple[List[Tuple[int, int, int, int, int]], int]:
            collected: List[Tuple[int, int, int, int, int]] = []
            consecutive_invalid_objs = 0
            total_valid_objs = 0

            for chunk_idx, chunk_base in enumerate(chunk_ptrs):
                if not chunk_base:
                    continue
                items_in_chunk = min(OBJECTS_PER_CHUNK, num_elements - chunk_idx * OBJECTS_PER_CHUNK)
                if items_in_chunk <= 0:
                    break

                chunk_data_size = items_in_chunk * active_item_size
                chunk_data = read_bytes(handle, chunk_base, chunk_data_size)
                if not chunk_data:
                    continue

                if len(chunk_data) < chunk_data_size:
                    chunk_data = chunk_data.ljust(chunk_data_size, b'\x00')

                obj_ptrs = []
                for within_idx in range(items_in_chunk):
                    item_offset = within_idx * active_item_size
                    if active_item_size >= 8:
                        obj_ptr = struct.unpack_from("<Q", chunk_data, item_offset)[0]
                    else:
                        obj_ptr = 0

                    if not _plausible_runtime_ptr(obj_ptr, ptr_floor):
                        consecutive_invalid_objs += 1
                        breaker_limit = 1000000 if total_valid_objs > 1000 else 5000
                        if consecutive_invalid_objs >= breaker_limit:
                            raise RuntimeError(
                                f"Smart Circuit Breaker Tripped: {breaker_limit} consecutive UObjects failed to read "
                                f"(chunk {chunk_idx}, item {within_idx}). CR3 or PID is likely incorrect."
                            )
                        continue

                    consecutive_invalid_objs = 0
                    total_valid_objs += 1
                    global_idx = chunk_idx * OBJECTS_PER_CHUNK + within_idx
                    obj_ptrs.append((global_idx, obj_ptr))

                header_reads = scatter_read_multiple(
                    handle, [(obj_ptr, 0x28) for _, obj_ptr in obj_ptrs]
                )
                for (global_idx, obj_ptr), fields_raw in zip(obj_ptrs, header_reads):
                    if not fields_raw or len(fields_raw) < 0x28:
                        continue
                    class_ptr = struct.unpack_from("<Q", fields_raw, UOBJECT_CLASS)[0]
                    if not _plausible_uobject_class_ptr(class_ptr):
                        continue
                    name_idx = struct.unpack_from("<I", fields_raw, UOBJECT_NAME)[0]
                    outer_ptr = struct.unpack_from("<Q", fields_raw, UOBJECT_OUTER)[0]
                    collected.append((global_idx, obj_ptr, class_ptr, name_idx, outer_ptr))

                if num_elements > 0 and ((chunk_idx & 0x7) == 0 or chunk_idx == len(chunk_ptrs) - 1):
                    scanned = min(num_elements, (chunk_idx + 1) * OBJECTS_PER_CHUNK)
                    scan_frac = scanned / max(1, num_elements)
                    _emit_progress_fraction(0.05 + (0.30 * scan_frac))

            return collected, total_valid_objs

        global_obj_fields, total_valid_objs = _collect_global_obj_fields(item_size)
        _emit_progress_fraction(0.35)

        if num_elements > 0 and not global_obj_fields:
            best_fields = global_obj_fields
            best_stride = item_size
            for alt_stride in (FUOBJECTITEM_SIZE_STATS, FUOBJECTITEM_SIZE_LEGACY, FUOBJECTITEM_SIZE_NORMAL):
                if alt_stride == item_size:
                    continue
                trial_fields, _ = _collect_global_obj_fields(alt_stride)
                if len(trial_fields) > len(best_fields):
                    best_fields = trial_fields
                    best_stride = alt_stride
            if best_stride != item_size and best_fields:
                logger.warning(
                    "SDK walk stride auto-correct: %d -> %d (%d viable UObject headers)",
                    item_size,
                    best_stride,
                    len(best_fields),
                )
                item_size = best_stride
                global_obj_fields = best_fields
            elif not best_fields:
                logger.warning(
                    "SDK walk found 0 viable UObject headers from %d object slots (stride=%d, ptr_floor=0x%X)",
                    num_elements,
                    item_size,
                    ptr_floor,
                )
                    
        type_classes = {}
        unique_class_ptrs = list(
            set(cptr for _, _, cptr, _, _ in global_obj_fields if _plausible_uobject_class_ptr(cptr))
        )
        
        if unique_class_ptrs:
            class_name_queries = [(cptr + UOBJECT_NAME, 4) for cptr in unique_class_ptrs]
            c_results = scatter_read_multiple(handle, class_name_queries)
            for cptr, raw in zip(unique_class_ptrs, c_results):
                if raw and len(raw) >= 4:
                    c_name_idx = struct.unpack("<I", raw)[0]
                    type_classes[cptr] = read_fname(handle, gnames_ptr, c_name_idx, ue_version, case_preserving, legacy=legacy_names)
        _emit_progress_fraction(0.45)

        struct_objs = []
        enum_objs = []
        for global_idx, obj_ptr, class_ptr, name_idx, outer_ptr in global_obj_fields:
            cname = type_classes.get(class_ptr, "")
            if cname in ("Class", "ScriptStruct"):
                struct_objs.append((global_idx, obj_ptr, class_ptr, name_idx, outer_ptr, cname == "Class"))
            elif cname == "Enum":
                enum_objs.append(obj_ptr)

        preread_map = {}
        phase_b_function_map: dict = {}
        preread_function_info_map: dict = {}
        if USE_DRIVER and not _is_pre_425_ue(ue_version):
            target_ptrs_for_ffields = [obj_ptr for _, obj_ptr, _, _, _, _ in struct_objs]
            phase_b_function_map = {obj_ptr: [] for obj_ptr in target_ptrs_for_ffields}
            visited_children = set()

            children_reqs = [(obj_ptr + USTRUCT_CHILDREN, 8) for obj_ptr in target_ptrs_for_ffields]
            children_results = scatter_read_multiple(handle, children_reqs)

            active_chains: list = []
            for raw in children_results:
                if raw and len(raw) >= 8:
                    cptr = struct.unpack_from("<Q", raw)[0]
                    if cptr and 0x10000 <= cptr <= 0x7FFFFFFFFFFF:
                        active_chains.append((cptr, 0))
                    else:
                        active_chains.append(None)
                else:
                    active_chains.append(None)

            _CHILDREN_NODE_SIZE = 0x30
            max_waves = 500
            for _wave in range(max_waves):
                wave_items: list = []
                for ci, entry in enumerate(active_chains):
                    if entry is None:
                        continue
                    cptr, found = entry
                    if cptr in visited_children or found >= 500:
                        active_chains[ci] = None
                        continue
                    if not (0x10000 <= cptr <= 0x7FFFFFFFFFFF):
                        active_chains[ci] = None
                        continue
                    wave_items.append((ci, cptr))

                if not wave_items:
                    break

                node_reqs = [(cptr, _CHILDREN_NODE_SIZE) for _, cptr in wave_items]
                node_results = scatter_read_multiple(handle, node_reqs)

                unknown_class_ptrs = set()
                node_class_ptrs = []
                for (ci, cptr), raw in zip(wave_items, node_results):
                    if not raw or len(raw) < _CHILDREN_NODE_SIZE:
                        node_class_ptrs.append(0)
                        continue
                    fc_ptr = struct.unpack_from("<Q", raw, UOBJECT_CLASS)[0]
                    node_class_ptrs.append(fc_ptr)
                    if _plausible_uobject_class_ptr(fc_ptr) and fc_ptr not in type_classes:
                        unknown_class_ptrs.add(fc_ptr)

                if unknown_class_ptrs:
                    name_reqs = [(fc + UOBJECT_NAME, 4) for fc in unknown_class_ptrs]
                    name_results = scatter_read_multiple(handle, name_reqs)
                    for fc, raw in zip(unknown_class_ptrs, name_results):
                        if raw and len(raw) >= 4:
                            fc_idx = struct.unpack_from("<I", raw)[0]
                            fc_name = read_fname(handle, gnames_ptr, fc_idx, ue_version, case_preserving, legacy=legacy_names)
                            type_classes[fc] = fc_name

                for (ci, cptr), raw, fc_ptr in zip(wave_items, node_results, node_class_ptrs):
                    visited_children.add(cptr)
                    entry = active_chains[ci]
                    if entry is None:
                        continue
                    _, found = entry

                    if not raw or len(raw) < _CHILDREN_NODE_SIZE:
                        active_chains[ci] = None
                        continue

                    fc_name = type_classes.get(fc_ptr, "")
                    if "Function" in fc_name:
                        owner_struct_ptr = target_ptrs_for_ffields[ci]
                        phase_b_function_map.setdefault(owner_struct_ptr, []).append(cptr)
                        target_ptrs_for_ffields.append(cptr)

                    next_ptr = struct.unpack_from("<Q", raw, 0x28)[0]
                    if next_ptr and 0x10000 <= next_ptr <= 0x7FFFFFFFFFFF and next_ptr not in visited_children:
                        active_chains[ci] = (next_ptr, found + 1)
                    else:
                        active_chains[ci] = None

            if target_ptrs_for_ffields:
                logger.info(f"Unleashing Massive Scatter-Wave on {len(target_ptrs_for_ffields)} chains...")
                preread_map = _scatter_walk_ffield_chains(
                    target_ptrs_for_ffields,
                    handle,
                    gnames_ptr,
                    ue_version,
                    case_preserving,
                    offsets,
                    legacy_names,
                )

                missing_prereads = [
                    obj_ptr for _, obj_ptr, _, _, _, _ in struct_objs if obj_ptr not in preread_map
                ]
                if missing_prereads:
                    logger.warning(
                        "Scatter preread map missed %d struct(s); those will fall back to slower reads.",
                        len(missing_prereads),
                    )

                preread_function_info_map = _batch_preread_function_info(
                    [func_ptr for func_ptrs in phase_b_function_map.values() for func_ptr in func_ptrs],
                    handle,
                    gnames_ptr,
                    ue_version,
                    case_preserving,
                    legacy_names=legacy_names,
                    base=base,
                    size=size,
                )
        _emit_progress_fraction(0.55)

        _HEADER_SIZE = 0x60
        struct_header_map: dict = {}
        if USE_DRIVER and struct_objs:
            header_reqs = [(obj_ptr, _HEADER_SIZE) for _, obj_ptr, _, _, _, _ in struct_objs]
            header_results = scatter_read_multiple(handle, header_reqs)
            for (_, obj_ptr, _, _, _, _), raw in zip(struct_objs, header_results):
                if raw and len(raw) >= _HEADER_SIZE:
                    struct_header_map[obj_ptr] = raw
                    nidx = struct.unpack_from("<I", raw, UOBJECT_NAME)[0]
                    if nidx and obj_ptr not in _uobject_name_cache:
                        n = read_fname(handle, gnames_ptr, nidx, ue_version, case_preserving, legacy=legacy_names)
                        _uobject_name_cache[obj_ptr] = n

            outer_ptrs_to_resolve = set()
            for raw in struct_header_map.values():
                optr = struct.unpack_from("<Q", raw, UOBJECT_OUTER)[0]
                if optr and 0x10000 <= optr <= 0x7FFFFFFFFFFF and optr not in _uobject_name_cache:
                    outer_ptrs_to_resolve.add(optr)
            if outer_ptrs_to_resolve:
                outer_name_reqs = [(optr + UOBJECT_NAME, 4) for optr in outer_ptrs_to_resolve]
                outer_name_results = scatter_read_multiple(handle, outer_name_reqs)
                for optr, raw in zip(outer_ptrs_to_resolve, outer_name_results):
                    if raw and len(raw) >= 4:
                        oidx = struct.unpack_from("<I", raw)[0]
                        n = read_fname(handle, gnames_ptr, oidx, ue_version, case_preserving, legacy=legacy_names)
                        _uobject_name_cache[optr] = n

            if not _is_pre_423_ue(ue_version):
                super_ptrs_to_resolve = set()
                for raw in struct_header_map.values():
                    sptr = struct.unpack_from("<Q", raw, USTRUCT_SUPER)[0]
                    if sptr and 0x10000 <= sptr <= 0x7FFFFFFFFFFF and sptr not in _uobject_name_cache:
                        super_ptrs_to_resolve.add(sptr)
                if super_ptrs_to_resolve:
                    super_name_reqs = [(sptr + UOBJECT_NAME, 4) for sptr in super_ptrs_to_resolve]
                    super_name_results = scatter_read_multiple(handle, super_name_reqs)
                    for sptr, raw in zip(super_ptrs_to_resolve, super_name_results):
                        if raw and len(raw) >= 4:
                            sidx = struct.unpack_from("<I", raw)[0]
                            n = read_fname(handle, gnames_ptr, sidx, ue_version, case_preserving, legacy=legacy_names)
                            _uobject_name_cache[sptr] = n

                _prebuild_super_chain_cache(
                    handle,
                    struct_header_map,
                    gnames_ptr,
                    ue_version,
                    case_preserving,
                    legacy_names=legacy_names,
                )

        total_structs = max(1, len(struct_objs))
        for struct_idx, (global_idx, obj_ptr, class_ptr, name_idx, outer_ptr, is_class) in enumerate(struct_objs, start=1):
            if (struct_idx & 0x3F) == 0 or struct_idx == total_structs:
                struct_frac = struct_idx / total_structs
                _emit_progress_fraction(0.55 + (0.40 * struct_frac))

            info = _walk_struct(
                handle,
                obj_ptr,
                gnames_ptr,
                ue_version,
                case_preserving,
                is_class=is_class,
                offsets=offsets,
                legacy_names=legacy_names,
                base=base,
                size=size,
                preread_members=preread_map.get(obj_ptr),
                global_preread_map=preread_map,
                preread_header=struct_header_map.get(obj_ptr),
                preread_func_ptrs=phase_b_function_map.get(obj_ptr),
                global_preread_function_info=preread_function_info_map,
            )
            if info and info.members:
                dump.structs.append(info)

        total_enums = max(1, len(enum_objs))
        for enum_idx, eptr in enumerate(enum_objs, start=1):
            info = _walk_enum(
                handle,
                eptr,
                gnames_ptr,
                ue_version,
                case_preserving,
                legacy_names=legacy_names,
            )
            if info and info.values:
                dump.enums.append(info)
            if (enum_idx & 0x3F) == 0 or enum_idx == total_enums:
                enum_frac = enum_idx / total_enums
                _emit_progress_fraction(0.95 + (0.04 * enum_frac))

    finally:
        if _bulk_ctx is not None:
            _bulk_ctx.__exit__(None, None, None)
        clear_memory_snapshots()

    if progress_callback:
        progress_callback(num_elements, num_elements)

    return dump

def _walk_struct(
    handle: int,
    struct_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    is_class: bool = False,
    offsets: dict = None,
    legacy_names: bool = False,
    base: int = 0,
    size: int = 0,
    preread_members=None,
    global_preread_map=None,
    preread_header=None,
    preread_func_ptrs=None,
    global_preread_function_info=None,
) -> Optional[StructInfo]:
    import struct as _s
    pre_425 = _is_pre_425_ue(ue_version)
    pre_423 = _is_pre_423_ue(ue_version)

    if pre_423:
        super_off = USTRUCT_SUPER_LEGACY
        children_off = USTRUCT_CHILDREN_LEGACY
        props_size_off = USTRUCT_PROPERTIES_SIZE_LEGACY
    else:
        super_off = USTRUCT_SUPER
        children_off = USTRUCT_CHILDREN
        props_size_off = USTRUCT_PROPERTIES_SIZE

    def _cached_obj_name(ptr: int) -> str:
        cached = _uobject_name_cache.get(ptr)
        if cached is not None:
            return cached
        nidx = read_uint32(handle, ptr + UOBJECT_NAME)
        n = read_fname(
            handle, gnames_ptr, nidx, ue_version, case_preserving, legacy=legacy_names
        )
        _uobject_name_cache[ptr] = n
        return n

    _hdr = preread_header
    if _hdr and len(_hdr) >= 0x60 and not pre_423:
        name = _cached_obj_name(struct_ptr)
        if not name:
            return None
        outer_ptr = _s.unpack_from("<Q", _hdr, UOBJECT_OUTER)[0]
        package = _cached_obj_name(outer_ptr) if outer_ptr else ""
        props_size = _s.unpack_from("<i", _hdr, props_size_off)[0]
        if props_size <= 0:
            return None
        super_ptr = _s.unpack_from("<Q", _hdr, super_off)[0]
        super_name = _cached_obj_name(super_ptr) if super_ptr else ""
        child_ptr = _s.unpack_from("<Q", _hdr, children_off)[0]
    else:
        name = _cached_obj_name(struct_ptr)
        if not name:
            return None
        outer_ptr = read_uint64(handle, struct_ptr + UOBJECT_OUTER)
        package = _cached_obj_name(outer_ptr) if outer_ptr else ""
        props_size = read_int32(handle, struct_ptr + props_size_off)
        if props_size <= 0:
            return None
        super_ptr = read_uint64(handle, struct_ptr + super_off)
        super_name = _cached_obj_name(super_ptr) if super_ptr else ""
        child_ptr = None

    full_name = f"{package}.{name}" if package else name

    _sc_next_off = USTRUCT_SUPER_LEGACY if pre_423 else USTRUCT_SUPER
    if super_ptr and super_ptr in _super_chain_cache:
        super_chain = list(_super_chain_cache[super_ptr])
    else:
        super_chain = []
        _sc_ptr = super_ptr
        _sc_visited = set()
        while _sc_ptr and _sc_ptr > 0x10000 and len(super_chain) < 50:
            if _sc_ptr in _sc_visited:
                break
            if _sc_ptr in _super_chain_cache:
                super_chain.extend(_super_chain_cache[_sc_ptr])
                break
            _sc_visited.add(_sc_ptr)
            _sc_name = _cached_obj_name(_sc_ptr)
            if _sc_name:
                super_chain.append(_sc_name)
            _sc_ptr = read_uint64(handle, _sc_ptr + _sc_next_off)
        if super_ptr and super_ptr > 0x10000:
            _super_chain_cache[super_ptr] = super_chain

    info = StructInfo(
        name=name,
        full_name=full_name,
        address=struct_ptr,
        size=props_size,
        super_name=super_name,
        is_class=is_class,
        package=package,
        super_chain=super_chain,
    )

    visited: set = set()
    max_props = 500

    if preread_func_ptrs is not None and not pre_425:
        for func_ptr in preread_func_ptrs[:max_props]:
            if not (0x10000 <= func_ptr <= 0x7FFFFFFFFFFF):
                continue
            func = _read_ufunction(
                handle,
                func_ptr,
                gnames_ptr,
                ue_version,
                case_preserving,
                offsets=offsets,
                legacy_names=legacy_names,
                base=base,
                size=size,
                preread_members=global_preread_map.get(func_ptr) if global_preread_map else None,
                preread_info=global_preread_function_info.get(func_ptr) if global_preread_function_info else None,
            )
            if func:
                info.functions.append(func)
        child_ptr = 0

    if child_ptr is None:
        child_ptr = read_uint64(handle, struct_ptr + children_off)
    
    from src.core.memory import add_memory_snapshot, USE_DRIVER

    _skip_prescan = preread_members is not None or preread_func_ptrs is not None
    if USE_DRIVER and not _skip_prescan:
        from src.core.driver import read_memory_kernel
        from src.core.memory import TARGET_PID, _snapshot_pages
        page_size = 0x1000

        def _ensure_page_snapshotted(ptr, snapped_pages):
            page = ptr & ~(page_size - 1)
            if page not in snapped_pages and page not in _snapshot_pages:
                data = read_memory_kernel(TARGET_PID, page, page_size)
                if data:
                    add_memory_snapshot(page, data)
                snapped_pages.add(page)

        snapped = set()

        curr = child_ptr
        while curr and not (curr in visited) and (0x10000 <= curr <= 0x7FFFFFFFFFFF):
            _ensure_page_snapshotted(curr, snapped)
            field_class_ptr = read_uint64(handle, curr + UOBJECT_CLASS)
            if field_class_ptr:
                _ensure_page_snapshotted(field_class_ptr, snapped)
            curr = read_uint64(handle, curr + UPROPERTY_NEXT)
            if len(snapped) > 2000:
                break

        if not pre_425:
            if offsets is None:
                offsets = get_ffield_offsets(ue_version)
            child_prop_prescan = read_uint64(handle, struct_ptr + USTRUCT_CHILD_PROPS)
            curr = child_prop_prescan
            while curr and not (curr in visited) and (0x10000 <= curr <= 0x7FFFFFFFFFFF):
                _ensure_page_snapshotted(curr, snapped)
                class_priv = read_uint64(handle, curr + offsets["FFIELD_CLASS_PRIVATE"])
                if class_priv:
                    _ensure_page_snapshotted(class_priv, snapped)
                curr = read_uint64(handle, curr + offsets["FFIELD_NEXT"])
                if len(snapped) > 2000:
                    break

    child_ptr_run = child_ptr
    while child_ptr_run and len(info.members) + len(info.functions) < max_props:
        if child_ptr_run in visited:
            break
        visited.add(child_ptr_run)

        if not (0x10000 <= child_ptr_run <= 0x7FFFFFFFFFFF):
            break

        field_class_ptr = read_uint64(handle, child_ptr_run + UOBJECT_CLASS)
        field_class_name = ""
        if _plausible_uobject_class_ptr(field_class_ptr):
            field_class_name = _ffield_class_name_cache.get(field_class_ptr, "")
            if not field_class_name:
                fcn_idx = read_uint32(handle, field_class_ptr + UOBJECT_NAME)
                field_class_name = read_fname(
                    handle, gnames_ptr, fcn_idx, ue_version, case_preserving, legacy=legacy_names
                )
                if field_class_name:
                    _ffield_class_name_cache[field_class_ptr] = field_class_name
        if "Function" in field_class_name:
            func = _read_ufunction(
                handle, child_ptr_run, gnames_ptr, ue_version, case_preserving,
                offsets=offsets, legacy_names=legacy_names, base=base, size=size,
                preread_members=global_preread_map.get(child_ptr_run) if global_preread_map else None,
                preread_info=global_preread_function_info.get(child_ptr_run) if global_preread_function_info else None,
            )
            if func:
                info.functions.append(func)
        elif pre_425 and "Property" in field_class_name:
            member = _read_uproperty(
                handle, child_ptr_run, gnames_ptr, ue_version, case_preserving,
                field_class_name, legacy_names=legacy_names,
            )
            if member:
                info.members.append(member)

        child_ptr_run = read_uint64(handle, child_ptr_run + UPROPERTY_NEXT)

    if not pre_425:
        if offsets is None:
            offsets = get_ffield_offsets(ue_version)

        if preread_members is not None:
            info.members.extend(preread_members)
        else:
            from src.core.memory import USE_DRIVER as _USE_DRV
            if _USE_DRV:
                fallback_map = _scatter_walk_ffield_chains(
                    [struct_ptr], handle, gnames_ptr, ue_version,
                    case_preserving, offsets, legacy_names,
                )
                info.members.extend(fallback_map.get(struct_ptr, []))
            else:
                child_prop_run = read_uint64(handle, struct_ptr + USTRUCT_CHILD_PROPS)
                while child_prop_run and len(info.members) < max_props:
                    if child_prop_run in visited:
                        break
                    visited.add(child_prop_run)
                    if not (0x10000 <= child_prop_run <= 0x7FFFFFFFFFFF):
                        break
                    member = _read_property(
                        handle, child_prop_run, gnames_ptr, ue_version, case_preserving,
                        offsets=offsets, legacy_names=legacy_names,
                    )
                    if member:
                        info.members.append(member)
                    child_prop_run = read_uint64(handle, child_prop_run + offsets["FFIELD_NEXT"])

    for m in info.members:
        if m.offset + m.size > props_size:
            logger.warning(
                f"Size violation in {name}: {m.name} "
                f"offset=0x{m.offset:X} size={m.size} "
                f"exceeds PropertiesSize={props_size}"
            )

    return info

def _probe_ufunction_flags(handle: int, func_ptr: int, ue_version: str = "") -> int:
    _COMMON_BITS = 0x04020400

    if ue_version and ue_version in _ufunction_flags_offset_cache:
        cached_off = _ufunction_flags_offset_cache[ue_version]
        return read_uint32(handle, func_ptr + cached_off)

    for off in _UFUNCTION_FLAGS_PROBE_OFFSETS:
        val = read_uint32(handle, func_ptr + off)
        if val and 0 < val <= 0xFFFFFFFF and (val & _COMMON_BITS):
            if ue_version:
                _ufunction_flags_offset_cache[ue_version] = off
                logger.debug(
                    "UFunction flags offset cached: 0x%X for UE %s", off, ue_version
                )
            return val
    return 0

def _read_ufunction(
    handle: int,
    func_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    offsets: dict = None,
    legacy_names: bool = False,
    base: int = 0,
    size: int = 0,
    preread_members=None,
    preread_info=None,
) -> Optional[FunctionInfo]:
    name = ""
    if preread_info is not None:
        name = preread_info.get("name", "") or _uobject_name_cache.get(func_ptr, "")
    if not name:
        name_idx = read_uint32(handle, func_ptr + UOBJECT_NAME)
        name = read_fname(
            handle, gnames_ptr, name_idx, ue_version, case_preserving, legacy=legacy_names
        )
    if not name:
        return None
    _uobject_name_cache[func_ptr] = name

    func_flags = preread_info.get("flags", 0) if preread_info is not None else 0
    if not func_flags:
        func_flags = _probe_ufunction_flags(handle, func_ptr, ue_version)

    func_info = FunctionInfo(name=name, address=func_ptr, flags=func_flags)

    if preread_info is not None:
        func_info.exec_func = preread_info.get("exec_func", 0)
        func_info.rva = preread_info.get("rva", 0)
    elif base and size:
        cached_off = _ufunction_flags_offset_cache.get(ue_version)
        if hasattr(_read_ufunction, f"_cached_{ue_version}_exec_off"):
            exec_off = getattr(_read_ufunction, f"_cached_{ue_version}_exec_off")
            ptr = read_uint64(handle, func_ptr + exec_off)
            if base <= ptr < base + size:
                func_info.exec_func = ptr
                func_info.rva = ptr - base
        else:
            scan_start = (cached_off - 0x20) if cached_off else 0x40
            scan_end = (cached_off + 0x40) if cached_off else 0xC0
            for off in range(max(0, scan_start), scan_end, 8):
                ptr = read_uint64(handle, func_ptr + off)
                if base <= ptr < base + size:
                    func_info.exec_func = ptr
                    func_info.rva = ptr - base
                    setattr(_read_ufunction, f"_cached_{ue_version}_exec_off", off)
                    break

    pre_425 = _is_pre_425_ue(ue_version)
    pre_423 = _is_pre_423_ue(ue_version)

    if pre_423:
        children_off = USTRUCT_CHILDREN_LEGACY
    else:
        children_off = USTRUCT_CHILDREN

    visited: set = set()
    max_params = 64

    if pre_425:
        child_ptr = read_uint64(handle, func_ptr + children_off)
        while child_ptr and len(func_info.params) < max_params:
            if child_ptr in visited:
                break
            visited.add(child_ptr)

            if not (0x10000 <= child_ptr <= 0x7FFFFFFFFFFF):
                break

            member = _read_uproperty(
                handle,
                child_ptr,
                gnames_ptr,
                ue_version,
                case_preserving,
                legacy_names=legacy_names,
            )
            if member:
                flags = read_uint64(handle, child_ptr + UPROPERTY_PROPERTY_FLAGS)
                param = FunctionParamInfo(
                    name=member.name,
                    offset=member.offset,
                    size=member.size,
                    type_name=member.type_name,
                    flags=flags,
                )
                func_info.params.append(param)

            child_ptr = read_uint64(handle, child_ptr + UPROPERTY_NEXT)
    else:
        if offsets is None:
            offsets = get_ffield_offsets(ue_version)

        _members = preread_members
        if _members is None:
            from src.core.memory import USE_DRIVER as _USE_DRV
            if _USE_DRV:
                _fback = _scatter_walk_ffield_chains(
                    [func_ptr], handle, gnames_ptr, ue_version,
                    case_preserving, offsets, legacy_names,
                )
                _members = _fback.get(func_ptr, [])

        if _members is not None:
            for member in _members:
                param = FunctionParamInfo(
                    name=member.name,
                    offset=member.offset,
                    size=member.size,
                    type_name=member.type_name,
                    flags=getattr(member, 'flags', 0),
                )
                func_info.params.append(param)
        else:
            child_prop = read_uint64(handle, func_ptr + USTRUCT_CHILD_PROPS)

            while child_prop and len(func_info.params) < max_params:
                if child_prop in visited:
                    break
                visited.add(child_prop)

                if not (0x10000 <= child_prop <= 0x7FFFFFFFFFFF):
                    break

                member = _read_property(
                    handle,
                    child_prop,
                    gnames_ptr,
                    ue_version,
                    case_preserving,
                    offsets=offsets,
                    legacy_names=legacy_names,
                )
                if member:
                    flags = read_uint64(handle, child_prop + offsets["FPROPERTY_FLAGS"])
                    param = FunctionParamInfo(
                        name=member.name,
                        offset=member.offset,
                        size=member.size,
                        type_name=member.type_name,
                        flags=flags,
                    )
                    func_info.params.append(param)

                child_prop = read_uint64(handle, child_prop + offsets["FFIELD_NEXT"])

    return func_info

def _read_uproperty(
    handle: int,
    prop_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    type_name: str = "",
    legacy_names: bool = False,
) -> Optional[MemberInfo]:
    name_idx = read_uint32(handle, prop_ptr + UOBJECT_NAME)
    name = read_fname(
        handle, gnames_ptr, name_idx, ue_version, case_preserving, legacy=legacy_names
    )
    if not name:
        return None

    if not type_name:
        class_ptr = read_uint64(handle, prop_ptr + UOBJECT_CLASS)
        if class_ptr:
            type_name_idx = read_uint32(handle, class_ptr + UOBJECT_NAME)
            type_name = read_fname(
                handle,
                gnames_ptr,
                type_name_idx,
                ue_version,
                case_preserving,
                legacy=legacy_names,
            )

    array_dim = read_int32(handle, prop_ptr + UPROPERTY_ARRAY_DIM)
    element_size = read_int32(handle, prop_ptr + UPROPERTY_ELEMENT_SIZE)
    offset = read_int32(handle, prop_ptr + UPROPERTY_OFFSET_INTERNAL)

    if offset < 0 or element_size <= 0:
        return None

    size = element_size * max(array_dim, 1)

    return MemberInfo(
        name=name,
        offset=offset,
        size=size,
        type_name=type_name or "Unknown",
        array_dim=array_dim if array_dim > 1 else 1,
    )

def _read_property(
    handle: int,
    prop_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    offsets: dict = None,
    legacy_names: bool = False,
) -> Optional[MemberInfo]:
    if offsets is None:
        offsets = get_ffield_offsets(ue_version)

    name_idx = read_uint32(handle, prop_ptr + offsets["FFIELD_NAME"])
    name = read_fname(
        handle, gnames_ptr, name_idx, ue_version, case_preserving, legacy=legacy_names
    )
    if not name:
        return None

    class_private = read_uint64(handle, prop_ptr + offsets["FFIELD_CLASS_PRIVATE"])
    type_name = ""
    if class_private:
        type_name_idx = read_uint32(handle, class_private + offsets["FFIELDCLASS_NAME"])
        type_name = read_fname(
            handle,
            gnames_ptr,
            type_name_idx,
            ue_version,
            case_preserving,
            legacy=legacy_names,
        )

    offset = read_int32(handle, prop_ptr + offsets["FPROPERTY_OFFSET"])
    element_size = read_int32(handle, prop_ptr + offsets["FPROPERTY_ELEMENT_SIZE"])
    array_dim = read_int32(handle, prop_ptr + offsets["FPROPERTY_ARRAY_DIM"])
    flags = read_uint64(handle, prop_ptr + offsets["FPROPERTY_FLAGS"])

    if offset < 0 or element_size <= 0:
        return None

    size = element_size * max(array_dim, 1)

    return MemberInfo(
        name=name,
        offset=offset,
        size=size,
        type_name=type_name or "Unknown",
        array_dim=array_dim if array_dim > 1 else 1,
        flags=flags,
    )

def _walk_enum(
    handle: int,
    enum_ptr: int,
    gnames_ptr: int,
    ue_version: str,
    case_preserving: bool,
    legacy_names: bool = False,
) -> Optional[EnumInfo]:

    name_idx = read_uint32(handle, enum_ptr + UOBJECT_NAME)
    name = read_fname(
        handle, gnames_ptr, name_idx, ue_version, case_preserving, legacy=legacy_names
    )
    if not name:
        return None

    outer_ptr = read_uint64(handle, enum_ptr + UOBJECT_OUTER)
    package = ""
    if outer_ptr:
        outer_name_idx = read_uint32(handle, outer_ptr + UOBJECT_NAME)
        package = read_fname(
            handle,
            gnames_ptr,
            outer_name_idx,
            ue_version,
            case_preserving,
            legacy=legacy_names,
        )

    full_name = f"{package}.{name}" if package else name

    info = EnumInfo(name=name, full_name=full_name, address=enum_ptr)

    names_data_ptr = 0
    names_count = 0
    for off in _UENUM_NAMES_PROBE_OFFSETS:
        p = read_uint64(handle, enum_ptr + off)
        c = read_int32(handle, enum_ptr + off + 8)
        if p and 1 <= c <= 500:
            names_data_ptr = p
            names_count = c
            break

    if not names_data_ptr or names_count <= 0:
        return info

    tarray_size = names_count * 16
    tarray_data = read_bytes(handle, names_data_ptr, tarray_size)

    if tarray_data and len(tarray_data) >= tarray_size:
        for i in range(names_count):
            off = i * 16
            entry_name_idx = struct.unpack_from("<I", tarray_data, off)[0]
            entry_value = struct.unpack_from("<q", tarray_data, off + 8)[0]

            entry_name = read_fname(
                handle,
                gnames_ptr,
                entry_name_idx,
                ue_version,
                case_preserving,
                legacy=legacy_names,
            )
            if entry_name:
                info.values.append((entry_name, entry_value))
    else:
        for i in range(names_count):
            entry_addr = names_data_ptr + i * 16
            entry_name_idx = read_uint32(handle, entry_addr)
            entry_value = read_uint64(handle, entry_addr + 8)

            entry_name = read_fname(
                handle,
                gnames_ptr,
                entry_name_idx,
                ue_version,
                case_preserving,
                legacy=legacy_names,
            )
            if entry_name:
                info.values.append((entry_name, entry_value))

    return info
