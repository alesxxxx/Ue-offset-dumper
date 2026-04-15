
import time as _time
import struct
from typing import Dict, List, Optional, Tuple
from collections import Counter

from src.core.memory import read_bytes, read_uint64, read_uint32, read_int32
from src.core.pe_parser import get_pe_rdata_data_scan_ranges
from src.core.scanner import scan_pattern, resolve_rip
from src.engines.ue.signatures import GOBJECTS_SIGS
from src.engines.ue.offsets_override import load_game_offsets_override
from src.engines.ue.gnames import read_fname

import logging

logger = logging.getLogger(__name__)

BRUTE_TIMEOUT = 20.0

OBJECTS_PER_CHUNK = 0x10000
FUOBJECTITEM_SIZE_LEGACY = 16
FUOBJECTITEM_SIZE_NORMAL = 24
FUOBJECTITEM_SIZE_STATS = 32
FUOBJECTITEM_SIZE_UE5 = 48

_PLAUSIBLE_PTR_LO = 0x10000
_PLAUSIBLE_PTR_HI = 0x7FFFFFFFFFFF
PAGE_SIZE = 0x1000
FUOBJECTARRAY_SEARCH_BYTES = 0x40
FUOBJECTARRAY_OBJECT_PTR_OFFSETS = (0x0, 0x8, 0x10, 0x18)
FUOBJECTARRAY_COUNTER_SCAN_MAX = 0x2C
FUOBJECTARRAY_CANDIDATE_LIMIT = 4096
FUOBJECTARRAY_SAMPLE_SLOTS = 16

BRUTE_TIMEOUT = 45.0
FUOBJECTARRAY_OBJECT_PTR_OFFSETS = tuple(range(0, 0x31, 8))
FUOBJECTARRAY_COUNTER_SCAN_MAX = 0x30
FUOBJECTARRAY_CANDIDATE_LIMIT = 8192

_gobjects_brute_last_meta: Dict[str, int] = {}
_gobjects_objects_offset: Dict[int, int] = {}
_gobjects_resolution_meta: Dict[str, object] = {}
FUOBJECTARRAY_LAYOUT_BONUSES = {
    (0x0, 0x8): 4,
    (0x0, 0x10): 3,
    (0x10, 0x18): 6,
    (0x20, 0x30): 6,
}
_KNOWN_GOBJECT_CLASS_NAMES = {
    "Class",
    "Package",
    "World",
    "Level",
    "Function",
    "Enum",
    "ScriptStruct",
    "Struct",
    "Property",
    "ObjectProperty",
    "ClassProperty",
}

def get_last_gobjects_resolution_meta() -> Dict[str, object]:
    return dict(_gobjects_resolution_meta)

def _set_gobjects_resolution_meta(
    *,
    address: int,
    item_size: int,
    method: str,
    objects_offset: Optional[int] = None,
) -> None:
    _gobjects_resolution_meta.clear()
    _gobjects_resolution_meta.update(
        {
            "address": address,
            "item_size": item_size,
            "method": method,
            "objects_offset": (
                FUOBJECTARRAY_OBJECTS_OFFSET
                if objects_offset is None
                else objects_offset
            ),
        }
    )

def clear_gobjects_scan_state() -> None:
    _gobjects_brute_cache.clear()
    _gobjects_brute_last_meta.clear()
    _gobjects_objects_offset.clear()
    _gobjects_resolution_meta.clear()

def get_gobjects_objects_offset(gobjects_ptr: int) -> int:
    return _gobjects_objects_offset.get(gobjects_ptr, FUOBJECTARRAY_OBJECTS_OFFSET)

def get_gobjects_objects_ptr(handle: int, gobjects_ptr: int) -> int:
    return read_uint64(handle, gobjects_ptr + get_gobjects_objects_offset(gobjects_ptr))

def _plausible_ue_ptr64(p: int) -> bool:
    return _PLAUSIBLE_PTR_LO < p < _PLAUSIBLE_PTR_HI

def _plausible_module_ptr(value: int, module_base: int, module_end: int) -> bool:
    return bool(module_base and module_base <= value < module_end)

def _plausible_runtime_heap_ptr(value: int, module_base: int, module_end: int) -> bool:
    return _plausible_ue_ptr64(value) and not _plausible_module_ptr(
        value, module_base, module_end
    )

def _try_read_qword(handle: int, address: int) -> Tuple[bool, int]:
    data = read_bytes(handle, address, 8)
    if len(data) < 8:
        return False, 0
    return True, int.from_bytes(data, "little")

def _shape_looks_like_fuobjectarray(
    num_elements: int,
    max_elements: int,
    num_chunks: int,
    max_chunks: int,
) -> bool:
    if not (GOBJECTS_BRUTE_MIN_OBJECT_COUNT <= num_elements <= 5_000_000):
        return False
    if max_elements and max_elements < num_elements:
        return False
    if max_elements and max_elements > 16_000_000:
        return False
    if not (1 <= num_chunks <= 0x4000):
        return False
    if max_chunks and max_chunks < num_chunks:
        return False
    if max_chunks and max_chunks > 0x4000:
        return False

    expected_chunks = max(
        1, (num_elements + OBJECTS_PER_CHUNK - 1) // OBJECTS_PER_CHUNK
    )
    if num_chunks < expected_chunks:
        return False
    if max_chunks and max_chunks < expected_chunks:
        return False
    return True

def _probe_fuobjectarray_shape(handle: int, base: int) -> Optional[Dict[str, int]]:
    raw = read_bytes(handle, base, FUOBJECTARRAY_SEARCH_BYTES)
    if len(raw) < 0x20:
        return None
    return _probe_fuobjectarray_candidate_bytes(raw, base_addr=base)

def _probe_fuobjectarray_candidate_bytes(
    raw: bytes,
    *,
    base_addr: int = 0,
    module_base: int = 0,
    module_end: int = 0,
) -> Optional[Dict[str, int]]:
    if len(raw) < 0x20:
        return None

    best: Optional[Dict[str, int]] = None
    best_score = -1
    ptr_checker = (
        (lambda value: _plausible_runtime_heap_ptr(value, module_base, module_end))
        if module_base and module_end
        else _plausible_ue_ptr64
    )

    max_counter_off = min(len(raw) - 16, FUOBJECTARRAY_COUNTER_SCAN_MAX)
    for objects_off in FUOBJECTARRAY_OBJECT_PTR_OFFSETS:
        if objects_off + 8 > len(raw):
            continue
        objects_ptr = struct.unpack_from("<Q", raw, objects_off)[0]
        if not ptr_checker(objects_ptr):
            continue

        for counter_off in range(0, max_counter_off + 1, 4):
            max_elements = struct.unpack_from("<i", raw, counter_off + 0x0)[0]
            num_elements = struct.unpack_from("<i", raw, counter_off + 0x4)[0]
            max_chunks = struct.unpack_from("<i", raw, counter_off + 0x8)[0]
            num_chunks = struct.unpack_from("<i", raw, counter_off + 0xC)[0]

            if not _shape_looks_like_fuobjectarray(
                num_elements=num_elements,
                max_elements=max_elements,
                num_chunks=num_chunks,
                max_chunks=max_chunks,
            ):
                continue

            expected_chunks = max(
                1, (num_elements + OBJECTS_PER_CHUNK - 1) // OBJECTS_PER_CHUNK
            )
            score = 0
            score += max(0, 4 - abs(objects_off - 0x10) // 8)
            score += max(
                0,
                8
                - abs(
                    counter_off - min(objects_off + 8, FUOBJECTARRAY_COUNTER_SCAN_MAX)
                ),
            )
            score += 2 if max_elements >= num_elements else 0
            score += 2 if max_chunks >= num_chunks else 0
            score += 2 if num_chunks == expected_chunks else 1
            score += 1 if max_elements else 0
            score += 1 if max_chunks else 0
            score += FUOBJECTARRAY_LAYOUT_BONUSES.get((objects_off, counter_off), 0)

            candidate = {
                "layout": "scored",
                "base_addr": base_addr,
                "objects_ptr": objects_ptr,
                "objects_off": objects_off,
                "max_elements": max_elements,
                "num_elements": num_elements,
                "max_chunks": max_chunks,
                "num_chunks": num_chunks,
                "counter_off": counter_off,
                "score": score,
            }
            if score > best_score:
                best_score = score
                best = candidate

    return best

def _page_align(value: int) -> int:
    return value & ~(PAGE_SIZE - 1)

def _iter_fuobjectarray_counter_clusters(data: bytes):
    usable = len(data) & ~0x3
    if usable < 16:
        return

    words = memoryview(data)[:usable].cast("I")
    max_index = len(words) - 3
    for idx in range(max_index):
        num_elements = int(words[idx + 1])
        if not (GOBJECTS_BRUTE_MIN_OBJECT_COUNT <= num_elements <= 5_000_000):
            continue

        max_elements = int(words[idx + 0])
        if max_elements and (max_elements < num_elements or max_elements > 16_000_000):
            continue

        max_chunks = int(words[idx + 2])
        num_chunks = int(words[idx + 3])
        if not (1 <= num_chunks <= 0x4000):
            continue
        if max_chunks and (max_chunks < num_chunks or max_chunks > 0x4000):
            continue

        expected_chunks = max(
            1, (num_elements + OBJECTS_PER_CHUNK - 1) // OBJECTS_PER_CHUNK
        )
        if num_chunks < expected_chunks:
            continue
        if max_chunks and max_chunks < expected_chunks:
            continue

        yield idx * 4

def _enumerate_fuobjectarray_candidates(
    handle: int,
    ranges: List[Tuple[int, int]],
    module_base: int,
    module_end: int,
    deadline: float,
) -> List[Dict[str, int]]:
    candidates: Dict[Tuple[int, int, int, int, int], Dict[str, int]] = {}
    counter_offsets = tuple(range(0, FUOBJECTARRAY_COUNTER_SCAN_MAX + 1, 4))

    for start, end in ranges:
        if _time.monotonic() > deadline:
            break
        data = read_bytes(handle, start, end - start)
        if len(data) < FUOBJECTARRAY_SEARCH_BYTES:
            continue

        for cluster_rel in _iter_fuobjectarray_counter_clusters(data):
            if (cluster_rel & 0x1FF) == 0 and _time.monotonic() > deadline:
                break

            for counter_off in counter_offsets:
                if cluster_rel < counter_off:
                    continue
                base_rel = cluster_rel - counter_off
                if base_rel & 0x7:
                    continue
                if base_rel + FUOBJECTARRAY_SEARCH_BYTES > len(data):
                    continue

                base_addr = start + base_rel
                probe = _probe_fuobjectarray_candidate_bytes(
                    data[base_rel : base_rel + FUOBJECTARRAY_SEARCH_BYTES],
                    base_addr=base_addr,
                    module_base=module_base,
                    module_end=module_end,
                )
                if probe is None:
                    continue

                shape_key = (
                    probe["objects_ptr"],
                    probe["max_elements"],
                    probe["num_elements"],
                    probe["max_chunks"],
                    probe["num_chunks"],
                )
                current = candidates.get(shape_key)
                if current is None:
                    candidates[shape_key] = probe
                    continue
                if probe["score"] > current["score"]:
                    candidates[shape_key] = probe
                    continue
                if (
                    probe["score"] == current["score"]
                    and probe["base_addr"] < current["base_addr"]
                ):
                    candidates[shape_key] = probe

    ordered = sorted(
        candidates.values(),
        key=lambda item: (
            item["score"],
            item["num_elements"],
            item["objects_off"],
            -item["base_addr"],
        ),
        reverse=True,
    )
    return ordered[:FUOBJECTARRAY_CANDIDATE_LIMIT]

UOBJECT_VTABLE = 0x00
UOBJECT_FLAGS = 0x08
UOBJECT_INDEX = 0x0C
UOBJECT_CLASS = 0x10
UOBJECT_NAME = 0x18
UOBJECT_OUTER = 0x20

FUOBJECTARRAY_OBJECTS_OFFSET = 0x00
FUOBJECTARRAY_NUMELEMENTS_CANDIDATES = [0x14, 0x0C, 0x18, 0x08, 0x10]

GOBJECTS_BRUTE_MIN_OBJECT_COUNT = 1000
_gobjects_brute_cache: Dict[int, Tuple[int, int]] = {}

def _gobject_item_object_ptr(
    handle: int,
    gobjects_ptr: int,
    index: int,
    item_size: int,
) -> int:
    objects_ptr = get_gobjects_objects_ptr(handle, gobjects_ptr)
    if not objects_ptr:
        return 0
    chunk_idx = index // OBJECTS_PER_CHUNK
    within_idx = index % OBJECTS_PER_CHUNK
    chunk_base = read_uint64(handle, objects_ptr + chunk_idx * 8)
    if not chunk_base:
        return 0
    return read_uint64(handle, chunk_base + within_idx * item_size)

def probe_gobjects_item_size(handle: int, gobjects_ptr: int) -> int:
    best_size = 0
    best_valid = -1
    for item_size in (
        FUOBJECTITEM_SIZE_NORMAL,
        FUOBJECTITEM_SIZE_STATS,
        FUOBJECTITEM_SIZE_UE5,
        FUOBJECTITEM_SIZE_LEGACY,
    ):
        valid = 0
        for i in range(10):
            obj_ptr = _gobject_item_object_ptr(handle, gobjects_ptr, i, item_size)
            if not obj_ptr or not _plausible_ue_ptr64(obj_ptr):
                continue
            vtable = read_uint64(handle, obj_ptr + UOBJECT_VTABLE)
            if _plausible_ue_ptr64(vtable):
                valid += 1
        if valid > best_valid:
            best_valid = valid
            best_size = item_size
    if best_valid <= 3:
        return 0
    return best_size

def find_gobjects_brute(handle: int, base: int, size: int) -> Tuple[int, int]:
    if base in _gobjects_brute_cache:
        return _gobjects_brute_cache[base]

    ranges = get_pe_rdata_data_scan_ranges(handle, base)
    if not ranges:
        _gobjects_brute_cache[base] = (0, 0)
        return 0, 0

    from src.core.debug import dbg
    from src.core.memory import (
        USE_DRIVER,
        snapshot_mark,
        snapshot_memory_ranges,
        snapshot_restore_mark,
    )

    global _gobjects_brute_last_meta
    _gobjects_brute_last_meta = {
        "timed_out": 0,
        "candidate_count": 0,
        "candidate_cap_hit": 0,
        "tolerant_requested": 1,
        "tolerant_supported": 0,
    }

    tolerant_supported = False
    if USE_DRIVER:
        from src.core.driver import supports_tolerant_bulk_read

        tolerant_supported = supports_tolerant_bulk_read()
        _gobjects_brute_last_meta["tolerant_supported"] = 1 if tolerant_supported else 0

    dbg("find_gobjects_brute: %d scan ranges from PE sections", len(ranges))
    for sec_start, sec_end in ranges:
        dbg(
            "  section 0x%X..0x%X (%d KB)",
            sec_start,
            sec_end,
            (sec_end - sec_start) // 1024,
        )
    if USE_DRIVER:
        dbg(
            "find_gobjects_brute: tolerant bulk scan path %s",
            "ENABLED"
            if tolerant_supported
            else "UNAVAILABLE (old driver fallback to strict reads)",
        )

    snap_mark = snapshot_mark()
    try:
        stats = snapshot_memory_ranges(handle, ranges, tolerant=True)
        for stat in stats:
            dbg(
                "find_gobjects_brute: section 0x%X read OK (%d KB, %d%% non-zero, %s)",
                stat["start"],
                stat["size"] // 1024,
                stat["nonzero_pct"],
                "tolerant" if stat.get("tolerant") else "strict-fallback",
            )
        result = _find_gobjects_brute_inner_buffered(handle, base, size, ranges)
    finally:
        snapshot_restore_mark(snap_mark)

    _gobjects_brute_cache[base] = result
    return result

def _find_gobjects_brute_inner(handle, base, size, ranges):
    from src.core.debug import dbg

    best_key: Optional[Tuple[int, int, int, int]] = None
    best_pair: Optional[Tuple[int, int]] = None
    t0 = _time.monotonic()
    candidates_checked = 0
    consecutive_read_fails = 0
    MAX_CONSECUTIVE_FAILS = 200
    module_end = base + size

    for start, end in ranges:
        addr = start
        if addr % 8:
            addr += 8 - (addr % 8)
        _timed_out = False
        while addr < end:
            candidates_checked += 1
            if (candidates_checked & 0x3F) == 0:
                elapsed = _time.monotonic() - t0
                if elapsed > BRUTE_TIMEOUT:
                    dbg(
                        "_find_gobjects_brute_inner: TIMEOUT after %.1fs "
                        "(%d candidates checked)",
                        elapsed,
                        candidates_checked,
                    )
                    _timed_out = True
                    break

            ok_chunks, chunks_ptr = _try_read_qword(handle, addr)
            if not ok_chunks:
                addr += 8
                continue
            if not _plausible_ue_ptr64(chunks_ptr):
                addr += 8
                continue
            ok_chunk0, chunk0 = _try_read_qword(handle, chunks_ptr)
            if not ok_chunk0:
                consecutive_read_fails += 1
                if consecutive_read_fails >= MAX_CONSECUTIVE_FAILS:
                    dbg(
                        "_find_gobjects_brute_inner: %d consecutive read "
                        "failures, skipping rest of section",
                        consecutive_read_fails,
                    )
                    break
                addr += 8
                continue
            consecutive_read_fails = 0
            if not _plausible_runtime_heap_ptr(chunk0, base, module_end):
                addr += 8
                continue

            shape = _probe_fuobjectarray_shape(handle, addr)
            if shape is None:
                addr += 8
                continue

            if shape["num_chunks"] > 1 and shape["num_elements"] > OBJECTS_PER_CHUNK:
                ok_chunk1, chunk1 = _try_read_qword(handle, chunks_ptr + 8)
                if not ok_chunk1 or not _plausible_runtime_heap_ptr(
                    chunk1, base, module_end
                ):
                    addr += 8
                    continue

            for stride in (
                FUOBJECTITEM_SIZE_NORMAL,
                FUOBJECTITEM_SIZE_STATS,
                FUOBJECTITEM_SIZE_UE5,
                FUOBJECTITEM_SIZE_LEGACY,
            ):
                valid = 0
                readable_slots = 0
                for slot in range(8):
                    ok_obj, obj_ptr = _try_read_qword(handle, chunk0 + slot * stride)
                    if not ok_obj:
                        continue
                    readable_slots += 1
                    if not _plausible_runtime_heap_ptr(obj_ptr, base, module_end):
                        continue
                    ok_vtable, vtable = _try_read_qword(
                        handle, obj_ptr + UOBJECT_VTABLE
                    )
                    if ok_vtable and _plausible_module_ptr(vtable, base, module_end):
                        valid += 1
                if readable_slots < 4:
                    continue
                if valid < 6:
                    continue

                obj_count = shape["num_elements"]
                if obj_count < GOBJECTS_BRUTE_MIN_OBJECT_COUNT:
                    logger.debug(
                        f"GObjects brute rejected 0x{addr:X} — object count too low ({obj_count})"
                    )
                    continue

                key = (obj_count, valid, -stride, addr)
                if best_key is None or key > best_key:
                    best_key = key
                    best_pair = (addr, stride)
            addr += 8

        if _timed_out:
            break

    elapsed = _time.monotonic() - t0
    if best_pair is None:
        dbg(
            "_find_gobjects_brute_inner: no valid GObjects found "
            "(%.1fs, %d candidates)",
            elapsed,
            candidates_checked,
        )
        return 0, 0

    oc, vv, _, winner_addr = best_key
    winner_stride = best_pair[1]
    dbg(
        "_find_gobjects_brute_inner: found 0x%X stride=%d valid=%d/8 "
        "count=%d (%.1fs, %d candidates)",
        winner_addr,
        winner_stride,
        vv,
        oc,
        elapsed,
        candidates_checked,
    )
    return best_pair

def _find_gobjects_brute_inner_buffered(handle, base, size, ranges):
    from src.core.debug import dbg
    from src.core.memory import prefetch_memory_pages

    global _gobjects_brute_last_meta
    t0 = _time.monotonic()
    module_end = base + size
    deadline = t0 + BRUTE_TIMEOUT

    candidates = _enumerate_fuobjectarray_candidates(
        handle, ranges, base, module_end, deadline
    )
    _gobjects_brute_last_meta["candidate_count"] = len(candidates)
    _gobjects_brute_last_meta["candidate_cap_hit"] = (
        1 if len(candidates) >= FUOBJECTARRAY_CANDIDATE_LIMIT else 0
    )
    if _time.monotonic() > deadline:
        _gobjects_brute_last_meta["timed_out"] = 1
        elapsed = _time.monotonic() - t0
        dbg(
            "_find_gobjects_brute_inner: TIMEOUT after %.1fs (%d candidates checked)",
            elapsed,
            len(candidates),
        )
        return 0, 0

    dbg("_find_gobjects_brute_inner: %d local structural candidates", len(candidates))
    if not candidates:
        elapsed = _time.monotonic() - t0
        dbg(
            "_find_gobjects_brute_inner: no valid GObjects found (%.1fs, 0 candidates)",
            elapsed,
        )
        return 0, 0

    if len(candidates) >= FUOBJECTARRAY_CANDIDATE_LIMIT:
        dbg(
            "_find_gobjects_brute_inner: candidate cap reached (%d); validation may not cover the full section",
            FUOBJECTARRAY_CANDIDATE_LIMIT,
        )

    chunk_table_pages: List[int] = []
    for candidate in candidates:
        chunk_table_pages.append(_page_align(candidate["objects_ptr"]))
        if candidate["num_chunks"] > 1:
            chunk_table_pages.append(_page_align(candidate["objects_ptr"] + 8))
    prefetch_memory_pages(handle, chunk_table_pages, tolerant=True)

    stage2: List[Dict[str, int]] = []
    for candidate in candidates:
        if _time.monotonic() > deadline:
            break
        ok_chunk0, chunk0 = _try_read_qword(handle, candidate["objects_ptr"])
        if not ok_chunk0 or not _plausible_runtime_heap_ptr(chunk0, base, module_end):
            continue
        candidate["chunk0"] = chunk0

        if (
            candidate["num_chunks"] > 1
            and candidate["num_elements"] > OBJECTS_PER_CHUNK
        ):
            ok_chunk1, chunk1 = _try_read_qword(handle, candidate["objects_ptr"] + 8)
            if not ok_chunk1 or not _plausible_runtime_heap_ptr(
                chunk1, base, module_end
            ):
                continue
            candidate["chunk1"] = chunk1
        stage2.append(candidate)

    if not stage2:
        elapsed = _time.monotonic() - t0
        dbg(
            "_find_gobjects_brute_inner: no valid GObjects found (%.1fs, %d candidates)",
            elapsed,
            len(candidates),
        )
        return 0, 0

    chunk_pages: List[int] = []
    for candidate in stage2:
        chunk_pages.append(_page_align(candidate["chunk0"]))
        if "chunk1" in candidate:
            chunk_pages.append(_page_align(candidate["chunk1"]))
    prefetch_memory_pages(handle, chunk_pages, tolerant=True)

    object_pages: List[int] = []
    for candidate in stage2:
        for stride in (
            FUOBJECTITEM_SIZE_NORMAL,
            FUOBJECTITEM_SIZE_STATS,
            FUOBJECTITEM_SIZE_UE5,
            FUOBJECTITEM_SIZE_LEGACY,
        ):
            for slot in range(FUOBJECTARRAY_SAMPLE_SLOTS):
                ok_obj, obj_ptr = _try_read_qword(
                    handle, candidate["chunk0"] + slot * stride
                )
                if ok_obj and _plausible_runtime_heap_ptr(obj_ptr, base, module_end):
                    object_pages.append(_page_align(obj_ptr))
    prefetch_memory_pages(handle, object_pages, tolerant=True)

    best_entry: Optional[Dict[str, int]] = None
    for candidate in stage2:
        if _time.monotonic() > deadline:
            _gobjects_brute_last_meta["timed_out"] = 1
            break
        for stride in (
            FUOBJECTITEM_SIZE_NORMAL,
            FUOBJECTITEM_SIZE_STATS,
            FUOBJECTITEM_SIZE_UE5,
            FUOBJECTITEM_SIZE_LEGACY,
        ):
            valid = 0
            readable_slots = 0
            classish = 0
            nameish = 0
            indexish = 0

            for slot in range(FUOBJECTARRAY_SAMPLE_SLOTS):
                ok_obj, obj_ptr = _try_read_qword(
                    handle, candidate["chunk0"] + slot * stride
                )
                if not ok_obj:
                    continue
                readable_slots += 1
                if not _plausible_runtime_heap_ptr(obj_ptr, base, module_end):
                    continue

                ok_vtable, vtable = _try_read_qword(handle, obj_ptr + UOBJECT_VTABLE)
                if ok_vtable and _plausible_module_ptr(vtable, base, module_end):
                    valid += 1

                ok_class, class_ptr = _try_read_qword(handle, obj_ptr + UOBJECT_CLASS)
                if ok_class and _plausible_runtime_heap_ptr(
                    class_ptr, base, module_end
                ):
                    classish += 1

                name_idx = read_int32(handle, obj_ptr + UOBJECT_NAME)
                if 0 <= name_idx <= 20_000_000:
                    nameish += 1

                internal_idx = read_int32(handle, obj_ptr + UOBJECT_INDEX)
                if -1 <= internal_idx <= candidate["num_elements"] + 0x1000:
                    indexish += 1

            if readable_slots < 6 or valid < 6:
                continue

            entry = {
                "addr": candidate["base_addr"],
                "stride": stride,
                "objects_off": candidate["objects_off"],
                "score": candidate["score"] * 8
                + valid * 10
                + classish * 4
                + nameish * 3
                + indexish * 2,
                "valid": valid,
                "num_elements": candidate["num_elements"],
            }
            if best_entry is None or (
                entry["score"],
                entry["num_elements"],
                entry["valid"],
                -entry["stride"],
                -entry["addr"],
            ) > (
                best_entry["score"],
                best_entry["num_elements"],
                best_entry["valid"],
                -best_entry["stride"],
                -best_entry["addr"],
            ):
                best_entry = entry

    elapsed = _time.monotonic() - t0
    if best_entry is None:
        dbg(
            "_find_gobjects_brute_inner: no valid GObjects found (%.1fs, %d candidates)",
            elapsed,
            len(candidates),
        )
        return 0, 0

    dbg(
        "_find_gobjects_brute_inner: found 0x%X stride=%d valid=%d/%d count=%d (%.1fs, %d candidates)",
        best_entry["addr"],
        best_entry["stride"],
        best_entry["valid"],
        FUOBJECTARRAY_SAMPLE_SLOTS,
        best_entry["num_elements"],
        elapsed,
        len(candidates),
    )
    _gobjects_objects_offset[best_entry["addr"]] = best_entry["objects_off"]
    return best_entry["addr"], best_entry["stride"]

def _looks_coherent_gobject_class_name(name: str) -> bool:
    if not name or len(name) > 96:
        return False
    if name in _KNOWN_GOBJECT_CLASS_NAMES:
        return True
    return any(
        name.endswith(suffix)
        for suffix in ("Class", "Struct", "Function", "Property", "Package", "World")
    )

def find_gobjects_names_seeded(
    handle: int,
    module_base: int,
    module_size: int,
    gnames_ptr: int,
    *,
    ue_version: str = "4.27",
    case_preserving: Optional[bool] = None,
    legacy_names: bool = False,
) -> Tuple[int, int]:
    if not gnames_ptr:
        return 0, 0

    ranges = get_pe_rdata_data_scan_ranges(handle, module_base)
    if not ranges:
        return 0, 0

    from src.core.memory import (
        snapshot_mark,
        snapshot_memory_ranges,
        snapshot_restore_mark,
    )

    deadline = _time.monotonic() + min(BRUTE_TIMEOUT, 20.0)
    best_entry: Optional[Dict[str, int]] = None
    snap_mark = snapshot_mark()
    try:
        snapshot_memory_ranges(handle, ranges, tolerant=True)
        candidates = _enumerate_fuobjectarray_candidates(
            handle,
            ranges,
            module_base,
            module_base + module_size,
            deadline,
        )
        for candidate in candidates[:256]:
            if _time.monotonic() > deadline:
                break
            addr = candidate["base_addr"]
            _gobjects_objects_offset[addr] = candidate["objects_off"]
            item_size = probe_gobjects_item_size(handle, addr)
            if not item_size:
                continue
            if not validate_gobjects(
                handle,
                addr,
                gnames_ptr=gnames_ptr,
                ue_version=ue_version,
                case_preserving=case_preserving,
                item_size=item_size,
                legacy_names=legacy_names,
            ):
                continue

            entry = {
                "addr": addr,
                "stride": item_size,
                "score": candidate["score"],
                "objects_off": candidate["objects_off"],
            }
            if best_entry is None or (
                entry["score"],
                -entry["stride"],
                -entry["addr"],
            ) > (
                best_entry["score"],
                -best_entry["stride"],
                -best_entry["addr"],
            ):
                best_entry = entry
    finally:
        snapshot_restore_mark(snap_mark)

    if best_entry is None:
        return 0, 0

    _gobjects_objects_offset[best_entry["addr"]] = best_entry["objects_off"]
    return best_entry["addr"], best_entry["stride"]

def find_gobjects(
    handle: int,
    module_base: int,
    module_size: int,
    ue_version: str = "4.27",
    process_name: Optional[str] = None,
    diag=None,
    gnames_ptr: int = 0,
    case_preserving: Optional[bool] = None,
    legacy_names: bool = False,
) -> Tuple[int, int]:
    _gobjects_resolution_meta.clear()
    override = load_game_offsets_override(process_name)
    if override is not None:
        _ogn, ogo, _ogw, item_stride, _legacy = override
        override_addr = module_base + ogo
        _gobjects_objects_offset[override_addr] = FUOBJECTARRAY_OBJECTS_OFFSET
        if validate_gobjects(
            handle,
            override_addr,
            gnames_ptr=gnames_ptr,
            ue_version=ue_version,
            case_preserving=case_preserving,
            item_size=item_stride,
            legacy_names=legacy_names,
        ):
            _set_gobjects_resolution_meta(
                address=override_addr,
                item_size=item_stride,
                method="offsets_override",
                objects_offset=FUOBJECTARRAY_OBJECTS_OFFSET,
            )
            logger.debug(
                f"GObjects from OffsetsInfo.json: +0x{ogo:X} stride={item_stride} "
                f"(validated)"
            )
            if diag:
                diag.info(
                    f"Using validated cached offset +0x{ogo:X} from OffsetsInfo.json",
                    "GObjects",
                )
            return override_addr, item_stride

        logger.warning(
            "Cached GObjects override +0x%X failed validation; continuing with live scan",
            ogo,
        )
        _gobjects_objects_offset.pop(override_addr, None)
        if process_name:
            try:
                from src.engines.ue.offsets_override import mark_offsets_stale

                mark_offsets_stale(process_name)
            except Exception:
                pass
        if diag:
            diag.warn(
                f"Cached offset +0x{ogo:X} failed validation; rescanning live",
                "GObjects",
            )

    votes: Counter = Counter()
    sig_details = []

    from src.core.memory import USE_DRIVER as _USE_DRV

    _bulk_ctx = None
    if _USE_DRV:
        from src.core.driver import bulk_read_mode as _brm

        _bulk_ctx = _brm()
        _bulk_ctx.__enter__()

    import struct as _struct
    from src.core.debug import dbg

    from src.core.pe_parser import get_pe_text_scan_ranges as _get_text_ranges

    _text_ranges = _get_text_ranges(handle, module_base)
    if not _text_ranges:
        _text_ranges = [(module_base, module_base + module_size)]

    _text_total = sum(end - start for start, end in _text_ranges)
    dbg(
        "find_gobjects: reading .text section 0x%X + %d MB for AOB cache (vs full %d MB)...",
        _text_ranges[0][0] if _text_ranges else module_base,
        _text_total // (1024 * 1024),
        module_size // (1024 * 1024),
    )

    _text_sections: List[Tuple[int, bytes]] = []
    if _USE_DRV:
        from src.core.driver import read_memory_kernel_tolerant as _rmk
        from src.core.memory import TARGET_PID as _TPID

        for _start, _end in _text_ranges:
            _data = _rmk(_TPID, _start, _end - _start)
            if _data:
                _text_sections.append((_start, _data))
    else:
        for _start, _end in _text_ranges:
            _data = read_bytes(handle, _start, _end - _start)
            if _data:
                _text_sections.append((_start, _data))

    module_data = b"".join(data for _, data in _text_sections)
    _first_section_base = _text_sections[0][0] if _text_sections else module_base

    _have_data = module_data and len(module_data) > 0x1000
    if _have_data:
        _sample_pages = 256
        _page_size = max(len(module_data) // _sample_pages, 1)
        _nonzero = 0
        for _si in range(_sample_pages):
            _off = _si * _page_size
            if _off + 8 <= len(module_data):
                if module_data[_off : _off + 8] != b"\x00" * 8:
                    _nonzero += 1
        _readable_pct = _nonzero * 100 // _sample_pages
        dbg("find_gobjects: module data readability: %d%% non-zero", _readable_pct)
        min_readable_pct = 30 if _USE_DRV else 5
        if _readable_pct < min_readable_pct:
            dbg(
                "find_gobjects: <%d%% readable — skipping AOB in favor of brute force",
                min_readable_pct,
            )
            _have_data = False

    if _have_data:
        from src.core.scanner import _parse_pattern, _build_prefix, _match_full

        for sig in sorted(GOBJECTS_SIGS, key=lambda s: s.priority):
            pat_bytes, mask = _parse_pattern(sig.pattern)
            pat_len = len(pat_bytes)
            if pat_len == 0:
                continue
            prefix = _build_prefix(pat_bytes, mask)
            hits = []
            search_end = len(module_data) - pat_len + 1
            i = 0
            while i < search_end and len(hits) < 20:
                pos = module_data.find(prefix, i, len(module_data))
                if pos == -1:
                    break
                if pos < search_end and _match_full(
                    module_data, pos, pat_bytes, mask, pat_len
                ):
                    hits.append(_first_section_base + pos)
                i = pos + 1

            resolved = []
            for hit in hits:
                local_off = hit - _first_section_base
                disp_off = local_off + sig.disp_offset
                if disp_off + 4 <= len(module_data):
                    disp = _struct.unpack_from("<i", module_data, disp_off)[0]
                    target = hit + sig.instruction_size + disp
                    if target > module_base:
                        votes[target] += 1
                        resolved.append(target)

            detail = f"{len(hits)} hit(s), {len(resolved)} resolved"
            sig_details.append((sig.name, len(hits), len(resolved)))
            if diag:
                diag.tried("GObjects", sig.name, detail)

        dbg("find_gobjects: local AOB scan done, %d unique candidates", len(votes))
    else:
        dbg(
            "find_gobjects: module read failed/unreadable (%d bytes), skipping AOB",
            len(module_data) if module_data else 0,
        )

    module_data = None

    if _bulk_ctx is not None:
        _bulk_ctx.__exit__(None, None, None)

    if not votes and _USE_DRV:
        dbg("find_gobjects: cached AOB had no votes; retrying live scan_pattern pass")
        if diag:
            diag.info(
                "Cached module AOB yielded no votes in kernel mode; retrying live pattern scan",
                "GObjects",
            )
        _fallback_bulk = None
        try:
            from src.core.driver import bulk_read_mode as _brm

            _fallback_bulk = _brm()
            _fallback_bulk.__enter__()
            for sig in sorted(GOBJECTS_SIGS, key=lambda s: s.priority):
                hits = scan_pattern(
                    handle,
                    module_base,
                    module_size,
                    sig.pattern,
                    max_results=20,
                )
                resolved = []
                for hit in hits:
                    target = resolve_rip(
                        handle, hit, sig.disp_offset, sig.instruction_size
                    )
                    if target is None or target <= module_base:
                        continue
                    votes[target] += 1
                    resolved.append(target)

                detail = f"{len(hits)} hit(s), {len(resolved)} resolved"
                sig_details.append((f"{sig.name}_live", len(hits), len(resolved)))
                if diag:
                    diag.tried("GObjects", f"{sig.name}_live", detail)
        finally:
            if _fallback_bulk is not None:
                _fallback_bulk.__exit__(None, None, None)

    if votes:
        for addr, vote_count in votes.most_common():
            raw = read_bytes(handle, addr, 0x30)
            if raw and len(raw) >= 0x28:
                hexdump = " ".join(f"{b:02X}" for b in raw[:0x30])
                i32_vals = [
                    struct.unpack_from("<i", raw, o)[0] for o in range(0, 0x28, 4)
                ]
                i64_vals = [
                    struct.unpack_from("<q", raw, o)[0] for o in range(0, 0x28, 8)
                ]
                dbg("GObjects struct raw at +0x%X (%d votes):", addr, vote_count)
                dbg("  hex: %s", hexdump)
                dbg("  i32: %s", i32_vals)
                dbg("  i64: %s", i64_vals)

            shape = _probe_fuobjectarray_shape(handle, addr)
            if shape is not None:
                _gobjects_objects_offset[addr] = shape["objects_off"]
            else:
                _gobjects_objects_offset.setdefault(addr, FUOBJECTARRAY_OBJECTS_OFFSET)
            item_size = probe_gobjects_item_size(handle, addr)
            if item_size:
                is_valid = validate_gobjects(
                    handle,
                    addr,
                    gnames_ptr=gnames_ptr,
                    ue_version=ue_version,
                    case_preserving=case_preserving,
                    item_size=item_size,
                    legacy_names=legacy_names,
                )
                if is_valid:
                    if diag:
                        diag.passed(
                            "GObjects",
                            "probe_item_size",
                            f"addr=+0x{addr - module_base:X} stride={item_size} ({vote_count} votes)",
                        )
                        diag.set_confidence(
                            "GObjects",
                            min(1.0, vote_count / 3),
                            f"{vote_count} signature votes, stride={item_size}",
                        )
                    _set_gobjects_resolution_meta(
                        address=addr,
                        item_size=item_size,
                        method="signature_probe",
                        objects_offset=get_gobjects_objects_offset(addr),
                    )
                    return addr, item_size
                if diag:
                    diag.tried(
                        "GObjects",
                        "validate_candidate",
                        f"addr=+0x{addr - module_base:X} rejected after structural/name validation",
                    )
            else:
                if diag:
                    diag.tried(
                        "GObjects",
                        "probe_item_size",
                        f"addr=+0x{addr - module_base:X} rejected (structure validation failed)",
                    )

    total_hits = sum(d[1] for d in sig_details)
    if diag:
        if total_hits == 0:
            diag.failed(
                "GObjects",
                "AOB signatures",
                f"0 hits across {len(GOBJECTS_SIGS)} patterns — "
                f"this game's code patterns don't match any known UE build",
            )
        else:
            diag.failed(
                "GObjects",
                "AOB validation",
                f"{total_hits} raw hits but none passed structure validation",
            )

    logger.debug("GObjects AOB failed, trying brute force...")
    if diag:
        diag.tried("GObjects", "brute_force_scan", "Scanning .rdata/.data sections")

    result = find_gobjects_brute(handle, module_base, module_size)
    if result[0]:
        if diag:
            diag.passed(
                "GObjects",
                "brute_force_scan",
                f"Found at +0x{result[0] - module_base:X} stride={result[1]}",
            )
            diag.set_confidence(
                "GObjects", 0.6, "found via brute-force (no signature match)"
            )
        _set_gobjects_resolution_meta(
            address=result[0],
            item_size=result[1],
            method="structural_scan",
            objects_offset=get_gobjects_objects_offset(result[0]),
        )
    else:
        fallback_gnames = gnames_ptr
        fallback_cp = case_preserving
        fallback_legacy = legacy_names
        if not fallback_gnames:
            from src.engines.ue.gnames import (
                find_gnames,
                get_last_gnames_resolution_meta,
            )

            fallback_gnames, fallback_legacy = find_gnames(
                handle,
                module_base,
                module_size,
                ue_version,
                gobjects_hint=0,
                process_name=process_name,
            )
            gnames_meta = get_last_gnames_resolution_meta()
            if gnames_meta:
                fallback_cp = gnames_meta.get("case_preserving")

        if fallback_gnames:
            names_seeded = find_gobjects_names_seeded(
                handle,
                module_base,
                module_size,
                fallback_gnames,
                ue_version=ue_version,
                case_preserving=fallback_cp,
                legacy_names=fallback_legacy,
            )
            if names_seeded[0]:
                if diag:
                    diag.passed(
                        "GObjects",
                        "names_seeded_validation",
                        f"Found at +0x{names_seeded[0] - module_base:X} stride={names_seeded[1]} using recovered names",
                    )
                    diag.set_confidence(
                        "GObjects",
                        0.7,
                        "validated structural candidate using recovered GNames",
                    )
                _set_gobjects_resolution_meta(
                    address=names_seeded[0],
                    item_size=names_seeded[1],
                    method="names_seeded_structural",
                    objects_offset=get_gobjects_objects_offset(names_seeded[0]),
                )
                return names_seeded

        if diag:
            if _gobjects_brute_last_meta.get("timed_out"):
                detail = "Timed out while scoring local FUObjectArray candidates"
                if _gobjects_brute_last_meta.get("candidate_cap_hit"):
                    detail += " (candidate cap reached)"
                diag.failed("GObjects", "brute_force_scan", detail)
            else:
                diag.failed(
                    "GObjects",
                    "brute_force_scan",
                    "No valid FUObjectArray found in .rdata/.data sections",
                )
            diag.set_confidence("GObjects", 0.0, "all methods exhausted")
    return result

def get_object_count(handle: int, gobjects_ptr: int) -> int:
    return _try_read_num_elements(handle, gobjects_ptr) or 0

def _try_read_num_elements(handle: int, base: int) -> int:
    for off in FUOBJECTARRAY_NUMELEMENTS_CANDIDATES:
        val = read_int32(handle, base + off)
        if val == 0:
            continue
        if 1 <= val <= 5_000_000:
            return val
    return 0

def read_uobject(
    handle: int,
    gobjects_ptr: int,
    index: int,
    item_size: int = FUOBJECTITEM_SIZE_NORMAL,
) -> Optional[Dict]:
    objects_ptr = get_gobjects_objects_ptr(handle, gobjects_ptr)
    if not objects_ptr:
        return None

    chunk_idx = index // OBJECTS_PER_CHUNK
    within_idx = index % OBJECTS_PER_CHUNK

    chunk_base = read_uint64(handle, objects_ptr + chunk_idx * 8)
    if not chunk_base:
        return None

    item_addr = chunk_base + within_idx * item_size
    obj_ptr = read_uint64(handle, item_addr)
    if not obj_ptr:
        return None

    flags = read_int32(handle, obj_ptr + UOBJECT_FLAGS)
    internal_index = read_int32(handle, obj_ptr + UOBJECT_INDEX)
    class_ptr = read_uint64(handle, obj_ptr + UOBJECT_CLASS)
    name_index = read_uint32(handle, obj_ptr + UOBJECT_NAME)
    outer_ptr = read_uint64(handle, obj_ptr + UOBJECT_OUTER)

    return {
        "address": obj_ptr,
        "flags": flags,
        "internal_index": internal_index,
        "class_ptr": class_ptr,
        "name_index": name_index,
        "outer_ptr": outer_ptr,
    }

def get_object_name(
    handle: int,
    gobjects_ptr: int,
    gnames_ptr: int,
    index: int,
    ue_version: str = "4.27",
    case_preserving: bool = False,
    item_size: int = FUOBJECTITEM_SIZE_NORMAL,
) -> str:
    obj = read_uobject(handle, gobjects_ptr, index, item_size)
    if not obj:
        return ""

    return read_fname(
        handle, gnames_ptr, obj["name_index"], ue_version, case_preserving
    )

def get_object_class_name(
    handle: int,
    gnames_ptr: int,
    class_ptr: int,
    ue_version: str = "4.27",
    case_preserving: bool = False,
) -> str:
    if not class_ptr:
        return ""

    class_name_index = read_uint32(handle, class_ptr + UOBJECT_NAME)
    return read_fname(handle, gnames_ptr, class_name_index, ue_version, case_preserving)

def get_object_full_name(
    handle: int,
    gobjects_ptr: int,
    gnames_ptr: int,
    index: int,
    ue_version: str = "4.27",
    case_preserving: bool = False,
    item_size: int = FUOBJECTITEM_SIZE_NORMAL,
) -> str:
    obj = read_uobject(handle, gobjects_ptr, index, item_size)
    if not obj:
        return ""

    obj_name = read_fname(
        handle, gnames_ptr, obj["name_index"], ue_version, case_preserving
    )
    class_name = get_object_class_name(
        handle, gnames_ptr, obj["class_ptr"], ue_version, case_preserving
    )

    outers = []
    current_outer = obj["outer_ptr"]
    max_depth = 20
    while current_outer and max_depth > 0:
        outer_name_idx = read_uint32(handle, current_outer + UOBJECT_NAME)
        outer_name = read_fname(
            handle, gnames_ptr, outer_name_idx, ue_version, case_preserving
        )
        if outer_name:
            outers.append(outer_name)
        current_outer = read_uint64(handle, current_outer + UOBJECT_OUTER)
        max_depth -= 1

    outers.reverse()
    path = ".".join(outers + [obj_name]) if outers else obj_name
    return f"{class_name} {path}" if class_name else path

def validate_gobjects(
    handle: int,
    gobjects_ptr: int,
    gnames_ptr: int = 0,
    ue_version: str = "4.27",
    case_preserving: Optional[bool] = False,
    item_size: int = FUOBJECTITEM_SIZE_NORMAL,
    legacy_names: bool = False,
) -> bool:
    count = get_object_count(handle, gobjects_ptr)
    if count <= 0:
        return False

    valid = 0
    valid_names = 0
    coherent_classes = 0
    class_name_cache: Dict[int, str] = {}
    for i in range(min(12, count)):
        obj = read_uobject(handle, gobjects_ptr, i, item_size)
        if not obj:
            continue
        if _plausible_ue_ptr64(obj["class_ptr"]):
            valid += 1
        if not gnames_ptr:
            continue

        obj_name = read_fname(
            handle,
            gnames_ptr,
            obj["name_index"],
            ue_version,
            case_preserving,
            legacy=legacy_names,
        )
        if obj_name and obj_name != "None":
            valid_names += 1

        class_ptr = obj["class_ptr"]
        if not class_ptr:
            continue
        class_name = class_name_cache.get(class_ptr)
        if class_name is None:
            class_name_index = read_uint32(handle, class_ptr + UOBJECT_NAME)
            class_name = read_fname(
                handle,
                gnames_ptr,
                class_name_index,
                ue_version,
                case_preserving,
                legacy=legacy_names,
            )
            class_name_cache[class_ptr] = class_name
        if _looks_coherent_gobject_class_name(class_name):
            coherent_classes += 1

    if not gnames_ptr:
        return valid >= 5
    return valid >= 5 and (valid_names >= 3 or coherent_classes >= 2)

def probe_item_size(
    handle: int,
    gobjects_ptr: int,
) -> int:
    sz = probe_gobjects_item_size(handle, gobjects_ptr)
    return sz if sz else FUOBJECTITEM_SIZE_NORMAL
