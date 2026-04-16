import json
import os
import re
from collections import defaultdict
from typing import Dict, Iterable, List, Optional, Set, Tuple


def _sanitize_identifier(name: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_]", "_", str(name or ""))
    if safe and safe[0].isdigit():
        safe = f"_{safe}"
    return safe or "Unknown"


def _split_full_name(full_name: str) -> Tuple[str, str]:
    full_name = str(full_name or "").replace("/Script/", "")
    if "." in full_name:
        package, short_name = full_name.split(".", 1)
        return package, short_name
    return "Global", full_name or "Unknown"


def _symbol_for_full_name(full_name: str) -> str:
    package, short_name = _split_full_name(full_name)
    return f"{_sanitize_identifier(package)}_{_sanitize_identifier(short_name)}"


def _package_symbol(package_name: str) -> str:
    return _sanitize_identifier(package_name or "Global")


def _load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return default


def has_v2_dump(dump_dir: str) -> bool:
    classes = _load_json(os.path.join(dump_dir, "ClassesInfoV2.json"), {})
    structs = _load_json(os.path.join(dump_dir, "StructsInfoV2.json"), {})
    return bool(classes.get("schema_version") == 2 or structs.get("schema_version") == 2)


def _load_v2_struct_entries(dump_dir: str) -> List[dict]:
    entries: List[dict] = []
    for filename in ("ClassesInfoV2.json", "StructsInfoV2.json"):
        payload = _load_json(os.path.join(dump_dir, filename), {})
        if payload.get("schema_version") == 2:
            entries.extend(payload.get("data", []) or [])
    return entries


def _load_legacy_enums(dump_dir: str) -> Dict[str, dict]:
    payload = _load_json(os.path.join(dump_dir, "EnumsInfo.json"), {})
    enums: Dict[str, dict] = {}
    for entry in payload.get("data", []) or []:
        if not entry:
            continue
        full_name, values = next(iter(entry.items()))
        package, short_name = _split_full_name(full_name)
        enums[full_name] = {
            "full_name": full_name,
            "package": package,
            "name": short_name,
            "symbol": _symbol_for_full_name(full_name),
            "values": list(values or []),
            "underlying": "uint8_t",
        }
    return enums


def _iter_type_refs(type_node: Optional[dict], *, context: str = "direct") -> Iterable[Tuple[str, str, str, Optional[str]]]:
    if not type_node:
        return
    kind = type_node.get("kind", "")
    full_name = type_node.get("full_name", "")
    if kind == "named_struct" and full_name:
        yield ("struct", full_name, context, None)
        return
    if kind == "enum" and full_name:
        enum_underlying = type_node.get("enum_underlying") or {}
        underlying = enum_underlying.get("signature_name") or enum_underlying.get("display_name")
        yield ("enum", full_name, context, underlying)
        return
    if kind in {"object", "class", "soft_object", "soft_class", "weak_object", "lazy_object", "object_ptr", "class_ptr", "interface", "field_path"}:
        yield from _iter_type_refs(type_node.get("pointee"), context="pointer")
        return
    if kind in {"array", "set"}:
        yield from _iter_type_refs(type_node.get("inner"), context="container")
        return
    if kind == "map":
        yield from _iter_type_refs(type_node.get("key"), context="container")
        yield from _iter_type_refs(type_node.get("value"), context="container")


def _tarjan_scc(graph: Dict[str, Set[str]]) -> List[List[str]]:
    index = 0
    stack: List[str] = []
    on_stack: Set[str] = set()
    indexes: Dict[str, int] = {}
    lowlinks: Dict[str, int] = {}
    components: List[List[str]] = []

    def strongconnect(node: str) -> None:
        nonlocal index
        indexes[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)

        for dep in graph.get(node, set()):
            if dep not in indexes:
                strongconnect(dep)
                lowlinks[node] = min(lowlinks[node], lowlinks[dep])
            elif dep in on_stack:
                lowlinks[node] = min(lowlinks[node], indexes[dep])

        if lowlinks[node] == indexes[node]:
            component: List[str] = []
            while stack:
                value = stack.pop()
                on_stack.discard(value)
                component.append(value)
                if value == node:
                    break
            components.append(sorted(component))

    for node in sorted(graph):
        if node not in indexes:
            strongconnect(node)

    return components


def _topological_components(graph: Dict[str, Set[str]]) -> Tuple[List[List[str]], Dict[str, int], Dict[int, Set[int]]]:
    components = _tarjan_scc(graph)
    component_index = {
        node: idx
        for idx, nodes in enumerate(components)
        for node in nodes
    }
    condensed: Dict[int, Set[int]] = defaultdict(set)
    indegree: Dict[int, int] = {idx: 0 for idx in range(len(components))}
    for node, deps in graph.items():
        src = component_index[node]
        for dep in deps:
            dst = component_index[dep]
            if src == dst:
                continue
            if dst not in condensed[src]:
                condensed[src].add(dst)
                indegree[dst] += 1

    ready = sorted(idx for idx, degree in indegree.items() if degree == 0)
    ordered: List[List[str]] = []
    while ready:
        idx = ready.pop(0)
        ordered.append(components[idx])
        for dep in sorted(condensed.get(idx, set())):
            indegree[dep] -= 1
            if indegree[dep] == 0:
                ready.append(dep)
                ready.sort()

    if len(ordered) != len(components):
        ordered = components

    return ordered, component_index, condensed


def _collect_enum_underlyings(type_entries: List[dict], enums: Dict[str, dict]) -> None:
    def visit_type_node(type_node: Optional[dict]) -> None:
        if not type_node:
            return
        kind = type_node.get("kind")
        if kind == "enum" and type_node.get("full_name") in enums:
            underlying = (
                ((type_node.get("enum_underlying") or {}).get("signature_name"))
                or ((type_node.get("enum_underlying") or {}).get("display_name"))
                or enums[type_node["full_name"]]["underlying"]
            )
            enums[type_node["full_name"]]["underlying"] = underlying
        for child_key in ("pointee", "inner", "key", "value", "enum_underlying"):
            visit_type_node(type_node.get(child_key))

    for entry in type_entries:
        for member in entry.get("members", []) or []:
            visit_type_node(member.get("type"))
        for function in entry.get("functions", []) or []:
            visit_type_node((function.get("return") or {}).get("type"))
            for param in function.get("params", []) or []:
                visit_type_node(param.get("type"))


def _build_type_index(entries: List[dict], enums: Dict[str, dict]) -> Tuple[Dict[str, dict], Dict[str, List[dict]], Dict[str, Set[str]], Dict[str, Set[str]], Dict[str, Dict[str, str]], Dict[str, Dict[str, Set[str]]]]:
    types_by_full: Dict[str, dict] = {}
    packages: Dict[str, List[dict]] = defaultdict(list)
    package_graph: Dict[str, Set[str]] = defaultdict(set)
    soft_struct_refs: Dict[str, Set[str]] = defaultdict(set)
    enum_refs: Dict[str, Dict[str, str]] = defaultdict(dict)
    type_graph_by_package: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))

    _collect_enum_underlyings(entries, enums)

    for entry in entries:
        full_name = entry.get("full_name") or ""
        package, short_name = _split_full_name(full_name)
        entry["package"] = package
        entry["name"] = short_name
        entry["symbol"] = _symbol_for_full_name(full_name)
        entry["hard_deps"] = set()
        entry["soft_deps"] = set()
        types_by_full[full_name] = entry
        packages[package].append(entry)

    for entry in entries:
        full_name = entry["full_name"]
        package = entry["package"]
        if entry.get("super_full_name"):
            entry["hard_deps"].add(entry["super_full_name"])
        for member in entry.get("members", []) or []:
            for ref_kind, ref_name, context, underlying in _iter_type_refs(member.get("type")):
                if ref_kind == "enum":
                    enum_refs[package][ref_name] = underlying or enums.get(ref_name, {}).get("underlying", "uint8_t")
                elif context == "direct":
                    entry["hard_deps"].add(ref_name)
                else:
                    entry["soft_deps"].add(ref_name)
        for function in entry.get("functions", []) or []:
            return_type = (function.get("return") or {}).get("type")
            for ref_kind, ref_name, context, underlying in _iter_type_refs(return_type):
                if ref_kind == "enum":
                    enum_refs[package][ref_name] = underlying or enums.get(ref_name, {}).get("underlying", "uint8_t")
                elif context == "direct":
                    entry["hard_deps"].add(ref_name)
                else:
                    entry["soft_deps"].add(ref_name)
            for param in function.get("params", []) or []:
                for ref_kind, ref_name, context, underlying in _iter_type_refs(param.get("type")):
                    if ref_kind == "enum":
                        enum_refs[package][ref_name] = underlying or enums.get(ref_name, {}).get("underlying", "uint8_t")
                    elif context == "direct":
                        entry["hard_deps"].add(ref_name)
                    else:
                        entry["soft_deps"].add(ref_name)

        local_graph = type_graph_by_package[package]
        local_graph.setdefault(full_name, set())
        for dep in sorted(entry["hard_deps"]):
            if dep not in types_by_full:
                continue
            dep_package = types_by_full[dep]["package"]
            if dep_package != package:
                package_graph[package].add(dep_package)
            else:
                local_graph[full_name].add(dep)
        for dep in sorted(entry["soft_deps"]):
            if dep in types_by_full:
                soft_struct_refs[package].add(dep)

    for package in packages:
        package_graph.setdefault(package, set())
        type_graph_by_package.setdefault(package, {})

    return types_by_full, packages, package_graph, soft_struct_refs, enum_refs, type_graph_by_package


def _qualified_type_name(type_node: Optional[dict], *, current_package: str, types_by_full: Dict[str, dict], enums: Dict[str, dict], same_scc_packages: Set[str], emitted_symbols: Set[str], direct_value_context: bool) -> Tuple[str, bool]:
    if not type_node:
        return "void", False
    kind = type_node.get("kind")
    signature_name = type_node.get("signature_name") or type_node.get("display_name") or "void"
    size_hint = int(type_node.get("size") or 0)
    align_hint = int(type_node.get("align") or 1)

    if kind == "named_struct":
        full_name = type_node.get("full_name") or ""
        target = types_by_full.get(full_name)
        if not target:
            return signature_name or "uint8_t", False
        symbol = target["symbol"]
        if direct_value_context:
            if target["package"] == current_package:
                if symbol in emitted_symbols:
                    return symbol, False
                return f"TCycleFixup<0x{int(target.get('size', 0) or size_hint):X}, 0x{int(((target.get('layout') or {}).get('min_alignment') or align_hint or 1)):X}>", True
            if target["package"] in same_scc_packages:
                return f"TCycleFixup<0x{int(target.get('size', 0) or size_hint):X}, 0x{int(((target.get('layout') or {}).get('min_alignment') or align_hint or 1)):X}>", True
        return symbol, False

    if kind == "enum":
        full_name = type_node.get("full_name") or ""
        enum_info = enums.get(full_name)
        return (enum_info["symbol"] if enum_info else signature_name), False

    if kind in {"primitive", "opaque"}:
        if kind == "opaque" and size_hint > 1:
            return f"TCycleFixup<0x{size_hint:X}, 0x{max(1, align_hint):X}>", True
        return signature_name, False

    if kind in {"object", "object_ptr", "class", "class_ptr", "soft_object", "soft_class", "weak_object", "lazy_object", "interface", "field_path"}:
        pointee, _ = _qualified_type_name(
            type_node.get("pointee"),
            current_package=current_package,
            types_by_full=types_by_full,
            enums=enums,
            same_scc_packages=same_scc_packages,
            emitted_symbols=emitted_symbols,
            direct_value_context=False,
        )
        if kind == "object":
            return f"{pointee}*", False
        if kind == "object_ptr":
            return f"TObjectPtr<{pointee}>", False
        if kind == "class_ptr":
            return "TObjectPtr<UClass>", False
        if kind == "class":
            if (type_node.get("metadata") or {}).get("is_subclass_of"):
                return f"TSubclassOf<{pointee}>", False
            return "UClass*", False
        if kind == "soft_object":
            return f"TSoftObjectPtr<{pointee}>", False
        if kind == "soft_class":
            return f"TSoftClassPtr<{pointee}>", False
        if kind == "weak_object":
            return f"TWeakObjectPtr<{pointee}>", False
        if kind == "lazy_object":
            return f"TLazyObjectPtr<{pointee}>", False
        if kind == "interface":
            return f"TScriptInterface<{pointee}>", False
        if kind == "field_path":
            return f"TFieldPath<{pointee}>", False

    if kind == "array":
        inner, _ = _qualified_type_name(
            type_node.get("inner"),
            current_package=current_package,
            types_by_full=types_by_full,
            enums=enums,
            same_scc_packages=same_scc_packages,
            emitted_symbols=emitted_symbols,
            direct_value_context=False,
        )
        return f"TArray<{inner}>", False

    if kind == "set":
        inner, _ = _qualified_type_name(
            type_node.get("inner"),
            current_package=current_package,
            types_by_full=types_by_full,
            enums=enums,
            same_scc_packages=same_scc_packages,
            emitted_symbols=emitted_symbols,
            direct_value_context=False,
        )
        return f"TSet<{inner}>", False

    if kind == "map":
        key, _ = _qualified_type_name(
            type_node.get("key"),
            current_package=current_package,
            types_by_full=types_by_full,
            enums=enums,
            same_scc_packages=same_scc_packages,
            emitted_symbols=emitted_symbols,
            direct_value_context=False,
        )
        value, _ = _qualified_type_name(
            type_node.get("value"),
            current_package=current_package,
            types_by_full=types_by_full,
            enums=enums,
            same_scc_packages=same_scc_packages,
            emitted_symbols=emitted_symbols,
            direct_value_context=False,
        )
        return f"TMap<{key}, {value}>", False

    if kind == "delegate":
        return "FScriptDelegate", False
    if kind == "multicast_delegate":
        return "FMulticastScriptDelegate", False

    return signature_name or "uint8_t", False


def _emit_field_declaration(cpp_type: str, field_name: str, *, array_dim: int = 1, comment: str = "") -> str:
    field_name = _sanitize_identifier(field_name)
    suffix = f"[{array_dim}]" if array_dim > 1 else ""
    tail = f" // {comment}" if comment else ""
    return f"    {cpp_type} {field_name}{suffix};{tail}\n"


def _emit_padding(name: str, offset: int, size: int) -> str:
    return f"    uint8_t {name}[0x{size:X}]; // 0x{offset:04X}\n"


def _emit_bitfield_group(group: List[dict], storage_offset: int) -> str:
    lines: List[str] = []
    cursor = 0
    group = sorted(group, key=lambda item: (item["bool_meta"]["bit_index"], item["name"]))
    for index, member in enumerate(group):
        bit_index = int((member.get("bool_meta") or {}).get("bit_index", -1))
        if bit_index < 0:
            continue
        if bit_index > cursor:
            lines.append(
                f"    uint8_t pad_bits_{storage_offset:04X}_{index} : {bit_index - cursor};\n"
            )
        lines.append(
            f"    uint8_t {_sanitize_identifier(member['name'])} : 1; // 0x{storage_offset:04X} bit {bit_index}\n"
        )
        cursor = bit_index + 1
    if cursor < 8:
        lines.append(
            f"    uint8_t pad_bits_{storage_offset:04X}_tail : {8 - cursor};\n"
        )
    return "".join(lines)


def _emit_struct_body(type_entry: dict, *, current_package: str, types_by_full: Dict[str, dict], enums: Dict[str, dict], same_scc_packages: Set[str], emitted_symbols: Set[str]) -> Tuple[str, List[Tuple[str, int]]]:
    layout = type_entry.get("layout") or {}
    members = sorted(
        type_entry.get("members", []) or [],
        key=lambda member: (
            int(member.get("storage_offset", member.get("offset", 0))),
            int((member.get("bool_meta") or {}).get("bit_index", 0)),
            member.get("name", ""),
        ),
    )
    lines: List[str] = []
    assertions: List[Tuple[str, int]] = []

    super_full_name = type_entry.get("super_full_name") or ""
    super_entry = types_by_full.get(super_full_name) if super_full_name else None
    reuse_super_tail = bool(layout.get("reuses_super_tail_padding")) and super_entry is not None
    current_offset = 0
    if super_entry is not None:
        if reuse_super_tail:
            used_size = int((super_entry.get("layout") or {}).get("last_member_end") or super_entry.get("size") or 0)
            super_align = int((super_entry.get("layout") or {}).get("min_alignment") or 1)
            lines.append(
                f"    TCycleFixup<0x{used_size:X}, 0x{super_align:X}> Super; // logical base: {super_entry['symbol']}\n"
            )
            current_offset = used_size
        else:
            current_offset = int((super_entry.get("layout") or {}).get("aligned_size") or super_entry.get("size") or 0)

    idx = 0
    while idx < len(members):
        member = members[idx]
        storage_offset = int(member.get("storage_offset", member.get("offset", 0)))
        bool_meta = member.get("bool_meta") or {}
        is_packed_bool = bool_meta and not bool(bool_meta.get("is_native"))

        if storage_offset > current_offset:
            pad = storage_offset - current_offset
            lines.append(_emit_padding(f"pad_{current_offset:04X}", current_offset, pad))
            current_offset = storage_offset

        if is_packed_bool:
            group: List[dict] = []
            group_offset = storage_offset
            while idx < len(members):
                candidate = members[idx]
                candidate_meta = candidate.get("bool_meta") or {}
                if not candidate_meta or bool(candidate_meta.get("is_native")):
                    break
                candidate_offset = int(candidate.get("storage_offset", candidate.get("offset", 0)))
                if candidate_offset != group_offset:
                    break
                group.append(candidate)
                idx += 1
            lines.append(_emit_bitfield_group(group, group_offset))
            current_offset = group_offset + 1
            continue

        type_node = member.get("type") or {}
        cpp_type, _ = _qualified_type_name(
            type_node,
            current_package=current_package,
            types_by_full=types_by_full,
            enums=enums,
            same_scc_packages=same_scc_packages,
            emitted_symbols=emitted_symbols,
            direct_value_context=True,
        )
        array_dim = int(member.get("array_dim", 1) or 1)
        comment = f"0x{int(member.get('offset', 0)):04X}"
        lines.append(
            _emit_field_declaration(
                cpp_type,
                member.get("name", "Field"),
                array_dim=array_dim,
                comment=comment,
            )
        )
        assertions.append((member.get("name", "Field"), int(member.get("offset", 0))))
        current_offset = storage_offset + max(1, int(member.get("size", 1)))
        idx += 1

    struct_size = int(type_entry.get("size", 0))
    if struct_size > current_offset:
        lines.append(_emit_padding(f"pad_{current_offset:04X}", current_offset, struct_size - current_offset))

    return "".join(lines), assertions


def _emit_function_param_structs(type_entry: dict, *, current_package: str, types_by_full: Dict[str, dict], enums: Dict[str, dict], same_scc_packages: Set[str], emitted_symbols: Set[str]) -> str:
    lines: List[str] = []
    type_symbol = type_entry["symbol"]
    for function in type_entry.get("functions", []) or []:
        params = sorted(
            function.get("params", []) or [],
            key=lambda param: (
                int(param.get("storage_offset", param.get("offset", 0))),
                int(((param.get("bool_meta") or {}).get("bit_index", 0))),
                param.get("name", ""),
            ),
        )
        if not params and function.get("return") is None:
            continue
        struct_name = f"{type_symbol}_{_sanitize_identifier(function['name'])}_Params"
        lines.append(f"// Signature: {function.get('signature', 'void')}\n")
        lines.append(f"struct {struct_name} {{\n")
        current_offset = 0
        idx = 0
        while idx < len(params):
            param = params[idx]
            storage_offset = int(param.get("storage_offset", param.get("offset", 0)))
            bool_meta = param.get("bool_meta") or {}
            is_packed_bool = bool_meta and not bool(bool_meta.get("is_native"))
            if storage_offset > current_offset:
                pad = storage_offset - current_offset
                lines.append(_emit_padding(f"pad_{current_offset:04X}", current_offset, pad))
                current_offset = storage_offset
            if is_packed_bool:
                group: List[dict] = []
                group_offset = storage_offset
                while idx < len(params):
                    candidate = params[idx]
                    candidate_meta = candidate.get("bool_meta") or {}
                    if not candidate_meta or bool(candidate_meta.get("is_native")):
                        break
                    candidate_offset = int(candidate.get("storage_offset", candidate.get("offset", 0)))
                    if candidate_offset != group_offset:
                        break
                    group.append(candidate)
                    idx += 1
                lines.append(_emit_bitfield_group(group, group_offset))
                current_offset = group_offset + 1
                continue

            cpp_type, _ = _qualified_type_name(
                param.get("type"),
                current_package=current_package,
                types_by_full=types_by_full,
                enums=enums,
                same_scc_packages=same_scc_packages,
                emitted_symbols=emitted_symbols,
                direct_value_context=True,
            )
            lines.append(
                _emit_field_declaration(
                    cpp_type,
                    param.get("name", "Param"),
                    comment=f"0x{int(param.get('offset', 0)):04X} flags={param.get('flags', '0x0')}",
                )
            )
            current_offset = storage_offset + max(1, int(param.get("size", 1)))
            idx += 1
        lines.append("};\n")
        lines.append(f"static_assert(sizeof({struct_name}) == 0x{current_offset:X});\n\n")
    return "".join(lines)


def _emit_runtime_headers(out_dir: str) -> None:
    basic_path = os.path.join(out_dir, "Basic.hpp")
    with open(basic_path, "w", encoding="utf-8") as f:
        f.write("#pragma once\n")
        f.write("#include <cstddef>\n")
        f.write("#include <cstdint>\n\n")
        f.write("namespace sdk {\n\n")
        f.write("struct UObject;\nstruct UClass;\nstruct UInterface;\nstruct UFunction;\n\n")
        f.write("template<std::size_t Size, std::size_t Align = 1>\n")
        f.write("struct alignas(Align) TCycleFixup {\n    std::uint8_t Data[Size == 0 ? 1 : Size];\n};\n\n")
        f.write("struct FName {\n    std::int32_t ComparisonIndex;\n    std::int32_t Number;\n};\n")
        f.write("static_assert(sizeof(FName) == 0x8);\n\n")
        f.write("struct FString {\n    wchar_t* Data;\n    std::int32_t Num;\n    std::int32_t Max;\n};\n")
        f.write("static_assert(sizeof(FString) == 0x10);\n\n")
        f.write("struct FText {\n    std::uint8_t Data[0x18];\n};\n")
        f.write("static_assert(sizeof(FText) == 0x18);\n\n")
        f.write("struct FScriptDelegate {\n    std::uint8_t Data[0x10];\n};\n")
        f.write("struct FMulticastScriptDelegate {\n    std::uint8_t Data[0x10];\n};\n\n")
        f.write("template<typename T>\nstruct TObjectPtr {\n    T* Object;\n};\n")
        f.write("template<typename T>\nstruct TSubclassOf {\n    UClass* Class;\n};\n\n")
        f.write("} // namespace sdk\n")

    containers_path = os.path.join(out_dir, "UnrealContainers.hpp")
    with open(containers_path, "w", encoding="utf-8") as f:
        f.write("#pragma once\n")
        f.write('#include "Basic.hpp"\n\n')
        f.write("namespace sdk {\n\n")
        f.write("template<typename T>\nstruct TArray {\n    T* Data;\n    std::int32_t Num;\n    std::int32_t Max;\n};\n")
        f.write("static_assert(sizeof(TArray<int>) == 0x10);\n\n")
        f.write("template<typename K, typename V>\nstruct TPair {\n    K Key;\n    V Value;\n};\n\n")
        f.write("template<typename T>\nstruct TWeakObjectPtr {\n    std::int32_t ObjectIndex;\n    std::int32_t ObjectSerialNumber;\n};\n")
        f.write("template<typename T>\nstruct TLazyObjectPtr {\n    TWeakObjectPtr<T> WeakPtr;\n};\n")
        f.write("template<typename T>\nstruct TSoftObjectPtr {\n    std::uint8_t Data[0x28];\n};\n")
        f.write("template<typename T>\nstruct TSoftClassPtr {\n    TSoftObjectPtr<T> Value;\n};\n")
        f.write("template<typename T>\nstruct TScriptInterface {\n    T* ObjectPointer;\n    void* InterfacePointer;\n};\n")
        f.write("template<typename T>\nstruct TFieldPath {\n    std::uint8_t Data[0x10];\n};\n")
        f.write("template<typename T>\nstruct TSet {\n    std::uint8_t Data[0x50];\n};\n")
        f.write("template<typename K, typename V>\nstruct TMap {\n    std::uint8_t Data[0x50];\n};\n\n")
        f.write("} // namespace sdk\n")


def _emit_package_header(path: str, *, package_name: str, entries: List[dict], package_includes: List[str], forward_structs: List[str], forward_enums: List[Tuple[str, str]], types_by_full: Dict[str, dict], enums: Dict[str, dict], same_scc_packages: Set[str], type_graph: Dict[str, Set[str]]) -> None:
    ordered_type_groups, _, _ = _topological_components(type_graph)
    emitted_symbols: Set[str] = set()
    with open(path, "w", encoding="utf-8") as f:
        f.write("#pragma once\n")
        f.write('#include "Basic.hpp"\n')
        f.write('#include "UnrealContainers.hpp"\n')
        for include_name in package_includes:
            f.write(f'#include "{include_name}.hpp"\n')
        f.write("\nnamespace sdk {\n\n")

        local_entry_symbols = {entry["symbol"] for entry in entries}
        local_enums = sorted(
            (enum_info for enum_info in enums.values() if enum_info["package"] == package_name),
            key=lambda item: item["symbol"],
        )

        for symbol, underlying in forward_enums:
            if all(enum_info["symbol"] != symbol for enum_info in local_enums):
                f.write(f"enum class {symbol} : {underlying};\n")
        for symbol in forward_structs:
            if symbol not in local_entry_symbols:
                f.write(f"struct {symbol};\n")
        if forward_enums or forward_structs:
            f.write("\n")

        for enum_info in local_enums:
            f.write(f"enum class {enum_info['symbol']} : {enum_info['underlying']} {{\n")
            for name, value in enum_info["values"]:
                f.write(f"    {_sanitize_identifier(name)} = {value},\n")
            f.write("};\n\n")

        entry_lookup = {entry["full_name"]: entry for entry in entries}
        for component in ordered_type_groups:
            for full_name in component:
                if full_name not in entry_lookup:
                    continue
                entry = entry_lookup[full_name]
                layout = entry.get("layout") or {}
                align = int(layout.get("min_alignment") or 1)
                symbol = entry["symbol"]
                super_full_name = entry.get("super_full_name") or ""
                super_entry = types_by_full.get(super_full_name) if super_full_name else None
                reuse_super_tail = bool(layout.get("reuses_super_tail_padding")) and super_entry is not None

                f.write("#pragma pack(push, 0x1)\n")
                inheritance = ""
                if super_entry is not None and not reuse_super_tail:
                    inheritance = f" : public {super_entry['symbol']}"
                f.write(f"struct alignas(0x{align:X}) {symbol}{inheritance} {{\n")
                body, assertions = _emit_struct_body(
                    entry,
                    current_package=package_name,
                    types_by_full=types_by_full,
                    enums=enums,
                    same_scc_packages=same_scc_packages,
                    emitted_symbols=emitted_symbols,
                )
                f.write(body)
                f.write("};\n")
                f.write("#pragma pack(pop)\n")
                f.write(f"static_assert(sizeof({symbol}) == 0x{int(entry.get('size', 0)):X});\n")
                f.write(f"static_assert(alignof({symbol}) == 0x{align:X});\n")
                for field_name, offset in assertions:
                    safe_name = _sanitize_identifier(field_name)
                    if safe_name == "Super":
                        continue
                    f.write(f"static_assert(offsetof({symbol}, {safe_name}) == 0x{offset:X});\n")
                f.write("\n")
                emitted_symbols.add(symbol)

            for full_name in component:
                if full_name not in entry_lookup:
                    continue
                entry = entry_lookup[full_name]
                f.write(
                    _emit_function_param_structs(
                        entry,
                        current_package=package_name,
                        types_by_full=types_by_full,
                        enums=enums,
                        same_scc_packages=same_scc_packages,
                        emitted_symbols=emitted_symbols,
                    )
                )

        f.write("} // namespace sdk\n")


def generate_v2_package_headers(dump_dir: str, out_dir: str) -> List[str]:
    entries = _load_v2_struct_entries(dump_dir)
    enums = _load_legacy_enums(dump_dir)
    if not entries:
        return []

    types_by_full, packages, package_graph, soft_struct_refs, enum_refs, type_graph_by_package = _build_type_index(entries, enums)
    ordered_package_groups, package_component_index, _ = _topological_components(package_graph)
    package_scc_by_name = {
        package_name: set(ordered_package_groups[package_component_index[package_name]])
        for package_name in package_component_index
    }

    package_names: List[str] = []
    for package_group in ordered_package_groups:
        for package_name in package_group:
            package_symbol = _package_symbol(package_name)
            package_names.append(package_symbol)
            same_scc_packages = package_scc_by_name.get(package_name, {package_name})
            include_names = sorted(
                _package_symbol(dep)
                for dep in package_graph.get(package_name, set())
                if dep not in same_scc_packages
            )
            forward_structs = sorted(
                {
                    types_by_full[dep]["symbol"]
                    for dep in soft_struct_refs.get(package_name, set())
                    if dep in types_by_full and types_by_full[dep]["package"] != package_name
                }
            )
            forward_enums = sorted(
                (
                    enums[enum_name]["symbol"],
                    enum_refs.get(package_name, {}).get(enum_name) or enums[enum_name]["underlying"],
                )
                for enum_name in enum_refs.get(package_name, {})
                if enum_name in enums and enums[enum_name]["package"] != package_name
            )
            _emit_package_header(
                os.path.join(out_dir, f"{package_symbol}.hpp"),
                package_name=package_name,
                entries=sorted(packages[package_name], key=lambda item: item["symbol"]),
                package_includes=include_names,
                forward_structs=forward_structs,
                forward_enums=forward_enums,
                types_by_full=types_by_full,
                enums=enums,
                same_scc_packages=same_scc_packages,
                type_graph=type_graph_by_package.get(package_name, {}),
            )

    _emit_runtime_headers(out_dir)
    return package_names


def generate_v2_master_header(packages: List[str], out_dir: str) -> None:
    with open(os.path.join(out_dir, "SDK.hpp"), "w", encoding="utf-8") as f:
        f.write("#pragma once\n\n")
        f.write('#include "Basic.hpp"\n')
        f.write('#include "UnrealContainers.hpp"\n')
        f.write('#include "Offsets.hpp"\n')
        f.write('#include "chains.hpp"\n\n')
        for package in sorted(packages):
            f.write(f'#include "{package}.hpp"\n')
