
from typing import Any, Dict, List, Tuple
from dataclasses import dataclass, field

@dataclass
class MemberInfo:
    name: str
    offset: int
    size: int
    type_name: str
    array_dim: int = 1
    is_static: bool = False
    flags: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class FunctionParamInfo:
    name: str
    offset: int
    size: int
    type_name: str
    flags: int = 0

@dataclass
class FunctionInfo:
    name: str
    address: int
    rva: int = 0
    flags: int = 0
    exec_func: int = 0
    params: List[FunctionParamInfo] = field(default_factory=list)

@dataclass
class StructInfo:
    name: str
    full_name: str
    address: int
    size: int
    super_name: str = ""
    is_class: bool = False
    package: str = ""
    members: List[MemberInfo] = field(default_factory=list)
    functions: List[FunctionInfo] = field(default_factory=list)
    super_chain: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class EnumInfo:
    name: str
    full_name: str
    address: int
    values: List[Tuple[str, int]] = field(default_factory=list)

@dataclass
class SDKDump:
    structs: List[StructInfo] = field(default_factory=list)
    enums: List[EnumInfo] = field(default_factory=list)
    object_count: int = 0
    gnames_ptr: int = 0
    gobjects_ptr: int = 0
    gworld_ptr: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
