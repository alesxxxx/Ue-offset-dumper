import ctypes
import typing

# Common types
class CUtlTSHash(ctypes.Structure):
    # This is a complex template, we will parse its buckets manually in python
    pass

class SchemaType_t(ctypes.Structure):
    _fields_ = [
        ("vtable", ctypes.c_uint64),
        ("name", ctypes.c_uint64), # ptr to string
        ("type_system", ctypes.c_uint64),
        ("type_category", ctypes.c_uint8),
        ("atomic_category", ctypes.c_uint8),
    ]

class SchemaClassFieldData_t(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_uint64), # ptr to string
        ("schema_type", ctypes.c_uint64), # ptr to SchemaType_t
        ("offset", ctypes.c_uint32),
        ("metadata_size", ctypes.c_uint32),
        ("metadata", ctypes.c_uint64),
    ]

# Layout according to a2x/cs2-dumper
class SchemaClassInfoData_t(ctypes.Structure):
    _fields_ = [
        ("pad0", ctypes.c_uint64), # 0x00 base
        ("name", ctypes.c_uint64), # 0x08
        ("binary_name", ctypes.c_uint64), # 0x10
        ("module_name", ctypes.c_uint64), # 0x18
        ("size", ctypes.c_int32), # 0x20
        ("field_count", ctypes.c_int16), # 0x24
        ("static_metadata_count", ctypes.c_int16), # 0x26
        ("pad1", ctypes.c_uint16), # 0x28
        ("alignment", ctypes.c_uint8), # 0x2A
        ("has_base_class", ctypes.c_uint8), # 0x2B
        ("total_class_size", ctypes.c_int16), # 0x2C
        ("derived_class_size", ctypes.c_int16), # 0x2E
        ("fields", ctypes.c_uint64), # 0x30 pointer to SchemaClassFieldData
        ("pad2", ctypes.c_uint64), # 0x38 
        ("base_classes", ctypes.c_uint64), # 0x40
        ("static_metadata", ctypes.c_uint64), # 0x48
        ("pad3", ctypes.c_uint64), # 0x50 
        ("type_scope", ctypes.c_uint64), # 0x58
        ("schema_type", ctypes.c_uint64), # 0x60
        ("class_flags", ctypes.c_uint32), # 0x68
    ]

# We don't usually map out the CUtlTSHash entirely in memory. It's normally iterated via CUtlMemoryPool.

class CSchemaSystemTypeScope(ctypes.Structure):
    pass
    # contains CUtlTSHash for classes and enums

class CSchemaSystem(ctypes.Structure):
    pass
    # contains CUtlVector of type scopes
