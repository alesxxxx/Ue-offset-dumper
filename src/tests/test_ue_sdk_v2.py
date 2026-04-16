import json
import os
import shutil
import subprocess
import tempfile
import unittest

from src.core.models import (
    BoolMeta,
    EnumInfo,
    FunctionInfo,
    FunctionParamInfo,
    MemberInfo,
    SDKDump,
    StructInfo,
    StructLayoutMeta,
    TypeDesc,
)
from src.output.json_writer import write_all
from src.output.sdk_gen import generate_sdk


def _named_struct(full_name: str, size: int, align: int) -> TypeDesc:
    package, short_name = full_name.split(".", 1)
    return TypeDesc(
        kind="named_struct",
        display_name=short_name,
        full_name=full_name,
        package=package,
        size=size,
        align=align,
        signature_name=short_name,
    )


def _enum_desc(full_name: str, underlying: TypeDesc) -> TypeDesc:
    package, short_name = full_name.split(".", 1)
    return TypeDesc(
        kind="enum",
        display_name=short_name,
        full_name=full_name,
        package=package,
        size=underlying.size,
        align=underlying.align,
        signature_name=short_name,
        enum_underlying=underlying,
    )


def _build_test_dump() -> SDKDump:
    dump = SDKDump()
    dump.enums.append(
        EnumInfo(
            name="EWeaponType",
            full_name="Game.EWeaponType",
            address=0x3000,
            values=[("None", 0), ("Sword", 1), ("Bow", 2)],
            metadata={"underlying_type": "uint8_t"},
        )
    )

    actor = StructInfo(
        name="Actor",
        full_name="CoreUObject.Actor",
        address=0x1000,
        size=0x18,
        is_class=True,
        package="CoreUObject",
        layout=StructLayoutMeta(
            min_alignment=8,
            aligned_size=0x18,
            unaligned_size=0x18,
            highest_member_alignment=8,
            last_member_end=0x18,
            super_size=0,
            reuses_super_tail_padding=False,
        ),
    )
    actor.members.append(
        MemberInfo(
            name="RootComponent",
            offset=0x8,
            size=0x8,
            type_name="ObjectProperty",
            type_desc=TypeDesc(
                kind="object",
                pointee=_named_struct("CoreUObject.SceneComponent", 0, 8),
                size=8,
                align=8,
                signature_name="SceneComponent*",
                display_name="SceneComponent*",
            ),
        )
    )

    inventory_entry = StructInfo(
        name="InventoryEntry",
        full_name="Game.InventoryEntry",
        address=0x1100,
        size=0x10,
        is_class=False,
        package="Game",
        layout=StructLayoutMeta(
            min_alignment=8,
            aligned_size=0x10,
            unaligned_size=0x10,
            highest_member_alignment=8,
            last_member_end=0x10,
            super_size=0,
            reuses_super_tail_padding=False,
        ),
    )
    inventory_entry.members.extend(
        [
            MemberInfo(
                name="ItemId",
                offset=0x0,
                size=0x4,
                type_name="IntProperty",
                type_desc=TypeDesc(
                    kind="primitive",
                    display_name="int32_t",
                    signature_name="int32_t",
                    size=4,
                    align=4,
                ),
            ),
            MemberInfo(
                name="Label",
                offset=0x8,
                size=0x8,
                type_name="NameProperty",
                type_desc=TypeDesc(
                    kind="primitive",
                    display_name="FName",
                    signature_name="FName",
                    size=0x8,
                    align=4,
                ),
            ),
        ]
    )

    player_pawn = StructInfo(
        name="PlayerPawn",
        full_name="Game.PlayerPawn",
        address=0x1200,
        size=0x40,
        super_name="Actor",
        super_full_name="CoreUObject.Actor",
        is_class=True,
        package="Game",
        layout=StructLayoutMeta(
            min_alignment=8,
            aligned_size=0x40,
            unaligned_size=0x40,
            highest_member_alignment=8,
            last_member_end=0x38,
            super_size=0x18,
            reuses_super_tail_padding=False,
        ),
    )

    bool_desc = TypeDesc(
        kind="primitive",
        display_name="bool",
        signature_name="bool",
        size=1,
        align=1,
    )
    player_pawn.members.extend(
        [
            MemberInfo(
                name="bIsAlive",
                offset=0x18,
                storage_offset=0x18,
                size=1,
                type_name="BoolProperty",
                type_desc=bool_desc,
                bool_meta=BoolMeta(is_native=False, field_mask=0x01, byte_offset=0, bit_index=0),
            ),
            MemberInfo(
                name="bIsVisible",
                offset=0x18,
                storage_offset=0x18,
                size=1,
                type_name="BoolProperty",
                type_desc=bool_desc,
                bool_meta=BoolMeta(is_native=False, field_mask=0x04, byte_offset=0, bit_index=2),
            ),
            MemberInfo(
                name="Items",
                offset=0x20,
                storage_offset=0x20,
                size=0x10,
                type_name="ArrayProperty",
                type_desc=TypeDesc(
                    kind="array",
                    display_name="TArray<InventoryEntry>",
                    signature_name="TArray<InventoryEntry>",
                    size=0x10,
                    align=8,
                    inner=_named_struct("Game.InventoryEntry", 0x10, 8),
                ),
            ),
            MemberInfo(
                name="WeaponType",
                offset=0x30,
                storage_offset=0x30,
                size=1,
                type_name="EnumProperty",
                type_desc=_enum_desc(
                    "Game.EWeaponType",
                    TypeDesc(
                        kind="primitive",
                        display_name="uint8_t",
                        signature_name="uint8_t",
                        size=1,
                        align=1,
                    ),
                ),
            ),
        ]
    )

    get_stat = FunctionInfo(name="GetStat", address=0x5000, flags=0x123)
    get_stat.params.extend(
        [
            FunctionParamInfo(
                name="Index",
                offset=0x0,
                size=0x4,
                type_name="IntProperty",
                flags=0x82,
                type_desc=TypeDesc(
                    kind="primitive",
                    display_name="int32_t",
                    signature_name="int32_t",
                    size=4,
                    align=4,
                    is_const=True,
                ),
            ),
            FunctionParamInfo(
                name="OutName",
                offset=0x8,
                size=0x10,
                type_name="StrProperty",
                flags=0x980,
                type_desc=TypeDesc(
                    kind="primitive",
                    display_name="FString",
                    signature_name="FString",
                    size=0x10,
                    align=8,
                    is_ref=True,
                ),
            ),
            FunctionParamInfo(
                name="ReturnValue",
                offset=0x18,
                size=0x4,
                type_name="IntProperty",
                flags=0x480,
                type_desc=TypeDesc(
                    kind="primitive",
                    display_name="int32_t",
                    signature_name="int32_t",
                    size=4,
                    align=4,
                ),
            ),
        ]
    )
    get_stat.return_param = get_stat.params[-1]
    player_pawn.functions.append(get_stat)

    reused_tail = StructInfo(
        name="ReusedTailChild",
        full_name="Game.ReusedTailChild",
        address=0x1300,
        size=0x20,
        super_name="InventoryEntry",
        super_full_name="Game.InventoryEntry",
        is_class=False,
        package="Game",
        layout=StructLayoutMeta(
            min_alignment=8,
            aligned_size=0x20,
            unaligned_size=0x20,
            highest_member_alignment=8,
            last_member_end=0x20,
            super_size=0x10,
            reuses_super_tail_padding=True,
        ),
    )
    reused_tail.members.append(
        MemberInfo(
            name="ExtraId",
            offset=0xC,
            storage_offset=0xC,
            size=0x4,
            type_name="IntProperty",
            type_desc=TypeDesc(
                kind="primitive",
                display_name="int32_t",
                signature_name="int32_t",
                size=4,
                align=4,
            ),
        )
    )

    dump.structs.extend([actor, inventory_entry, player_pawn, reused_tail])
    return dump


class TestUESDKV2(unittest.TestCase):
    def test_write_all_emits_v2_files(self):
        dump = _build_test_dump()
        with tempfile.TemporaryDirectory() as temp_dir:
            write_all(
                temp_dir,
                dump,
                gnames_off=0x111,
                gobjects_off=0x222,
                gworld_off=0x333,
                engine="ue",
                ue_version="5.1",
            )
            with open(os.path.join(temp_dir, "ClassesInfoV2.json"), "r", encoding="utf-8") as f:
                classes_v2 = json.load(f)
            self.assertEqual(classes_v2["schema_version"], 2)
            player_entry = next(item for item in classes_v2["data"] if item["full_name"] == "Game.PlayerPawn")
            self.assertEqual(player_entry["super_full_name"], "CoreUObject.Actor")
            self.assertEqual(player_entry["layout"]["min_alignment"], 8)
            bool_member = next(item for item in player_entry["members"] if item["name"] == "bIsAlive")
            self.assertEqual(bool_member["bool_meta"]["bit_index"], 0)
            array_member = next(item for item in player_entry["members"] if item["name"] == "Items")
            self.assertEqual(array_member["type"]["kind"], "array")
            self.assertEqual(array_member["type"]["inner"]["full_name"], "Game.InventoryEntry")
            function_entry = next(item for item in player_entry["functions"] if item["name"] == "GetStat")
            self.assertIn("FString& OutName", function_entry["signature"])

    def test_generate_sdk_prefers_v2(self):
        dump = _build_test_dump()
        with tempfile.TemporaryDirectory() as dump_dir, tempfile.TemporaryDirectory() as out_dir:
            write_all(
                dump_dir,
                dump,
                gnames_off=0x111,
                gobjects_off=0x222,
                gworld_off=0x333,
                engine="ue",
                ue_version="5.1",
            )
            generate_sdk(dump_dir, out_dir, engine="ue")

            self.assertTrue(os.path.exists(os.path.join(out_dir, "Basic.hpp")))
            self.assertTrue(os.path.exists(os.path.join(out_dir, "UnrealContainers.hpp")))
            game_header = os.path.join(out_dir, "Game.hpp")
            self.assertTrue(os.path.exists(game_header))

            with open(game_header, "r", encoding="utf-8") as f:
                contents = f.read()
            self.assertIn("TArray<Game_InventoryEntry> Items", contents)
            self.assertIn("uint8_t bIsAlive : 1;", contents)
            self.assertIn("static_assert(sizeof(Game_PlayerPawn) == 0x40);", contents)
            self.assertIn("struct alignas(0x8) Game_ReusedTailChild", contents)
            self.assertIn("logical base: Game_InventoryEntry", contents)
            self.assertIn("// Signature: int32_t GetStat(const int32_t Index, FString& OutName)", contents)

    def test_generate_sdk_legacy_fallback_when_v2_is_absent(self):
        with tempfile.TemporaryDirectory() as dump_dir, tempfile.TemporaryDirectory() as out_dir:
            legacy_structs = {
                "data": [
                    {
                        "Game.LegacyActor": [
                            {"__InheritInfo": []},
                            {"__MDKClassSize": 16},
                            {"Value": [["IntProperty", "D", "", []], 0, 4]},
                        ]
                    }
                ]
            }
            for filename in ("ClassesInfo.json", "StructsInfo.json"):
                with open(os.path.join(dump_dir, filename), "w", encoding="utf-8") as f:
                    json.dump(legacy_structs, f)
            with open(os.path.join(dump_dir, "OffsetsInfo.json"), "w", encoding="utf-8") as f:
                json.dump({"engine": "ue", "data": []}, f)
            with open(os.path.join(dump_dir, "EnumsInfo.json"), "w", encoding="utf-8") as f:
                json.dump({"data": []}, f)

            generate_sdk(dump_dir, out_dir, engine="ue")

            self.assertFalse(os.path.exists(os.path.join(out_dir, "Basic.hpp")))
            with open(os.path.join(out_dir, "Game.hpp"), "r", encoding="utf-8") as f:
                contents = f.read()
            self.assertIn("struct Game_LegacyActor", contents)
            self.assertIn("int32_t Value", contents)

    def test_generated_v2_sdk_compiles_when_compiler_is_available(self):
        compiler = shutil.which("clang++") or shutil.which("g++")
        if compiler is None:
            self.skipTest("No C++ compiler available in PATH")

        dump = _build_test_dump()
        with tempfile.TemporaryDirectory() as dump_dir, tempfile.TemporaryDirectory() as out_dir:
            write_all(
                dump_dir,
                dump,
                gnames_off=0x111,
                gobjects_off=0x222,
                gworld_off=0x333,
                engine="ue",
                ue_version="5.1",
            )
            generate_sdk(dump_dir, out_dir, engine="ue")
            test_cpp = os.path.join(out_dir, "compile_test.cpp")
            with open(test_cpp, "w", encoding="utf-8") as f:
                f.write('#include "SDK.hpp"\nint main() { return 0; }\n')
            subprocess.run(
                [compiler, "-std=c++17", "-c", test_cpp, "-I", out_dir],
                check=True,
                capture_output=True,
                text=True,
            )


if __name__ == "__main__":
    unittest.main()
