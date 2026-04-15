# UE/Unity Dumper

Automated SDK offset dumper for **Unreal Engine 4/5** and **Unity (IL2CPP / Mono)** games on Windows. Also includes a Source engine netvar dumper.

Primary focus is Unreal Engine — tested against UE 4.22 through UE 5.5 across dozens of shipped titles.

---

## Supported Engines

| Engine | Format | Notes |
|---|---|---|
| Unreal Engine 4 / 5 | GNames + GObjects + GWorld + full SDK walk | Primary target |
| Unity IL2CPP | global-metadata.dat parser + PE scanner | Confirmed working |
| Unity Mono | Managed assembly reflection | Confirmed working |
| Source Engine | Netvar scanner | TF2 / L4D2 (Source 1) |

---

## Kernel Mode

A kernel-mode driver (`driver/`) is included for reading game memory without user-mode hooks.

> **Note:** Kernel mode is confirmed working against a subset of EAC and BattlEye protected titles. It does **not** bypass all protected games — particularly those with kernel-level anti-cheat components (e.g. Vanguard, nProtect). Test on your target before relying on it.

User-mode (`ReadProcessMemory`) works fine for unprotected and most lightly protected titles.

---

## Requirements

- **Python 3.10+**
- **Windows 10/11 x64**
- Visual Studio 2022 + WDK (only required to build the kernel driver)

---

## Quick Start

### GUI

```cmd
pip install psutil
python -m src.ui.app
```

### CLI

```cmd
python -m src.ui.cli --process Palworld-Win64-Shipping.exe
python -m src.ui.cli --process Palworld-Win64-Shipping.exe --output my_dump/
python -m src.ui.cli --engine il2cpp --process MyUnityGame.exe
python -m src.ui.cli --engine mono --process MyUnityGame.exe
python -m src.ui.cli --engine il2cpp --process MyGame.exe --metadata path/to/global-metadata.dat
python -m src.ui.cli --process MyGame.exe --kernel
```

### Building the kernel driver (optional)

```cmd
Build.bat
```

Requires Visual Studio 2022 and the Windows Driver Kit. The resulting `wdfsvc64.sys` must be mapped manually (e.g. via kdmapper). See `driver/BUILD.md`.

---

## C++ Trainer Template

The GUI includes a **"Generate C++ Workbench"** option that outputs a standalone ImGui overlay project wired to the dumped offsets.

> **⚠️ This is a starting point, not a finished product.**
> The generated template compiles and runs, but it will almost certainly require manual edits before it works correctly with your specific target:
> - Pointer chains are game-specific and may need adjusting
> - ESP/feature logic is stubbed out with placeholder values
> - Driver connection assumes `wdfsvc64.sys` is already mapped
> - Anti-cheat behavior varies — what works on one game may not work on another
>
> Treat it as scaffolding. You will need C++ knowledge to adapt it.

---

## Output

Dumps are written to `output/<ProcessName>/`:

| File | Contents |
|---|---|
| `OffsetsInfo.json` | GNames / GObjects / GWorld RVAs |
| `Classes.json` | All UClasses / structs with fields |
| `Enums.json` | All UEnum entries |
| `SDK/` | Generated C++ header files |
| `health.txt` | Dump quality report |

---

## Steam Audit (WIP)

The GUI includes a Steam library scanner that detects which of your installed/owned games use supported engines and whether kernel mode is recommended.

> **This feature is a work in progress.** Scanning large libraries may take a long time and some results may be incomplete. Improvements are ongoing.

---

## Confirmed Working Games

Unreal Engine titles tested and verified:

- Palworld (UE 5.1)
- Manor Lords (UE 5.5)
- Medieval Dynasty (UE 4.27)
- Half Sword (UE 5)
- VRising (Unity IL2CPP)
- 9Kings (Unity IL2CPP)
- Project Tower (UE)
- Solarland Client (UE)
- MHUR (UE)

---

## Project Structure

```
src/
  core/         Memory, driver IPC, PE parser, diagnostics
  engines/
    ue/         Unreal Engine scanner (GNames, GObjects, GWorld, SDK walker)
    il2cpp/     Unity IL2CPP metadata parser
    mono/       Unity Mono assembly dumper
    source/     Source engine netvar scanner
  ui/           GUI (app.py) and CLI (cli.py)
  output/       JSON writer, SDK generator, template generator
driver/         Kernel driver source (KMDF, C)
```

---

## License

MIT
