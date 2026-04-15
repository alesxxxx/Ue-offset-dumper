# Building the NOVA Kernel Driver

## Prerequisites

1. **Visual Studio 2019/2022** with C++ Desktop Development workload
2. **Windows Driver Kit (WDK)** matching your VS version
   - Download from: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
3. **Windows SDK** (usually installed with VS)

## Building wdfsvc64.sys

### Option A: Visual Studio
1. Open `driver.vcxproj` in Visual Studio
2. Select **Release | x64**
3. Build (Ctrl+Shift+B)
4. Output: `bin\wdfsvc64.sys`

### Option B: Command Line (Developer Command Prompt)
```
msbuild driver.vcxproj /p:Configuration=Release /p:Platform=x64
```

## Building kdmapper

1. Open `tools\kdmapper\kdmapper.sln` in Visual Studio
2. Select **Release | x64**
3. Build
4. Copy `tools\kdmapper\x64\Release\kdmapper.exe` to `bin\kdmapper.exe`

## Loading the Driver

```
# Run as Administrator
Launch.bat
```

Or manually:
```
bin\kdmapper.exe bin\wdfsvc64.sys
```

## Requirements for Loading

- **Secure Boot**: Must be DISABLED in BIOS
- **Hyper-V / VBS**: Should be disabled for best compatibility
- **Anti-virus**: May need exclusion for bin\ directory

## Verifying the Driver

After loading, run NOVA with `--kernel` flag:
```
python -m src.ui.cli --kernel -p YourGame.exe
```

If you see `[Kernel] Driver connected`, the driver is working.

## Debug Build

To build with debug logging (shows DbgPrint output in DebugView):
```
msbuild driver.vcxproj /p:Configuration=Debug /p:Platform=x64
```

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| kdmapper fails | Secure Boot enabled | Disable in BIOS |
| kdmapper fails | HVCI/VBS active | Disable in Windows Security |
| Driver loaded but NOVA can't connect | Section creation failed | Check DebugView for errors |
| CR3 lookup returns 0 | Wrong EPROCESS offset | Update `EPROCESS_DTB_OFFSET` in comm.h for your Windows build |
