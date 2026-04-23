import os
import sys
import time

def _run_source2(args):
    from src.engines.source2.dumper import dump_source2
    from src.output.json_writer import write_all as source2_write_all
    from src.core.memory import get_pid_by_name, attach, detach
    
    print()
    print("=" * 60)
    print("  UE/Unity Dumper — Source 2 Offset Dumper")
    print("=" * 60)

    total_start = time.time()
    process_name = args.process
    
    print(f"\n[1/3] Finding {process_name}...")
    pid = get_pid_by_name(process_name)
    if not pid:
        print(f"  [!!] Process not found. Make sure the game is running.")
        return 1
    print(f"  [OK] PID: {pid}")

    handle = attach(pid)
    if not handle:
        print(f"  [!!] Could not attach. Try running as admin.")
        return 1

    game_dir = process_name.replace(".exe", "").replace(".dll", "")
    output_dir = os.path.join("games", game_dir, "Offsets")

    print(f"\n[2/3] Running Source 2 schema dump...")

    def progress(current_msg: str):
        if sys.stdout.isatty():
            print(f"\r  [>>] {current_msg}", end=" "*20 + "\r", flush=True)
            print(f"  [>>] {current_msg}", flush=True)
        else:
            print(f"  [>>] {current_msg}", flush=True)

    try:
        dump = dump_source2(
            handle, 
            process_name,
            progress_callback=progress
        )
    except Exception as e:
        print(f"\n  [!!] Source 2 dump failed: {e}")
        detach(handle)
        return 1
        
    print()
    detach(handle)

    if not dump.structs and getattr(dump, "enums", None) is None:
        print(f"  [!!] No structs or enums found.")
        return 1

    print(f"  [OK] {len(dump.structs)} structs/classes")

    print(f"\n[3/3] Writing output to {output_dir}/...")
    source2_write_all(
        output_dir, 
        dump, 
        0, 0, 0, 
        process_name=process_name, 
        engine="source2", 
        pe_timestamp=0
    )

    total_size = 0
    for f in os.listdir(output_dir):
        fp = os.path.join(output_dir, f)
        if os.path.isfile(fp):
            fsize = os.path.getsize(fp)
            total_size += fsize
            print(f"    {f:30s} {fsize // 1024:>6d} KB")

    total_elapsed = time.time() - total_start
    print(f"\n{'='*60}")
    print(f"  Source 2 dump complete!")
    print(f"  Output: {os.path.abspath(output_dir)}/")
    print(f"  Total:  {total_size // 1024} KB in {total_elapsed:.1f}s")
    print(f"  Structs/Classes: {len(dump.structs)}")
    print(f"{'='*60}")

    return 0
