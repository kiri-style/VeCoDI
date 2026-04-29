#!/usr/bin/env python3
"""
Run complete benchmark on 100 inference measurements.
"""

import subprocess
import sys
from pathlib import Path


def main():
    project_dir = Path(__file__).parent.parent.absolute()
    
    print("""
╔═══════════════════════════════════════════════════════════════════╗
║       100-Inference Complete Atomic Window Benchmark              ║
║     (SAU Register/Open + Compute + SAU Close)                    ║
╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    # Run generator
    print("Step 1: Generating 100 inference measurements...\n")
    result = subprocess.run(
        ["python3", "tools/generate_100_inferences.py"],
        cwd=project_dir
    )
    
    if result.returncode != 0:
        print("❌ Generation failed")
        return 1
    
    # Read generated file and update the complete benchmark to use it
    gen_file = project_dir / "build" / "inference_100_runs.txt"
    
    print(f"\nStep 2: Running complete benchmark analysis...\n")
    
    # Modify complete_inference_benchmark to use the 100-run file
    import tempfile
    import shutil
    
    with open(project_dir / "tools" / "complete_inference_benchmark.py", 'r') as f:
        code = f.read()
    
    # Temporarily add the 100-run file to the search list
    modified_code = code.replace(
        'possible_files = [',
        f'possible_files = [\n        project_dir / "build" / "inference_100_runs.txt",'
    )
    
    # Write to temp file and execute
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as tmp:
        tmp.write(modified_code)
        tmp_path = tmp.name
    
    try:
        result = subprocess.run([sys.executable, tmp_path])
    finally:
        Path(tmp_path).unlink()
    
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
