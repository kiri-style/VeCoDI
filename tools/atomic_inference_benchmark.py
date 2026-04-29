#!/usr/bin/env python3
"""
Atomic Inference Window Benchmark

Measures the inference execution time within the atomic inference window:
- Early layers execution
- Late layers execution  
- Total inference (early + late + overhead)
- Compares cycles vs wall-clock time

Targets the split inference in CMSIS-NN implementation on Cortex-M33 (110 MHz).
"""

import re
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Dict, List
import json


@dataclass
class InferenceCycles:
    """Store cycle measurements from inference"""
    total_inferences: int = 0
    total_inference_cycles: int = 0
    early_layers_cycles: Optional[int] = None
    late_layers_cycles: Optional[int] = None
    
    # Stats
    total_inference_min: int = 0xFFFFFFFF
    total_inference_max: int = 0
    early_layers_min: Optional[int] = None
    early_layers_max: Optional[int] = None
    late_layers_min: Optional[int] = None
    late_layers_max: Optional[int] = None


class AtomicInferenceBenchmark:
    """Benchmark the atomic inference window execution"""
    
    # CPU frequency
    CPU_FREQ_HZ = 110_000_000  # STM32L552 @ 110 MHz
    
    def __init__(self, project_dir: str):
        self.project_dir = Path(project_dir)
        self.build_dir = self.project_dir / "build"
        self.src_dir = self.project_dir / "src"
        self.data: Dict[str, any] = {
            "timestamp": None,
            "cpu_freq_hz": self.CPU_FREQ_HZ,
            "cpu_freq_mhz": self.CPU_FREQ_HZ // 1_000_000,
            "measurements": [],
            "summary": {}
        }
        
    def cycles_to_ms(self, cycles: int) -> float:
        """Convert CPU cycles to milliseconds"""
        return (cycles * 1000.0) / self.CPU_FREQ_HZ
    
    def cycles_to_us(self, cycles: int) -> float:
        """Convert CPU cycles to microseconds"""
        return (cycles * 1_000_000.0) / self.CPU_FREQ_HZ
    
    def extract_inference_metrics(self, output: str) -> Optional[Dict[str, int]]:
        """Extract inference metrics from console output"""
        metrics = {}
        
        # Pattern: [SPLIT] Prediction = N (total inference: X cycles, Y ms)
        total_pattern = r'\[SPLIT\] Prediction = \d+ \(total inference: (\d+) cycles, (\d+) ms\)'
        match = re.search(total_pattern, output)
        if match:
            metrics['total_inference_cycles'] = int(match.group(1))
            metrics['total_inference_ms'] = int(match.group(2))
        
        # Pattern: [EARLY]... X cycles
        early_pattern = r'\[EARLY\].*?(\d+) cycles'
        match = re.search(early_pattern, output)
        if match:
            metrics['early_layers_cycles'] = int(match.group(1))
        
        # Pattern: [LATE]... X cycles
        late_pattern = r'\[LATE\].*?(\d+) cycles'
        match = re.search(late_pattern, output)
        if match:
            metrics['late_layers_cycles'] = int(match.group(1))
        
        # Pattern: inference_count, early_layers_count, etc.
        count_pattern = r'inference_count[:\s]+(\d+)'
        match = re.search(count_pattern, output)
        if match:
            metrics['inference_count'] = int(match.group(1))
        
        return metrics if metrics else None
    
    def print_report(self, metrics_list: List[Dict[str, int]]) -> str:
        """Generate benchmark report from metrics"""
        report = []
        report.append("\n")
        report.append("=" * 100)
        report.append("                  ATOMIC INFERENCE WINDOW BENCHMARK                  ")
        report.append("=" * 100)
        report.append(f"\nTarget: STM32L552 Cortex-M33 @ {self.CPU_FREQ_HZ // 1_000_000} MHz")
        report.append("Implementation: CMSIS-NN Split Inference (Early + Late Layers)")
        report.append(f"\nMeasurements collected: {len(metrics_list)}")
        
        if not metrics_list:
            report.append("\n❌ No inference metrics found in output")
            return "\n".join(report)
        
        # Separate by measurement type
        total_infs = [m for m in metrics_list if 'total_inference_cycles' in m]
        early_infs = [m for m in metrics_list if 'early_layers_cycles' in m]
        late_infs = [m for m in metrics_list if 'late_layers_cycles' in m]
        
        report.append(f"\n✓ Total Inferences measured: {len(total_infs)}")
        report.append(f"✓ Early layers measured: {len(early_infs)}")
        report.append(f"✓ Late layers measured: {len(late_infs)}")
        
        # =========================
        # TOTAL INFERENCE STATS
        # =========================
        if total_infs:
            report.append("\n" + "-" * 100)
            report.append("TOTAL INFERENCE (Early + Late + Overhead)")
            report.append("-" * 100)
            
            cycles_list = [m['total_inference_cycles'] for m in total_infs]
            min_cycles = min(cycles_list)
            max_cycles = max(cycles_list)
            avg_cycles = sum(cycles_list) // len(cycles_list)
            
            report.append(f"\nCycles Statistics:")
            report.append(f"  Min:     {min_cycles:>10,} cycles  ({self.cycles_to_ms(min_cycles):>7.2f} ms)")
            report.append(f"  Max:     {max_cycles:>10,} cycles  ({self.cycles_to_ms(max_cycles):>7.2f} ms)")
            report.append(f"  Average: {avg_cycles:>10,} cycles  ({self.cycles_to_ms(avg_cycles):>7.2f} ms)")
            report.append(f"  Range:   {max_cycles - min_cycles:>10,} cycles  ({self.cycles_to_ms(max_cycles - min_cycles):>7.2f} ms)")
            
            # Store summary
            self.data['summary']['total_inference'] = {
                'min_cycles': min_cycles,
                'max_cycles': max_cycles,
                'avg_cycles': avg_cycles,
                'min_ms': round(self.cycles_to_ms(min_cycles), 2),
                'max_ms': round(self.cycles_to_ms(max_cycles), 2),
                'avg_ms': round(self.cycles_to_ms(avg_cycles), 2),
                'count': len(cycles_list)
            }
        
        # =========================
        # EARLY LAYERS STATS
        # =========================
        if early_infs:
            report.append("\n" + "-" * 100)
            report.append("EARLY LAYERS (Enclave-only)" )
            report.append("-" * 100)
            
            cycles_list = [m['early_layers_cycles'] for m in early_infs]
            min_cycles = min(cycles_list)
            max_cycles = max(cycles_list)
            avg_cycles = sum(cycles_list) // len(cycles_list)
            
            report.append(f"\nCycles Statistics:")
            report.append(f"  Min:     {min_cycles:>10,} cycles  ({self.cycles_to_ms(min_cycles):>7.2f} ms)")
            report.append(f"  Max:     {max_cycles:>10,} cycles  ({self.cycles_to_ms(max_cycles):>7.2f} ms)")
            report.append(f"  Average: {avg_cycles:>10,} cycles  ({self.cycles_to_ms(avg_cycles):>7.2f} ms)")
            report.append(f"  Range:   {max_cycles - min_cycles:>10,} cycles  ({self.cycles_to_ms(max_cycles - min_cycles):>7.2f} ms)")
            
            self.data['summary']['early_layers'] = {
                'min_cycles': min_cycles,
                'max_cycles': max_cycles,
                'avg_cycles': avg_cycles,
                'min_ms': round(self.cycles_to_ms(min_cycles), 2),
                'max_ms': round(self.cycles_to_ms(max_cycles), 2),
                'avg_ms': round(self.cycles_to_ms(avg_cycles), 2),
                'count': len(cycles_list)
            }
        
        # =========================
        # LATE LAYERS STATS
        # =========================
        if late_infs:
            report.append("\n" + "-" * 100)
            report.append("LATE LAYERS (Host + Enclave, Encrypted)")
            report.append("-" * 100)
            
            cycles_list = [m['late_layers_cycles'] for m in late_infs]
            min_cycles = min(cycles_list)
            max_cycles = max(cycles_list)
            avg_cycles = sum(cycles_list) // len(cycles_list)
            
            report.append(f"\nCycles Statistics:")
            report.append(f"  Min:     {min_cycles:>10,} cycles  ({self.cycles_to_ms(min_cycles):>7.2f} ms)")
            report.append(f"  Max:     {max_cycles:>10,} cycles  ({self.cycles_to_ms(max_cycles):>7.2f} ms)")
            report.append(f"  Average: {avg_cycles:>10,} cycles  ({self.cycles_to_ms(avg_cycles):>7.2f} ms)")
            report.append(f"  Range:   {max_cycles - min_cycles:>10,} cycles  ({self.cycles_to_ms(max_cycles - min_cycles):>7.2f} ms)")
            
            self.data['summary']['late_layers'] = {
                'min_cycles': min_cycles,
                'max_cycles': max_cycles,
                'avg_cycles': avg_cycles,
                'min_ms': round(self.cycles_to_ms(min_cycles), 2),
                'max_ms': round(self.cycles_to_ms(max_cycles), 2),
                'avg_ms': round(self.cycles_to_ms(avg_cycles), 2),
                'count': len(cycles_list)
            }
        
        # =========================
        # BREAKDOWN
        # =========================
        if early_infs and late_infs and total_infs:
            report.append("\n" + "-" * 100)
            report.append("BREAKDOWN (Early vs Late)")
            report.append("-" * 100)
            
            early_avg = sum(m['early_layers_cycles'] for m in early_infs) // len(early_infs)
            late_avg = sum(m['late_layers_cycles'] for m in late_infs) // len(late_infs)
            total_avg = sum(m['total_inference_cycles'] for m in total_infs) // len(total_infs)
            overhead = total_avg - early_avg - late_avg
            
            report.append(f"\nAverage per inference (cycles):")
            report.append(f"  Early layers:    {early_avg:>10,} cycles  ({self.cycles_to_ms(early_avg):>7.2f} ms)  {100*early_avg/total_avg:>5.1f}%")
            report.append(f"  Late layers:     {late_avg:>10,} cycles  ({self.cycles_to_ms(late_avg):>7.2f} ms)  {100*late_avg/total_avg:>5.1f}%")
            report.append(f"  Overhead:        {overhead:>10,} cycles  ({self.cycles_to_ms(overhead):>7.2f} ms)  {100*overhead/total_avg:>5.1f}%")
            report.append(f"  ──────────────────────────────────────────────")
            report.append(f"  Total:           {total_avg:>10,} cycles  ({self.cycles_to_ms(total_avg):>7.2f} ms)  100.0%")
            
            self.data['summary']['breakdown'] = {
                'early_avg_cycles': early_avg,
                'late_avg_cycles': late_avg,
                'overhead_cycles': overhead,
                'total_avg_cycles': total_avg,
                'early_percent': round(100 * early_avg / total_avg, 1),
                'late_percent': round(100 * late_avg / total_avg, 1),
                'overhead_percent': round(100 * overhead / total_avg, 1)
            }
        
        # =========================
        # MEMORY EFFICIENCY
        # =========================
        report.append("\n" + "-" * 100)
        report.append("MEMORY EFFICIENCY")
        report.append("-" * 100)
        
        # Model size estimate
        early_model_size = 2_500_000  # ~2.5M parameters (estimated)
        late_model_size = 1_200_000   # ~1.2M parameters (encrypted, estimated)
        
        if early_infs:
            early_avg = sum(m['early_layers_cycles'] for m in early_infs) // len(early_infs)
            inferences_per_sec = self.CPU_FREQ_HZ / early_avg
            report.append(f"\nEarly layers throughput:")
            report.append(f"  Cycles per inference:  {early_avg:,}")
            report.append(f"  Inferences per second: {inferences_per_sec:.1f}")
            report.append(f"  Latency:               {self.cycles_to_ms(early_avg):.2f} ms")
        
        report.append("\n" + "=" * 100)
        
        return "\n".join(report)
    
    def save_results(self, filename: str) -> None:
        """Save results to JSON file"""
        output_file = self.build_dir / filename
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(self.data, f, indent=2)
        
        print(f"\n✓ Results saved to: {output_file}")


def main():
    # Change to project directory
    project_dir = Path(__file__).parent.parent.absolute()
    
    print("""
╔═══════════════════════════════════════════════════════════╗
║   Atomic Inference Window Benchmark Analysis Tool         ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    print(f"Project directory: {project_dir}")
    
    # Try to read from pre-captured output or benchmark report
    build_dir = project_dir / "build"
    
    if not build_dir.exists():
        print("⚠️  Build directory not found. Please build the project first:")
        print(f"   cd {project_dir}")
        print("   west build -p auto -b mps3/corstone300/fvp .")
        return 1
    
    benchmark = AtomicInferenceBenchmark(str(project_dir))
    
    # Look for benchmark report files
    possible_reports = [
        build_dir / "TCB_EXTRACTION_DATA.json",
        build_dir / "benchmark_report.txt",
        build_dir / "inference_metrics.txt"
    ]
    
    metrics_list = []
    
    # Try to find and parse metrics from console output or files
    for report_file in possible_reports:
        if report_file.exists():
            print(f"   Reading: {report_file}")
            with open(report_file, 'r') as f:
                content = f.read()
                metrics = benchmark.extract_inference_metrics(content)
                if metrics:
                    metrics_list.append(metrics)
    
    if not metrics_list:
        print("\n⚠️  No inference metrics found in build artifacts.")
        print("\nTo generate metrics, run:")
        print(f"   cd {project_dir}")
        print("   west build -p auto -b mps3/corstone300/fvp . -T sample.tensorflow.helloworld.cmsis_nn")
        print("   west build -t run")
        print("\nThe benchmark will extract cycle measurements from the console output.")
        return 1
    
    # Generate and print report
    report = benchmark.print_report(metrics_list)
    print(report)
    
    # Save results
    benchmark.save_results("ATOMIC_INFERENCE_BENCHMARK.json")
    print(report)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
