#!/usr/bin/env python3
"""
Advanced TCB Size Extractor v2 - Extract nested structures, constants, and alignment
"""

import re
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Set
from enum import Enum

# C type sizes and alignment (assuming Cortex-M33 / STM32L5 ABI)
C_TYPE_SIZES = {
    'uint8_t': (1, 1),
    'int8_t': (1, 1),
    'uint16_t': (2, 2),
    'int16_t': (2, 2),
    'uint32_t': (4, 4),
    'int32_t': (4, 4),
    'uint64_t': (8, 8),
    'int64_t': (8, 8),
    'bool': (1, 1),
    'char': (1, 1),
    'float': (4, 4),
    'double': (8, 8),
    'psa_key_id_t': (4, 4),
    'size_t': (8, 8),
    'psa_status_t': (4, 4),
}

@dataclass
class StructField:
    """Represents a field in a structure"""
    name: str
    type_str: str
    array_size: Optional[int] = None
    offset: int = 0
    
    def size(self, struct_cache: Dict = None) -> int:
        """Calculate field size including arrays"""
        struct_cache = struct_cache or {}
        base_type = self.type_str.strip('*')
        
        # Remove array brackets for type lookup
        clean_type = re.sub(r'\[.*?\]', '', base_type).strip()
        
        # Check if it's a struct (try to use cached size)
        if clean_type in struct_cache:
            size = struct_cache[clean_type]
        elif clean_type in C_TYPE_SIZES:
            size = C_TYPE_SIZES[clean_type][0]
        elif '*' in self.type_str:
            size = 8  # 64-bit pointer
        else:
            print(f"    [WARN] Unknown type: {clean_type}, assuming 4 bytes")
            size = 4
        
        # Apply array multiplier
        if self.array_size:
            size *= self.array_size
        else:
            match = re.search(r'\[(\d+)\]', self.type_str)
            if match:
                size *= int(match.group(1))
        
        return size
    
    def alignment(self, struct_cache: Dict = None) -> int:
        """Get alignment requirement"""
        struct_cache = struct_cache or {}
        base_type = self.type_str.strip('*').split('[')[0].strip()
        
        if base_type in struct_cache and isinstance(struct_cache[base_type], tuple):
            return struct_cache[base_type][1]
        elif base_type in C_TYPE_SIZES:
            return C_TYPE_SIZES[base_type][1]
        elif '*' in self.type_str:
            return 8
        return 1

@dataclass
class StructDef:
    """Represents a struct definition"""
    name: str
    fields: List[StructField] = field(default_factory=list)
    
    def calculate_size(self, struct_cache: Dict = None) -> int:
        """Calculate total struct size with alignment"""
        struct_cache = struct_cache or {}
        total = 0
        max_align = 1
        
        for field in self.fields:
            align = field.alignment(struct_cache)
            max_align = max(max_align, align)
            
            # Align current position
            if total % align != 0:
                total += align - (total % align)
            
            total += field.size(struct_cache)
        
        # Final padding to struct alignment
        if total % max_align != 0:
            total += max_align - (total % max_align)
        
        return total

class TCBExtractorV2:
    """Advanced TCB extractor with structure support"""
    
    def __init__(self, source_dir: Path):
        self.source_dir = Path(source_dir)
        self.variables: Dict[str, StructField] = {}
        self.structs: Dict[str, StructDef] = {}
        self.constants: Dict[str, int] = {}
        self.total_size = 0
        self.files_parsed = []
        
    def extract_all_files(self, pattern: str = "*.c") -> None:
        """Extract from all matching files"""
        for file in self.source_dir.glob(pattern):
            print(f"[*] Scanning {file.name}...")
            self._extract_from_file(file)
    
    def _extract_from_file(self, file_path: Path) -> None:
        """Extract variables, structs, and constants from file"""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
        except Exception as e:
            print(f"  [ERR] Cannot read {file_path}: {e}")
            return
        
        # Remove multi-line comments
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        # Remove single-line comments
        content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
        
        # Extract #define constants
        self._extract_constants(content)
        
        # Extract struct definitions
        self._extract_struct_definitions(content)
        
        # Extract variable declarations
        self._extract_variables(content)
        
        self.files_parsed.append(file_path.name)
    
    def _extract_constants(self, content: str) -> None:
        """Extract #define constants"""
        pattern = r'#define\s+(\w+)\s+(\d+)'
        
        for match in re.finditer(pattern, content):
            const_name = match.group(1)
            const_value = int(match.group(2))
            
            if 'SIZE' in const_name or 'LEN' in const_name:
                self.constants[const_name] = const_value
    
    def _extract_struct_definitions(self, content: str) -> None:
        """Extract struct definitions"""
        # Pattern: typedef struct { ... } name;
        pattern = r'(?:typedef\s+)?struct\s+(\w*)\s*\{(.*?)\}\s*(\w+)?\s*;'
        
        for match in re.finditer(pattern, content, re.DOTALL):
            struct_name_in_def = match.group(1) or match.group(3) or 'anonymous'
            body = match.group(2)
            
            fields = self._parse_struct_body(body)
            if fields:
                struct_obj = StructDef(struct_name_in_def, fields)
                self.structs[struct_name_in_def] = struct_obj
    
    def _parse_struct_body(self, body: str) -> List[StructField]:
        """Parse struct body to extract fields"""
        fields = []
        
        # Split by semicolons
        lines = body.split(';')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Pattern: type name[size]
            # Handle: uint8_t name[size], int32_t var, etc.
            match = re.match(r'(\w+(?:\s+\w+)*?)\s+(\w+)(?:\[(\d+)\])?$', line)
            
            if match:
                type_str = match.group(1)
                name = match.group(2)
                array_size = int(match.group(3)) if match.group(3) else None
                
                field = StructField(name, type_str, array_size)
                fields.append(field)
        
        return fields
    
    def _extract_variables(self, content: str) -> None:
        """Extract static variable declarations"""
        # Pattern: static type name[size] = ...;
        pattern = r'static\s+((?:const\s+)?(?:struct\s+)?[\w\s\*]+?)\s+(\w+)(?:\[(\d+)\])?\s*(?:=|;)'
        
        for match in re.finditer(pattern, content):
            type_decl = match.group(1).strip()
            var_name = match.group(2).strip()
            array_size = int(match.group(3)) if match.group(3) else None
            
            if self._is_tcb_relevant(var_name):
                field = StructField(var_name, type_decl, array_size)
                self.variables[var_name] = field
                
                size = field.size(self.structs)
                self.total_size += size
                
                print(f"  ✓ {var_name:45s} : {size:4d} bytes")
    
    def _is_tcb_relevant(self, var_name: str) -> bool:
        """Check if variable is TCB-critical"""
        tcb_keywords = [
            'session_key', 'session_key_set',
            '_pk_v', '_model_id', '_cert', '_cert_len', '_auth',
            'counter', 'counter_limit', 'counter_secure',
            'model_pub', 'model_secret', 'code_hash', 'model_info',
            'enclave_info', 'boot_enclave',
            'device_sign', 'device_pubkey', 'device_key',
            '_tx_', '_tx', 'transaction',
            'sau_', 'inference_counter', 'max_inferences',
        ]
        
        return any(kw in var_name.lower() for kw in tcb_keywords)
    
    def get_categories(self) -> Dict[str, List[Tuple[str, int]]]:
        """Categorize variables"""
        categories = {
            'ECDH Session & Keys': [],
            'M_update Authorization': [],
            'Model Identity & Crypto': [],
            'EnclaveInfo & Attestation': [],
            'Enclave Lifecycle': [],
            'Device Keys & Transactions': [],
            'SAU Memory Protection': [],
            'Counters & State': [],
        }
        
        for var_name, field in self.variables.items():
            size = field.size(self.structs)
            
            if any(kw in var_name for kw in ['session_key']):
                categories['ECDH Session & Keys'].append((var_name, size))
            elif any(kw in var_name for kw in ['s_pk_v', 's_cert', 's_auth', 's_model_id']):
                categories['M_update Authorization'].append((var_name, size))
            elif any(kw in var_name for kw in ['current_model', 'current_code']):
                categories['Model Identity & Crypto'].append((var_name, size))
            elif any(kw in var_name for kw in ['enclave_info', 'boot_']):
                categories['EnclaveInfo & Attestation'].append((var_name, size))
            elif any(kw in var_name for kw in ['inference_counter', 'max_inferences', 'enclave_created']):
                categories['Enclave Lifecycle'].append((var_name, size))
            elif any(kw in var_name for kw in ['s_device', 's_tx']):
                categories['Device Keys & Transactions'].append((var_name, size))
            elif any(kw in var_name for kw in ['sau_']):
                categories['SAU Memory Protection'].append((var_name, size))
            else:
                categories['Counters & State'].append((var_name, size))
        
        return {k: v for k, v in categories.items() if v}
    
    def generate_report(self) -> str:
        """Generate comprehensive TCB report"""
        lines = []
        lines.append("\n" + "="*100)
        lines.append("TCB SIZE ANALYSIS v2 - Advanced Extraction with Structure Support".center(100))
        lines.append("="*100)
        
        lines.append(f"\nFiles analyzed: {', '.join(self.files_parsed)}")
        lines.append(f"Structures detected: {len(self.structs)}")
        lines.append(f"Constants extracted: {len(self.constants)}")
        
        if self.structs:
            lines.append("\n" + "-"*100)
            lines.append("DETECTED STRUCTURES")
            lines.append("-"*100)
            for struct_name, struct_def in sorted(self.structs.items()):
                struct_size = struct_def.calculate_size(self.structs)
                lines.append(f"  struct {struct_name:30s} : {struct_size:5d} bytes ({len(struct_def.fields):2d} fields)")
                for field in struct_def.fields:
                    f_size = field.size(self.structs)
                    lines.append(f"    - {field.name:30s} : {f_size:5d} bytes")
        
        if self.constants:
            lines.append("\n" + "-"*100)
            lines.append("EXTRACTED CONSTANTS")
            lines.append("-"*100)
            for const_name in sorted(self.constants.keys()):
                lines.append(f"  #define {const_name:30s} {self.constants[const_name]:6d}")
        
        # Category breakdown
        lines.append("\n" + "="*100)
        lines.append("TCB BREAKDOWN BY CATEGORY")
        lines.append("="*100)
        
        categories = self.get_categories()
        category_totals = {}
        
        for category, variables in sorted(categories.items()):
            if not variables:
                continue
            
            cat_total = sum(size for _, size in variables)
            category_totals[category] = cat_total
            
            lines.append(f"\n{category.upper()}")
            lines.append("-" * 100)
            
            for var_name, size in sorted(variables, key=lambda x: -x[1]):
                pct = (size / cat_total * 100) if cat_total > 0 else 0
                lines.append(f"  {var_name:45s} : {size:5d} bytes ({pct:5.1f}%)")
            
            lines.append('  ' + '-' * 45 + '   ' + f'{cat_total:5d} bytes')
        
        # Grand totals
        lines.append("\n" + "="*100)
        lines.append("SUMMARY & TOTALS")
        lines.append("="*100)
        
        for category in sorted(category_totals.keys(), key=lambda x: -category_totals[x]):
            total = category_totals[category]
            pct = (total / self.total_size * 100) if self.total_size > 0 else 0
            lines.append(f"{category:45s} : {total:5d} bytes ({pct:5.1f}%)")
        
        lines.append("-" * 100)
        lines.append(f"{'TOTAL SECURE PARTITION TCB':45s} : {self.total_size:5d} bytes ({self.total_size/1024:.2f} KB)")
        lines.append("")
        lines.append("NOTE: PSA Crypto service is already protected within TF-M Secure World")
        lines.append("      (no additional TCB overhead to measure)")
        
        lines.append("="*100)
        
        # Memory efficiency
        lines.append("\nMEMORY EFFICIENCY METRICS")
        lines.append("-"*100)
        max_secure_ram = 64 * 1024  # STM32L552 Secure RAM
        tcb_pct = (self.total_size / max_secure_ram * 100)
        lines.append(f"TCB as % of available Secure RAM:      {tcb_pct:6.2f}% ({self.total_size}/{max_secure_ram} bytes)")
        lines.append(f"Secure RAM remaining for other uses:   {max_secure_ram - self.total_size:6d} bytes")
        
        lines.append("="*100)
        
        return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        workspace = Path.cwd()
    else:
        workspace = Path(sys.argv[1])
    
    # Look for source files
    dummy_partition_dir = workspace / "dummy_partition"
    src_dir = workspace / "src"
    
    extractor = TCBExtractorV2(dummy_partition_dir)
    
    # Extract from dummy_partition
    if dummy_partition_dir.exists():
        extractor.extract_all_files("*.c")
    
    # Also try src directory
    if src_dir.exists():
        for file in src_dir.glob("secure*.c"):
            print(f"[*] Also scanning {file.name}...")
            extractor._extract_from_file(file)
    
    # Generate report
    report = extractor.generate_report()
    print(report)
    
    # Save report
    output_file = workspace / "build" / "TCB_EXTRACTION_REPORT.txt"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        f.write(report)
    
    print(f"\n[✓] Report saved to {output_file}")
    
    # Also save JSON for further analysis
    import json
    json_output = {
        'total_tcb_bytes': extractor.total_size,
        'variables': {
            name: {'type': field.type_str, 'size': field.size(extractor.structs)}
            for name, field in extractor.variables.items()
        },
        'categories': {
            cat: {var: size for var, size in vars}
            for cat, vars in extractor.get_categories().items()
        },
        'structures': {
            name: {'fields': len(struct.fields), 'size': struct.calculate_size(extractor.structs)}
            for name, struct in extractor.structs.items()
        }
    }
    
    json_file = workspace / "build" / "TCB_EXTRACTION_DATA.json"
    with open(json_file, 'w') as f:
        json.dump(json_output, f, indent=2)
    
    print(f"[✓] JSON data saved to {json_file}")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
