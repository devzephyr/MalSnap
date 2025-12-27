#!/usr/bin/env python3
"""
MalSnap - Automated Malware Static Analysis Tool
Author: Adeyemi Folarin
Description: Fast static analysis for PE files with intelligent threat detection
"""

import os
import sys
import json
import hashlib
import math
import re
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

try:
    import pefile
    import yara
except ImportError as e:
    print(f"[!] Missing required library: {e}")
    print("[!] Install dependencies: pip install -r requirements.txt")
    sys.exit(1)

# Optional Textual import for interactive TUI
try:
    from textual.app import App, ComposeResult
    from textual.containers import Container, ScrollableContainer
    from textual.widgets import Header, Footer, Label, Static, TabbedContent, TabPane, DataTable, ProgressBar
    from textual.binding import Binding
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


class MalSnap:
    """Main malware analysis engine"""

    # Suspicious API calls commonly used by malware
    SUSPICIOUS_IMPORTS = {
        'VirtualAlloc': 'Memory allocation (possible code injection)',
        'VirtualAllocEx': 'Remote memory allocation (process injection)',
        'WriteProcessMemory': 'Write to another process (injection)',
        'CreateRemoteThread': 'Remote thread creation (injection)',
        'LoadLibrary': 'Dynamic library loading',
        'GetProcAddress': 'Dynamic API resolution (anti-analysis)',
        'WinExec': 'Command execution',
        'ShellExecute': 'Shell command execution',
        'URLDownloadToFile': 'File download from internet',
        'InternetOpen': 'Internet connection',
        'CreateProcess': 'Process creation',
        'RegSetValue': 'Registry modification',
        'RegCreateKey': 'Registry key creation',
        'CryptEncrypt': 'Encryption (possible ransomware)',
        'CryptDecrypt': 'Decryption',
        'SetWindowsHookEx': 'Keyboard/mouse hook (keylogger)',
        'GetAsyncKeyState': 'Keylogging capability',
        'OpenProcess': 'Process manipulation',
        'IsDebuggerPresent': 'Anti-debugging',
        'FindWindow': 'Window detection (anti-analysis)',
    }

    def __init__(self, file_path: str, yara_rules_path: Optional[str] = None):
        self.file_path = Path(file_path)
        self.yara_rules = None

        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if yara_rules_path and Path(yara_rules_path).exists():
            try:
                self.yara_rules = yara.compile(filepath=yara_rules_path)
            except Exception as e:
                print(f"[!] Failed to compile YARA rules: {e}")

        self.results: Dict[str, Any] = {
            'file_info': {},
            'hashes': {},
            'pe_info': {},
            'strings': {},
            'imports': {},
            'entropy': {},
            'yara_matches': [],
            'threat_score': 0,
            'analysis_timestamp': datetime.now().isoformat()
        }

    def calculate_hashes(self) -> Dict[str, str]:
        """Calculate file hashes for threat intelligence"""
        hashes = {}

        with open(self.file_path, 'rb') as f:
            data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()

        return hashes

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy to detect packing/encryption"""
        if not data:
            return 0.0

        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)

        return entropy

    def analyze_pe(self) -> Dict[str, Any]:
        """Analyze PE file structure"""
        try:
            pe = pefile.PE(str(self.file_path))

            pe_info = {
                'is_dll': pe.is_dll(),
                'is_exe': pe.is_exe(),
                'is_driver': pe.is_driver(),
                'compilation_timestamp': datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(),
                'target_machine': pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine],
                'number_of_sections': pe.FILE_HEADER.NumberOfSections,
                'sections': []
            }

            # Analyze sections
            for section in pe.sections:
                section_entropy = self.calculate_entropy(section.get_data())

                section_info = {
                    'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                    'virtual_address': hex(section.VirtualAddress),
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': round(section_entropy, 2),
                    'suspicious': section_entropy > 7.0  # High entropy suggests packing
                }
                pe_info['sections'].append(section_info)

            # Calculate overall entropy
            with open(self.file_path, 'rb') as f:
                overall_entropy = self.calculate_entropy(f.read())

            self.results['entropy'] = {
                'overall': round(overall_entropy, 2),
                'is_packed': overall_entropy > 7.0,
                'analysis': 'Likely packed/encrypted' if overall_entropy > 7.0 else 'Not packed'
            }

            pe.close()
            return pe_info

        except Exception as e:
            return {'error': f'Failed to parse PE: {str(e)}'}

    def extract_strings(self, min_length: int = 4) -> Dict[str, List[str]]:
        """Extract ASCII and Unicode strings from binary"""
        with open(self.file_path, 'rb') as f:
            data = f.read()

        # ASCII strings
        ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        ascii_strings = [s.decode('ascii') for s in re.findall(ascii_pattern, data)]

        # Unicode strings (UTF-16 LE)
        unicode_pattern = b'(?:[\x20-\x7E][\x00]){' + str(min_length).encode() + b',}'
        unicode_strings = [s.decode('utf-16-le', errors='ignore')
                          for s in re.findall(unicode_pattern, data)]

        # Filter interesting strings
        interesting = self._filter_interesting_strings(ascii_strings + unicode_strings)

        return {
            'total_ascii': len(ascii_strings),
            'total_unicode': len(unicode_strings),
            'interesting': interesting[:50]  # Top 50 interesting strings
        }

    def _filter_interesting_strings(self, strings: List[str]) -> List[str]:
        """Filter for potentially malicious or interesting strings"""
        patterns = [
            r'(?i)https?://[^\s]+',  # URLs
            r'(?i)ftp://[^\s]+',
            r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',  # IP addresses
            r'(?i).*\.exe\b',  # Executables
            r'(?i).*\.dll\b',  # DLLs
            r'(?i).*(password|passwd|pwd|pass).*',  # Password related
            r'(?i).*(admin|root|user).*',  # User accounts
            r'(?i).*(cmd|powershell|bash).*',  # Shell commands
            r'(?i).*(registry|regedit).*',  # Registry
            r'(?i).*(backdoor|trojan|virus|malware).*',  # Malware indicators
            r'SOFTWARE\\\\Microsoft\\\\Windows',  # Registry paths
            r'\\\\[^\\]+\\\\[^\\]+\$',  # Network shares
        ]

        interesting = set()
        for string in strings:
            for pattern in patterns:
                if re.search(pattern, string):
                    interesting.add(string)
                    break

        return sorted(list(interesting))

    def analyze_imports(self) -> Dict[str, Any]:
        """Analyze imported DLLs and functions for suspicious APIs"""
        try:
            pe = pefile.PE(str(self.file_path))

            imports = {
                'dlls': [],
                'suspicious_apis': [],
                'total_imports': 0
            }

            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                return imports

            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                dll_imports = []

                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        dll_imports.append(func_name)
                        imports['total_imports'] += 1

                        # Check for suspicious APIs
                        if func_name in self.SUSPICIOUS_IMPORTS:
                            imports['suspicious_apis'].append({
                                'function': func_name,
                                'dll': dll_name,
                                'description': self.SUSPICIOUS_IMPORTS[func_name]
                            })

                imports['dlls'].append({
                    'name': dll_name,
                    'imports': dll_imports[:20]  # Limit to first 20 for readability
                })

            pe.close()
            return imports

        except Exception as e:
            return {'error': f'Failed to analyze imports: {str(e)}'}

    def run_yara_scan(self) -> List[Dict[str, Any]]:
        """Run YARA rules against the file"""
        if not self.yara_rules:
            return []

        try:
            matches = self.yara_rules.match(str(self.file_path))
            return [{'rule': match.rule, 'tags': match.tags} for match in matches]
        except Exception as e:
            return [{'error': f'YARA scan failed: {str(e)}'}]

    def calculate_threat_score(self) -> int:
        """Calculate threat score based on analysis results (0-100)"""
        score = 0

        # High entropy (packed)
        if self.results['entropy'].get('is_packed'):
            score += 20

        # Suspicious imports
        suspicious_count = len(self.results['imports'].get('suspicious_apis', []))
        score += min(suspicious_count * 5, 30)  # Max 30 points

        # YARA matches
        yara_matches = len(self.results['yara_matches'])
        score += min(yara_matches * 15, 30)  # Max 30 points

        # Interesting strings (URLs, IPs, etc.)
        interesting_strings = len(self.results['strings'].get('interesting', []))
        score += min(interesting_strings * 2, 20)  # Max 20 points

        return min(score, 100)

    def analyze(self) -> Dict[str, Any]:
        """Run full analysis pipeline"""
        print(f"[*] Analyzing: {self.file_path.name}")

        # File info
        self.results['file_info'] = {
            'name': self.file_path.name,
            'path': str(self.file_path.absolute()),
            'size': self.file_path.stat().st_size,
            'size_readable': f"{self.file_path.stat().st_size / 1024:.2f} KB"
        }

        print("[*] Calculating hashes...")
        self.results['hashes'] = self.calculate_hashes()

        print("[*] Analyzing PE structure...")
        self.results['pe_info'] = self.analyze_pe()

        print("[*] Extracting strings...")
        self.results['strings'] = self.extract_strings()

        print("[*] Analyzing imports...")
        self.results['imports'] = self.analyze_imports()

        if self.yara_rules:
            print("[*] Running YARA scan...")
            self.results['yara_matches'] = self.run_yara_scan()

        print("[*] Calculating threat score...")
        self.results['threat_score'] = self.calculate_threat_score()

        return self.results

    def generate_report(self, output_format: str = 'json') -> str:
        """Generate analysis report"""
        if output_format == 'json':
            return json.dumps(self.results, indent=2)

        # Text report
        report = []
        report.append("=" * 80)
        report.append(f"MalSnap Analysis Report - {self.results['file_info']['name']}")
        report.append("=" * 80)
        report.append(f"\nFile Information:")
        report.append(f"  Path: {self.results['file_info']['path']}")
        report.append(f"  Size: {self.results['file_info']['size_readable']}")
        report.append(f"\nHashes:")
        report.append(f"  MD5:    {self.results['hashes']['md5']}")
        report.append(f"  SHA1:   {self.results['hashes']['sha1']}")
        report.append(f"  SHA256: {self.results['hashes']['sha256']}")

        report.append(f"\nEntropy Analysis:")
        report.append(f"  Overall Entropy: {self.results['entropy']['overall']}")
        report.append(f"  Assessment: {self.results['entropy']['analysis']}")

        if self.results['imports'].get('suspicious_apis'):
            report.append(f"\nSuspicious API Calls ({len(self.results['imports']['suspicious_apis'])}):")
            for api in self.results['imports']['suspicious_apis'][:10]:
                report.append(f"  - {api['function']} ({api['dll']})")
                report.append(f"    {api['description']}")

        if self.results['yara_matches']:
            report.append(f"\nYARA Matches:")
            for match in self.results['yara_matches']:
                report.append(f"  - {match['rule']}")

        report.append(f"\n{'=' * 80}")
        report.append(f"THREAT SCORE: {self.results['threat_score']}/100")

        if self.results['threat_score'] < 30:
            report.append("Assessment: LOW RISK")
        elif self.results['threat_score'] < 60:
            report.append("Assessment: MEDIUM RISK")
        else:
            report.append("Assessment: HIGH RISK")

        report.append("=" * 80)

        return "\n".join(report)


class MalSnapTUI(App):
    """Interactive malware analysis TUI built with Textual"""

    CSS = """
    Screen {
        background: $surface;
    }

    #info-panel {
        height: auto;
        border: solid $primary;
        padding: 1;
        margin: 1;
    }

    #threat-score {
        height: 7;
        border: solid $accent;
        padding: 1;
        margin: 1;
        content-align: center middle;
    }

    #progress-container {
        height: 5;
        padding: 1;
        margin: 1;
    }

    .green { color: $success; }
    .yellow { color: $warning; }
    .red { color: $error; }
    .cyan { color: $primary; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("r", "reload", "Reload Analysis"),
    ]

    def __init__(self, file_path: str, yara_rules: str = None):
        super().__init__()
        self.file_path = file_path
        self.yara_rules = yara_rules
        self.results = None

    def compose(self) -> ComposeResult:
        """Create child widgets"""
        yield Header()

        with Container(id="progress-container"):
            yield Label(f"Analyzing: {Path(self.file_path).name}", id="status")
            yield ProgressBar(total=100, show_eta=False, id="progress")

        with TabbedContent():
            with TabPane("Overview"):
                yield ScrollableContainer(id="overview")
            with TabPane("PE Structure"):
                yield ScrollableContainer(id="pe-structure")
            with TabPane("Imports"):
                yield ScrollableContainer(id="imports")
            with TabPane("Strings"):
                yield ScrollableContainer(id="strings")

        yield Footer()

    def on_mount(self) -> None:
        """Run analysis when app starts"""
        self.run_worker(self.analyze_file(), exclusive=True)

    async def analyze_file(self) -> None:
        """Analyze file in background worker"""
        try:
            analyzer = MalSnap(self.file_path, self.yara_rules)
            progress = self.query_one(ProgressBar)

            # Update progress during analysis
            progress.update(progress=20)
            analyzer.results['file_info'] = {
                'name': analyzer.file_path.name,
                'size_readable': f"{analyzer.file_path.stat().st_size / 1024:.2f} KB"
            }
            analyzer.results['hashes'] = analyzer.calculate_hashes()

            progress.update(progress=40)
            analyzer.results['pe_info'] = analyzer.analyze_pe()

            progress.update(progress=60)
            analyzer.results['strings'] = analyzer.extract_strings()

            progress.update(progress=80)
            analyzer.results['imports'] = analyzer.analyze_imports()
            analyzer.results['entropy'] = analyzer.results.get('entropy', {})

            if analyzer.yara_rules:
                analyzer.results['yara_matches'] = analyzer.run_yara_scan()

            progress.update(progress=100)
            analyzer.results['threat_score'] = analyzer.calculate_threat_score()

            self.results = analyzer.results

            # Update UI
            self.display_results()

        except Exception as e:
            self.notify(f"Error: {e}", severity="error")

    def display_results(self) -> None:
        """Display analysis results in UI"""
        if not self.results:
            return

        # Hide progress
        self.query_one("#progress-container").display = False

        # Overview tab
        overview = self.query_one("#overview")
        overview.mount(self._create_file_info())
        overview.mount(self._create_entropy_info())
        overview.mount(self._create_threat_score())

        # PE Structure tab
        pe_container = self.query_one("#pe-structure")
        pe_container.mount(self._create_pe_table())

        # Imports tab
        imports_container = self.query_one("#imports")
        imports_container.mount(self._create_imports_list())

        # Strings tab
        strings_container = self.query_one("#strings")
        strings_container.mount(self._create_strings_list())

        self.notify("Analysis complete!", severity="information")

    def _create_file_info(self) -> Static:
        """Create file information widget"""
        info = self.results['file_info']
        hashes = self.results['hashes']

        content = f"""[bold cyan]File Information[/bold cyan]
Name:    {info['name']}
Size:    {info['size_readable']}

[bold cyan]Hashes[/bold cyan]
MD5:     [yellow]{hashes['md5']}[/yellow]
SHA1:    [yellow]{hashes['sha1']}[/yellow]
SHA256:  [yellow]{hashes['sha256']}[/yellow]
"""
        return Static(content, classes="info-panel")

    def _create_entropy_info(self) -> Static:
        """Create entropy analysis widget"""
        entropy = self.results.get('entropy', {})

        if entropy.get('is_packed'):
            status = "[bold red]⚠ LIKELY PACKED/ENCRYPTED[/bold red]"
        else:
            status = "[bold green]✓ Not Packed[/bold green]"

        content = f"""[bold cyan]Entropy Analysis[/bold cyan]
Overall: [yellow]{entropy.get('overall', 0)}[/yellow]
Status:  {status}
"""
        return Static(content, classes="info-panel")

    def _create_threat_score(self) -> Static:
        """Create threat score widget"""
        score = self.results['threat_score']

        if score < 30:
            color = "green"
            assessment = "LOW RISK ✓"
        elif score < 60:
            color = "yellow"
            assessment = "MEDIUM RISK ⚠"
        else:
            color = "red"
            assessment = "HIGH RISK ⚠"

        filled = int(score / 5)
        empty = 20 - filled
        bar = "█" * filled + "░" * empty

        content = f"""
[bold]THREAT SCORE[/bold]

[bold {color}]{score}/100[/bold {color}]

{bar}

Assessment: [bold {color}]{assessment}[/bold {color}]
"""
        return Static(content, id="threat-score")

    def _create_pe_table(self) -> DataTable:
        """Create PE sections table"""
        table = DataTable()
        table.add_columns("Section", "V.Addr", "V.Size", "Entropy", "Status")

        pe_info = self.results.get('pe_info', {})
        for section in pe_info.get('sections', []):
            status = "⚠" if section.get('suspicious') else "✓"
            table.add_row(
                section['name'],
                section['virtual_address'],
                str(section['virtual_size']),
                str(section['entropy']),
                status
            )

        return table

    def _create_imports_list(self) -> Static:
        """Create suspicious imports list"""
        imports = self.results.get('imports', {})
        suspicious = imports.get('suspicious_apis', [])

        if not suspicious:
            return Static("[green]No suspicious API calls detected[/green]")

        content = "[bold red]Suspicious API Calls[/bold red]\n\n"
        for api in suspicious[:20]:
            content += f"[red]• {api['function']}[/red] ({api['dll']})\n  {api['description']}\n\n"

        return Static(content)

    def _create_strings_list(self) -> Static:
        """Create interesting strings list"""
        strings = self.results.get('strings', {})
        interesting = strings.get('interesting', [])

        if not interesting:
            return Static("[dim]No interesting strings found[/dim]")

        content = "[bold yellow]Interesting Strings[/bold yellow]\n\n"
        for s in interesting[:30]:
            content += f"[yellow]• {s}[/yellow]\n"

        if len(interesting) > 30:
            content += f"\n[dim]... and {len(interesting) - 30} more[/dim]"

        return Static(content)

    def action_reload(self) -> None:
        """Reload analysis"""
        self.notify("Reloading analysis...")
        self.run_worker(self.analyze_file(), exclusive=True)


def main():
    parser = argparse.ArgumentParser(
        description='MalSnap - Automated Malware Static Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  malsnap.py sample.exe                          # Interactive TUI (default)
  malsnap.py sample.exe --yara rules.yar         # TUI with YARA
  malsnap.py sample.exe --format json -o out.json  # JSON for automation
  malsnap.py sample.exe --format text            # Plain text output
        """
    )

    parser.add_argument('file', help='File to analyze')
    parser.add_argument('--yara', '-y', help='YARA rules file')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--format', '-f', choices=['text', 'json'],
                       default='tui', help='Output format (default: interactive TUI)')

    args = parser.parse_args()

    try:
        # Default to interactive TUI unless format specified or output file given
        if args.format == 'tui' and not args.output:
            if not TEXTUAL_AVAILABLE:
                print("[!] Textual library not installed. Falling back to text output.")
                print("[!] Install with: pip install textual")
                args.format = 'text'
            else:
                # Run interactive TUI
                app = MalSnapTUI(args.file, args.yara)
                app.run()
                return

        # For text/json or when saving to file
        analyzer = MalSnap(args.file, args.yara)
        analyzer.analyze()

        report = analyzer.generate_report(args.format)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"\n[+] Report saved to: {args.output}")
        else:
            print("\n" + report)

        print(f"\n[+] Analysis complete!")

    except FileNotFoundError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
