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

# Optional Rich import for TUI
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


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


class TUIRenderer:
    """Beautiful TUI renderer for analysis results"""

    def __init__(self):
        if not RICH_AVAILABLE:
            raise ImportError("Rich library required for TUI mode")
        self.console = Console()

    def display_banner(self):
        """Display ASCII banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ███╗   ███╗ █████╗ ██╗     ███████╗███╗   ██╗ █████╗ ██████╗║
║   ████╗ ████║██╔══██╗██║     ██╔════╝████╗  ██║██╔══██╗██╔══██║
║   ██╔████╔██║███████║██║     ███████╗██╔██╗ ██║███████║██████╔╝║
║   ██║╚██╔╝██║██╔══██║██║     ╚════██║██║╚██╗██║██╔══██║██╔═══╝ ║
║   ██║ ╚═╝ ██║██║  ██║███████╗███████║██║ ╚████║██║  ██║██║     ║
║   ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ║
║                                                               ║
║         Automated Malware Static Analysis Tool               ║
║                   By Adeyemi Folarin                          ║
╚═══════════════════════════════════════════════════════════════╝
"""
        self.console.print(banner, style="bold cyan")

    def analyze_with_progress(self, analyzer: MalSnap):
        """Run analysis with progress indicators"""
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=self.console
        ) as progress:

            task0 = progress.add_task("[cyan]Gathering file info...", total=1)
            analyzer.results['file_info'] = {
                'name': analyzer.file_path.name,
                'path': str(analyzer.file_path.absolute()),
                'size': analyzer.file_path.stat().st_size,
                'size_readable': f"{analyzer.file_path.stat().st_size / 1024:.2f} KB"
            }
            progress.update(task0, advance=1)

            task1 = progress.add_task("[cyan]Calculating hashes...", total=1)
            analyzer.results['hashes'] = analyzer.calculate_hashes()
            progress.update(task1, advance=1)

            task2 = progress.add_task("[cyan]Analyzing PE structure...", total=1)
            analyzer.results['pe_info'] = analyzer.analyze_pe()
            progress.update(task2, advance=1)

            task3 = progress.add_task("[cyan]Extracting strings...", total=1)
            analyzer.results['strings'] = analyzer.extract_strings()
            progress.update(task3, advance=1)

            task4 = progress.add_task("[cyan]Analyzing imports...", total=1)
            analyzer.results['imports'] = analyzer.analyze_imports()
            progress.update(task4, advance=1)

            if analyzer.yara_rules:
                task5 = progress.add_task("[cyan]Running YARA scan...", total=1)
                analyzer.results['yara_matches'] = analyzer.run_yara_scan()
                progress.update(task5, advance=1)

            task6 = progress.add_task("[cyan]Calculating threat score...", total=1)
            analyzer.results['threat_score'] = analyzer.calculate_threat_score()
            progress.update(task6, advance=1)

    def display_results(self, results: Dict[str, Any]):
        """Display analysis results in beautiful TUI format"""
        self.console.print("\n")

        # File info panels
        self.console.print(self._create_file_info_panel(results))
        self.console.print(self._create_pe_info_panel(results))
        self.console.print(self._create_entropy_panel(results))

        # Sections table
        if results['pe_info'].get('sections'):
            self.console.print("\n")
            self.console.print(self._create_sections_table(results))

        # Imports
        self.console.print("\n")
        self.console.print(self._create_imports_panel(results))

        # Strings
        if results['strings'].get('interesting'):
            self.console.print("\n")
            self.console.print(self._create_strings_panel(results))

        # YARA matches
        if results.get('yara_matches'):
            self.console.print("\n")
            self.console.print(self._create_yara_panel(results))

        # Threat score (centered)
        self.console.print("\n")
        self.console.print(self._create_threat_score_panel(results['threat_score']),
                          justify="center")
        self.console.print("\n")

    def _create_file_info_panel(self, results: dict) -> Panel:
        """Create file information panel"""
        file_info = results['file_info']
        hashes = results['hashes']

        table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("File Name", file_info['name'])
        table.add_row("Size", file_info['size_readable'])
        table.add_row("MD5", f"[yellow]{hashes['md5']}[/yellow]")
        table.add_row("SHA1", f"[yellow]{hashes['sha1']}[/yellow]")
        table.add_row("SHA256", f"[yellow]{hashes['sha256']}[/yellow]")

        return Panel(table, title="[bold]File Information[/bold]", border_style="cyan")

    def _create_pe_info_panel(self, results: dict) -> Panel:
        """Create PE structure information panel"""
        pe_info = results['pe_info']

        if 'error' in pe_info:
            return Panel(f"[red]{pe_info['error']}[/red]",
                        title="[bold]PE Analysis[/bold]", border_style="red")

        table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="white")

        file_type = []
        if pe_info.get('is_exe'): file_type.append("EXE")
        if pe_info.get('is_dll'): file_type.append("DLL")
        if pe_info.get('is_driver'): file_type.append("Driver")

        table.add_row("File Type", " | ".join(file_type) if file_type else "Unknown")
        table.add_row("Target Machine", pe_info.get('target_machine', 'Unknown'))
        table.add_row("Compiled", pe_info.get('compilation_timestamp', 'Unknown'))
        table.add_row("Sections", str(pe_info.get('number_of_sections', 0)))

        return Panel(table, title="[bold]PE Structure[/bold]", border_style="blue")

    def _create_entropy_panel(self, results: dict) -> Panel:
        """Create entropy analysis panel"""
        entropy = results.get('entropy', {})

        text = Text()
        text.append("Overall Entropy: ", style="cyan")
        text.append(f"{entropy.get('overall', 0)}\n", style="bold yellow")
        text.append("Status: ", style="cyan")

        if entropy.get('is_packed'):
            text.append("⚠ LIKELY PACKED/ENCRYPTED", style="bold red")
        else:
            text.append("✓ Not Packed", style="bold green")

        text.append(f"\n\n{entropy.get('analysis', '')}", style="white")

        return Panel(text, title="[bold]Entropy Analysis[/bold]", border_style="magenta")

    def _create_sections_table(self, results: dict) -> Table:
        """Create sections table"""
        pe_info = results['pe_info']

        table = Table(title="PE Sections", box=box.ROUNDED, show_lines=True)
        table.add_column("Section", style="cyan", no_wrap=True)
        table.add_column("Virtual Address", style="yellow")
        table.add_column("Virtual Size", justify="right", style="white")
        table.add_column("Raw Size", justify="right", style="white")
        table.add_column("Entropy", justify="right", style="magenta")
        table.add_column("Suspicious", justify="center")

        for section in pe_info.get('sections', []):
            suspicious = "⚠" if section.get('suspicious') else "✓"
            suspicious_style = "red" if section.get('suspicious') else "green"

            table.add_row(
                section['name'],
                section['virtual_address'],
                str(section['virtual_size']),
                str(section['raw_size']),
                str(section['entropy']),
                f"[{suspicious_style}]{suspicious}[/{suspicious_style}]"
            )

        return table

    def _create_imports_panel(self, results: dict) -> Panel:
        """Create imports analysis panel"""
        imports = results['imports']

        if 'error' in imports:
            return Panel(f"[red]{imports['error']}[/red]",
                        title="[bold]Import Analysis[/bold]", border_style="red")

        suspicious_apis = imports.get('suspicious_apis', [])

        if not suspicious_apis:
            return Panel("[green]No suspicious API calls detected[/green]",
                        title="[bold]Import Analysis[/bold]", border_style="green")

        table = Table(box=box.SIMPLE, show_header=True)
        table.add_column("API Function", style="red bold", no_wrap=True)
        table.add_column("DLL", style="yellow")
        table.add_column("Description", style="white")

        for api in suspicious_apis[:15]:
            table.add_row(api['function'], api['dll'], api['description'])

        if len(suspicious_apis) > 15:
            table.add_row("...", f"+{len(suspicious_apis) - 15} more", "", style="dim")

        return Panel(table,
                    title=f"[bold]Suspicious API Calls ({len(suspicious_apis)} detected)[/bold]",
                    border_style="red")

    def _create_strings_panel(self, results: dict) -> Panel:
        """Create interesting strings panel"""
        strings = results['strings']
        interesting = strings.get('interesting', [])

        if not interesting:
            return Panel("[dim]No interesting strings found[/dim]",
                        title="[bold]String Analysis[/bold]", border_style="white")

        text = Text()
        for string in interesting[:20]:
            text.append(f"• {string}\n", style="yellow")

        if len(interesting) > 20:
            text.append(f"\n... +{len(interesting) - 20} more strings", style="dim")

        return Panel(text,
                    title=f"[bold]Interesting Strings ({len(interesting)} found)[/bold]",
                    border_style="yellow")

    def _create_yara_panel(self, results: dict) -> Panel:
        """Create YARA matches panel"""
        yara_matches = results.get('yara_matches', [])

        if not yara_matches:
            return Panel("[dim]No YARA matches[/dim]",
                        title="[bold]YARA Scan[/bold]", border_style="white")

        table = Table(box=box.SIMPLE)
        table.add_column("Rule", style="red bold")
        table.add_column("Tags", style="yellow")

        for match in yara_matches:
            if 'error' in match:
                return Panel(f"[red]{match['error']}[/red]",
                            title="[bold]YARA Scan[/bold]", border_style="red")

            tags = ", ".join(match.get('tags', [])) if match.get('tags') else "none"
            table.add_row(match['rule'], tags)

        return Panel(table,
                    title=f"[bold]YARA Matches ({len(yara_matches)} rules)[/bold]",
                    border_style="red")

    def _create_threat_score_panel(self, score: int) -> Panel:
        """Create threat score panel with visual indicator"""
        if score < 30:
            color = "green"
            assessment = "LOW RISK"
            symbol = "✓"
        elif score < 60:
            color = "yellow"
            assessment = "MEDIUM RISK"
            symbol = "⚠"
        else:
            color = "red"
            assessment = "HIGH RISK"
            symbol = "⚠"

        filled = int(score / 5)
        empty = 20 - filled
        bar = "█" * filled + "░" * empty

        text = Text()
        text.append(f"\n{symbol} ", style=f"bold {color}")
        text.append(f"{score}/100\n\n", style=f"bold {color} on black")
        text.append(f"{bar}\n\n", style=color)
        text.append(f"Assessment: {assessment}", style=f"bold {color}")

        return Panel(text,
                    title="[bold]THREAT SCORE[/bold]",
                    border_style=color,
                    expand=False)


def main():
    parser = argparse.ArgumentParser(
        description='MalSnap - Automated Malware Static Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  malsnap.py sample.exe                          # Beautiful TUI (default)
  malsnap.py sample.exe --yara rules.yar         # TUI with YARA
  malsnap.py sample.exe --format json -o out.json  # JSON for automation
  malsnap.py sample.exe --format text            # Plain text output
        """
    )

    parser.add_argument('file', help='File to analyze')
    parser.add_argument('--yara', '-y', help='YARA rules file')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--format', '-f', choices=['tui', 'text', 'json'],
                       default='tui', help='Output format (default: tui)')

    args = parser.parse_args()

    try:
        # If TUI mode and not saving to file, use the TUI interface
        if args.format == 'tui' and not args.output:
            if not RICH_AVAILABLE:
                print("[!] Rich library not installed. Falling back to text output.")
                print("[!] Install with: pip install rich")
                args.format = 'text'
            else:
                tui = TUIRenderer()
                tui.display_banner()
                Console().print(f"\n[bold cyan]Analyzing:[/bold cyan] {args.file}\n")

                analyzer = MalSnap(args.file, args.yara)
                tui.analyze_with_progress(analyzer)
                tui.display_results(analyzer.results)

                Console().print("\n[bold green]✓ Analysis complete![/bold green]\n")
                return

        # For text/json or when saving to file
        analyzer = MalSnap(args.file, args.yara)
        analyzer.analyze()

        output_format = 'text' if args.format == 'tui' else args.format
        report = analyzer.generate_report(output_format)

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
