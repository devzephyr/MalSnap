#!/usr/bin/env python3
"""
MalSnap TUI - Beautiful Terminal Interface for Malware Analysis
Author: Adeyemi Folarin
Description: Rich TUI version of MalSnap with real-time progress and formatted output
"""

import sys
import argparse
from pathlib import Path

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.syntax import Syntax
    from rich.tree import Tree
    from rich import box
    from rich.layout import Layout
    from rich.text import Text
    import malsnap
except ImportError as e:
    print(f"[!] Missing required library: {e}")
    print("[!] Install dependencies: pip install -r requirements.txt")
    sys.exit(1)


class MalSnapTUI:
    """Beautiful TUI interface for MalSnap"""

    def __init__(self):
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

    def create_file_info_panel(self, results: dict) -> Panel:
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

    def create_entropy_panel(self, results: dict) -> Panel:
        """Create entropy analysis panel"""
        entropy = results['entropy']

        text = Text()
        text.append("Overall Entropy: ", style="cyan")
        text.append(f"{entropy['overall']}\n", style="bold yellow")
        text.append("Status: ", style="cyan")

        if entropy['is_packed']:
            text.append("⚠ LIKELY PACKED/ENCRYPTED", style="bold red")
        else:
            text.append("✓ Not Packed", style="bold green")

        text.append(f"\n\n{entropy['analysis']}", style="white")

        return Panel(text, title="[bold]Entropy Analysis[/bold]", border_style="magenta")

    def create_pe_info_panel(self, results: dict) -> Panel:
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

    def create_sections_table(self, results: dict) -> Table:
        """Create sections table"""
        pe_info = results['pe_info']

        if 'sections' not in pe_info:
            return Table()

        table = Table(title="PE Sections", box=box.ROUNDED, show_lines=True)
        table.add_column("Section", style="cyan", no_wrap=True)
        table.add_column("Virtual Address", style="yellow")
        table.add_column("Virtual Size", justify="right", style="white")
        table.add_column("Raw Size", justify="right", style="white")
        table.add_column("Entropy", justify="right", style="magenta")
        table.add_column("Suspicious", justify="center")

        for section in pe_info['sections']:
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

    def create_imports_panel(self, results: dict) -> Panel:
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

        for api in suspicious_apis[:15]:  # Show top 15
            table.add_row(
                api['function'],
                api['dll'],
                api['description']
            )

        if len(suspicious_apis) > 15:
            table.add_row(
                "...",
                f"+{len(suspicious_apis) - 15} more",
                "",
                style="dim"
            )

        return Panel(table,
                    title=f"[bold]Suspicious API Calls ({len(suspicious_apis)} detected)[/bold]",
                    border_style="red")

    def create_strings_panel(self, results: dict) -> Panel:
        """Create interesting strings panel"""
        strings = results['strings']
        interesting = strings.get('interesting', [])

        if not interesting:
            return Panel("[dim]No interesting strings found[/dim]",
                        title="[bold]String Analysis[/bold]", border_style="white")

        text = Text()
        for string in interesting[:20]:  # Show top 20
            text.append(f"• {string}\n", style="yellow")

        if len(interesting) > 20:
            text.append(f"\n... +{len(interesting) - 20} more strings", style="dim")

        return Panel(text,
                    title=f"[bold]Interesting Strings ({len(interesting)} found)[/bold]",
                    border_style="yellow")

    def create_yara_panel(self, results: dict) -> Panel:
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

    def create_threat_score_panel(self, score: int) -> Panel:
        """Create threat score panel with visual indicator"""
        # Determine color and assessment
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

        # Create visual bar
        filled = int(score / 5)  # 20 blocks for 100%
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

    def analyze_with_progress(self, file_path: str, yara_rules_path: str = None):
        """Run analysis with progress indicators"""
        analyzer = malsnap.MalSnap(file_path, yara_rules_path)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=self.console
        ) as progress:

            task0 = progress.add_task("[cyan]Gathering file info...", total=1)
            # Set up file info
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

            if yara_rules_path:
                task5 = progress.add_task("[cyan]Running YARA scan...", total=1)
                analyzer.results['yara_matches'] = analyzer.run_yara_scan()
                progress.update(task5, advance=1)

            task6 = progress.add_task("[cyan]Calculating threat score...", total=1)
            analyzer.results['threat_score'] = analyzer.calculate_threat_score()
            analyzer.results['entropy'] = analyzer.results.get('entropy', {})
            progress.update(task6, advance=1)

        return analyzer.results

    def display_results(self, results: dict):
        """Display analysis results in beautiful TUI format"""
        self.console.print("\n")

        # File info and entropy side by side
        self.console.print(self.create_file_info_panel(results))
        self.console.print(self.create_pe_info_panel(results))
        self.console.print(self.create_entropy_panel(results))

        # Sections table
        if results['pe_info'].get('sections'):
            self.console.print("\n")
            self.console.print(self.create_sections_table(results))

        # Imports
        self.console.print("\n")
        self.console.print(self.create_imports_panel(results))

        # Strings
        if results['strings'].get('interesting'):
            self.console.print("\n")
            self.console.print(self.create_strings_panel(results))

        # YARA matches
        if results.get('yara_matches'):
            self.console.print("\n")
            self.console.print(self.create_yara_panel(results))

        # Threat score (centered)
        self.console.print("\n")
        self.console.print(self.create_threat_score_panel(results['threat_score']),
                          justify="center")
        self.console.print("\n")


def main():
    parser = argparse.ArgumentParser(
        description='MalSnap TUI - Beautiful Terminal Interface for Malware Analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('file', help='File to analyze')
    parser.add_argument('--yara', '-y', help='YARA rules file')

    args = parser.parse_args()

    try:
        tui = MalSnapTUI()
        tui.display_banner()

        tui.console.print(f"\n[bold cyan]Analyzing:[/bold cyan] {args.file}\n")

        results = tui.analyze_with_progress(args.file, args.yara)
        tui.display_results(results)

        tui.console.print("\n[bold green]✓ Analysis complete![/bold green]\n")

    except FileNotFoundError as e:
        Console().print(f"\n[bold red]✗ Error:[/bold red] {e}\n")
        sys.exit(1)
    except Exception as e:
        Console().print(f"\n[bold red]✗ Unexpected error:[/bold red] {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
