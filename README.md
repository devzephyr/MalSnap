# MalSnap

**Fast, automated static analysis for Windows PE malware**

MalSnap is a Python-based static malware analysis tool designed for rapid triage and threat assessment of suspicious binaries. Built for security researchers, incident responders, and malware analysts.

## Features

- **PE Structure Analysis**: Parse and analyze Windows portable executable files
- **Hash Generation**: MD5, SHA1, SHA256 for threat intelligence correlation
- **Entropy Analysis**: Detect packed/encrypted malware using Shannon entropy
- **String Extraction**: Intelligent filtering for URLs, IPs, registry keys, and suspicious strings
- **Import Analysis**: Identify suspicious Windows API calls commonly used by malware
- **YARA Integration**: Scan files against custom YARA rules
- **Threat Scoring**: Automated risk assessment (0-100 scale)
- **Multiple Output Formats**: JSON for automation, text for human analysis

## Installation

```bash
git clone https://github.com/devzephyr/MalSnap.git
cd MalSnap
pip install -r requirements.txt
```

### Requirements

- Python 3.7+
- pefile
- yara-python
- textual (for interactive TUI)

## Usage

### Quick Start (Interactive TUI - Default)

MalSnap defaults to a fully interactive terminal interface built with Textual, featuring keyboard navigation, real-time analysis, and tabbed views:

```bash
python malsnap.py suspicious.exe
```

![MalSnap TUI Demo](https://via.placeholder.com/800x400?text=MalSnap+TUI+Demo)

The interactive TUI includes:
- **Tabbed Navigation**: Switch between Overview, PE Structure, Imports, and Strings tabs
- **Keyboard Controls**: Press 'q' to quit, 'r' to reload analysis
- **Real-time Progress**: Live progress bar during analysis
- **Color-coded Results**: Visual indicators for threat levels and suspicious content
- **Scrollable Views**: Navigate through large datasets easily
- **Professional Layout**: Clean, organized presentation of analysis results

### With YARA Rules

```bash
python malsnap.py suspicious.exe --yara rules/malware.yar
```

### For Automation (Text/JSON)

When you need machine-readable output for scripts or automation:

```bash
# Plain text output
python malsnap.py suspicious.exe --format text

# JSON output for automation
python malsnap.py suspicious.exe --format json --output report.json
```

## Output

MalSnap provides comprehensive analysis including:

### File Information
- File name, path, and size
- MD5, SHA1, SHA256 hashes

### PE Analysis
- File type (EXE, DLL, Driver)
- Compilation timestamp
- Target architecture
- Section analysis with entropy scores

### Entropy Analysis
- Overall file entropy
- Per-section entropy
- Packing detection (entropy > 7.0)

### String Extraction
- ASCII and Unicode strings
- Filtered interesting strings:
  - URLs and IP addresses
  - File paths and registry keys
  - Credential-related strings
  - Shell commands

### Import Analysis
- Imported DLLs and functions
- Suspicious API detection:
  - Process injection (VirtualAllocEx, WriteProcessMemory)
  - Anti-debugging (IsDebuggerPresent)
  - Keylogging (SetWindowsHookEx, GetAsyncKeyState)
  - Network activity (URLDownloadToFile, InternetOpen)
  - Encryption (CryptEncrypt, CryptDecrypt)

### Threat Score
Automated risk assessment based on:
- Packing/encryption indicators
- Suspicious API usage
- YARA rule matches
- Interesting strings

**Scoring:**
- 0-29: LOW RISK
- 30-59: MEDIUM RISK
- 60-100: HIGH RISK

## Example Output

### Interactive TUI Mode (Default)

When you run `python malsnap.py sample.exe`, you'll see an interactive terminal interface with:

**During Analysis:**
- Real-time progress bar showing current analysis stage (0-100%)
- Status indicator showing which file is being analyzed

**After Analysis - Tabbed Interface:**

**Tab 1: Overview**
- **File Information Panel**: File name, size, MD5/SHA1/SHA256 hashes (color-highlighted)
- **Entropy Analysis Panel**: Shannon entropy score with visual status indicator
  - ✓ Not Packed (green) - entropy < 7.0
  - ⚠ LIKELY PACKED/ENCRYPTED (red) - entropy > 7.0
- **Threat Score Widget**: Large, centered display with:
  - Numeric score (0-100) with color coding
  - Visual bar graph (█ filled, ░ empty)
  - Risk assessment (LOW/MEDIUM/HIGH)

**Tab 2: PE Structure**
- **Sections Table**: Interactive table showing all PE sections
  - Section name, virtual address, virtual size
  - Entropy per section
  - Suspicious indicators (⚠ for high entropy sections)
  - Scrollable for binaries with many sections

**Tab 3: Imports**
- **Suspicious API Calls List**: Red-highlighted dangerous Windows APIs
  - VirtualAllocEx - Remote memory allocation (process injection)
  - WriteProcessMemory - Write to another process (injection)
  - CreateRemoteThread - Remote thread creation (injection)
  - IsDebuggerPresent - Anti-debugging
  - CryptEncrypt/Decrypt - Encryption (possible ransomware)
  - Shows up to 20 most suspicious APIs
  - Empty state: "No suspicious API calls detected" (green)

**Tab 4: Strings**
- **Interesting Strings List**: Yellow-highlighted extracted strings
  - URLs, IP addresses, file paths
  - Registry keys, commands, credentials
  - Shows up to 30 strings with "...and X more" indicator
  - Scrollable for long lists

**Keyboard Controls:**
- `q` - Quit application
- `r` - Reload analysis (re-run on same file)
- `Tab` - Switch between tabs
- Arrow keys / Mouse - Navigate and scroll

### Text/JSON Mode

For automation or when saving to file:
```bash
# Plain text output
python malsnap.py sample.exe --format text

# JSON output
python malsnap.py sample.exe --format json --output report.json
```

## YARA Rules

Place YARA rules in the `rules/` directory. Example rule:

```yara
rule Suspicious_Packer
{
    meta:
        description = "Detects high entropy sections indicating packing"
        author = "MalSnap"

    strings:
        $upx = "UPX"
        $mpress = "MPRESS"

    condition:
        any of them
}
```

## Use Cases

### Malware Triage
Quickly assess unknown binaries for suspicious characteristics before deeper analysis.

### Incident Response
Generate hashes and identify malicious APIs during incident investigation.

### Threat Intelligence
Extract IOCs (hashes, IPs, URLs) for threat intelligence feeds.

### Academic Research
Study malware behavior patterns and common evasion techniques.

## Technical Details

### Entropy Calculation
Shannon entropy is calculated for the entire file and each PE section. High entropy (> 7.0) indicates packing or encryption, common malware obfuscation techniques.

### Suspicious API Detection
MalSnap maintains a curated list of 20+ Windows APIs commonly abused by malware:
- Memory manipulation (injection)
- Anti-analysis techniques
- Keylogging capabilities
- Network communication
- Registry persistence
- Encryption operations

### String Filtering
Regex-based filtering extracts potentially malicious indicators:
- Network artifacts (URLs, IPs, domains)
- File system paths
- Credential-related strings
- Shell commands
- Registry modifications

## Limitations

- **Static analysis only**: Does not execute samples (safe for analysis)
- **PE files only**: Currently supports Windows executables/DLLs
- **Signature-based detection**: May miss novel/polymorphic malware
- **No unpacking**: Packed samples require manual unpacking first

## Development Roadmap

- [ ] Support for ELF and Mach-O binaries
- [ ] Automated unpacking for common packers
- [ ] VirusTotal API integration
- [ ] Machine learning-based classification
- [ ] Web interface for batch analysis
- [ ] Docker container for isolated analysis

## Security Notice

This tool is designed for malware analysis. Always analyze samples in isolated environments:
- Air-gapped virtual machines
- Sandboxed containers
- Dedicated analysis workstations

Never execute untrusted binaries on production systems.

## Contributing

Contributions welcome! Areas for improvement:
- Additional suspicious API patterns
- More YARA rules
- ELF/Mach-O support
- Performance optimizations

## License

MIT License - See LICENSE file for details

## Author

**Adeyemi Folarin**
- Portfolio: [adeyemi.xyz](https://adeyemi.xyz)
- Blog: [blog.adeyemi.xyz](https://blog.adeyemi.xyz)
- GitHub: [@devzephyr](https://github.com/devzephyr)

## Acknowledgments

Built using knowledge from:
- Seneca Polytechnic Endpoint Security course
- Practical Malware Analysis research
- YARA project and pefile library

---

**Disclaimer**: This tool is for educational and authorized security research only. Users are responsible for complying with applicable laws and regulations.
