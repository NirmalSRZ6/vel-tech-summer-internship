#!/usr/bin/env python3
"""
main.py - Python Network Scanner
==================================
The main entry point for the Network Scanner tool.

This file handles:
  1. Parsing command-line arguments (what the user types in terminal)
  2. Orchestrating the scan flow (discovery → port scan → report)
  3. Displaying results in a clean, professional format

HOW TO RUN:
  Basic scan (needs sudo for ARP):
      sudo python main.py 192.168.1.0/24

  Scan specific IP only:
      python main.py 192.168.1.1 --ports-only

  Custom ports with banners:
      python main.py 192.168.1.1 --ports-only -p 22,80,443 --banners

  Save results with custom name:
      sudo python main.py 192.168.1.0/24 -o my_home_scan

  See all default ports:
      python main.py --list-ports

LEGAL DISCLAIMER:
  Only scan networks and systems you OWN or have WRITTEN PERMISSION to scan.
  Unauthorized network scanning is illegal under the Computer Fraud and Abuse Act
  (CFAA) in the US, and similar laws in India (IT Act 2000), UK, EU, etc.

Author: Your Name
GitHub: https://github.com/yourusername/network-scanner
"""

import argparse
import sys
import os
import platform
from datetime import datetime

# ── Import our custom scanner modules ─────────────────────────────
# These are files we wrote in the scanner/ folder
from scanner.host_discovery   import discover_hosts_arp, discover_hosts_ping, check_privileges
from scanner.port_scanner     import scan_ports_threaded, COMMON_PORTS
from scanner.service_detector import grab_banners_bulk
from scanner.report_generator import generate_txt_report, generate_csv_report, print_scan_summary


# ══════════════════════════════════════════════════════════════════
# DISPLAY FUNCTIONS  
# ══════════════════════════════════════════════════════════════════

def print_banner():
    """
    Print ASCII art header when the tool starts.
    
    ASCII art banners are common in cybersecurity tools - they make
    the tool look professional and recognizable.
    Think: Nmap, Metasploit, Netcat - they all have banners!
    """
    
    banner = r"""
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║        ██████╗ ██╗   ██╗████████╗██╗  ██╗ ██████╗       ║
    ║        ██╔══██╗╚██╗ ██╔╝╚══██╔══╝██║  ██║██╔═══██╗      ║
    ║        ██████╔╝ ╚████╔╝    ██║   ███████║██║   ██║      ║
    ║        ██╔═══╝   ╚██╔╝     ██║   ██╔══██║██║   ██║      ║
    ║        ██║        ██║      ██║   ██║  ██║╚██████╔╝      ║
    ║        ╚═╝        ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝       ║
    ║                                                          ║
    ║         🔍  PYTHON NETWORK SCANNER  v1.0                 ║
    ║         For Educational & Authorized Use Only            ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_divider(title=None, width=60):
    """Print a formatted divider line, optionally with a title."""
    if title:
        padding = (width - len(title) - 4) // 2
        print(f"\n{'═' * padding}[ {title} ]{'═' * padding}")
    else:
        print("─" * width)


def display_hosts_table(hosts):
    """
    Display discovered hosts in a formatted ASCII table.
    
    Args:
        hosts (list): List of host dicts from host discovery
    """
    
    if not hosts:
        print("\n  ❌  No hosts were discovered.")
        print("  → Make sure you're using the correct network range")
        print("  → Try running with sudo/administrator privileges")
        return
    
    print_divider(f"DISCOVERED HOSTS ({len(hosts)} found)")
    
    # Table header
    print(f"\n  {'#':<4} {'IP Address':<18} {'MAC Address':<20} {'Hostname'}")
    print(f"  {'─'*4} {'─'*18} {'─'*20} {'─'*25}")
    
    for i, host in enumerate(hosts, start=1):
        ip       = host.get('ip', 'N/A')
        mac      = host.get('mac', 'N/A')
        hostname = host.get('hostname', 'Unknown')
        
        print(f"  {i:<4} {ip:<18} {mac:<20} {hostname}")
    
    print()


def display_port_results(host_ip, open_ports, show_security=True):
    """
    Display open port results for a single host in a table.
    
    Args:
        host_ip (str):      IP address of the scanned host
        open_ports (list):  List of open port result dicts
        show_security (bool): Whether to show security warnings
    """
    
    from scanner.port_scanner import SECURITY_INTERESTING_PORTS
    
    if not open_ports:
        print(f"  ○  No open ports found on {host_ip}")
        return
    
    print(f"\n  Open ports on {host_ip} ({len(open_ports)} found):")
    print(f"  {'PORT':<8} {'SERVICE':<15} {'STATUS':<10} BANNER")
    print(f"  {'─'*8} {'─'*15} {'─'*10} {'─'*35}")
    
    for port_info in open_ports:
        port    = port_info.get('port', '?')
        service = port_info.get('service', 'Unknown')
        status  = port_info.get('status', 'OPEN')
        banner  = port_info.get('banner', '')
        
        # Shorten banner for terminal display
        if banner and banner not in ['No banner', 'No banner (timeout)', '']:
            banner_display = banner[:35] + "..." if len(banner) > 35 else banner
        else:
            banner_display = ""
        
        # Add warning icon for risky ports
        warning = " ⚠" if (show_security and port in SECURITY_INTERESTING_PORTS) else ""
        
        print(f"  {port:<8} {service:<15} {status:<10} {banner_display}{warning}")
    
    # Show security warnings below the table
    if show_security:
        risky = [p for p in open_ports if p.get('port') in SECURITY_INTERESTING_PORTS]
        if risky:
            print(f"\n  ⚠  SECURITY WARNINGS:")
            for rp in risky:
                note = SECURITY_INTERESTING_PORTS[rp['port']]
                print(f"     Port {rp['port']}: {note}")


# ══════════════════════════════════════════════════════════════════
# MAIN SCAN LOGIC
# ══════════════════════════════════════════════════════════════════

def run_full_scan(args):
    """
    Orchestrate the complete scanning process.
    
    SCAN FLOW:
        1. Privilege check (do we have root/admin?)
        2. Host Discovery (ARP scan OR direct IP)
        3. Port Scanning (TCP connect scan with threads)
        4. Banner Grabbing (optional, gets service version info)
        5. Results Display (formatted tables)
        6. Report Generation (TXT + CSV files)
    
    Args:
        args: Parsed arguments from argparse
    
    Returns:
        list: Complete scan results
    """
    
    print_banner()
    
    start_time = datetime.now()
    print(f"  [*] Scan started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  [*] Target:       {args.target}")
    print(f"  [*] OS:           {platform.system()} {platform.release()}")
    print()
    
    scan_results = []
    
    # ── PHASE 1: HOST DISCOVERY ───────────────────────────────────
    print_divider("PHASE 1: HOST DISCOVERY")
    
    if args.ports_only:
        # User wants to scan a specific IP - skip host discovery
        print(f"\n  [*] --ports-only flag set. Targeting {args.target} directly.")
        hosts = [{
            "ip":       args.target,
            "mac":      "N/A",
            "hostname": "Direct Target"
        }]
        # Try to resolve hostname
        try:
            import socket
            hostname = socket.gethostbyaddr(args.target)[0]
            hosts[0]["hostname"] = hostname
        except Exception:
            pass
    
    else:
        # Check if we have root/sudo privileges
        has_privileges = check_privileges()
        
        if not has_privileges:
            print("\n  ⚠  WARNING: ARP scanning needs root/admin privileges.")
            print("  ⚠  Without sudo, ARP scan will fail.")
            print()
            
            if not args.no_prompt:
                print("  Options:")
                print("  1. Restart with: sudo python main.py " + " ".join(sys.argv[1:]))
                print("  2. Use --ports-only to skip ARP scan")
                choice = input("\n  Fall back to TCP-based host discovery? (y/n): ").strip().lower()
                
                if choice != 'y':
                    print("  [!] Exiting. Run with sudo for ARP scanning.")
                    sys.exit(0)
                else:
                    # Use TCP-based discovery as fallback
                    hosts = discover_hosts_ping(args.target)
            else:
                # In no-prompt mode, fall back automatically
                hosts = discover_hosts_ping(args.target)
        else:
            # We have privileges, use ARP scanning
            hosts = discover_hosts_arp(args.target)
        
        display_hosts_table(hosts)
        
        if not hosts:
            print("  [!] No hosts found. Try checking your network range.")
            print(f"  [!] Your network range might be different from {args.target}")
            sys.exit(0)
    
    # ── PHASE 2: PORT SCANNING ────────────────────────────────────
    print_divider("PHASE 2: PORT SCANNING")
    
    # Ask for confirmation before scanning (unless --no-prompt flag)
    if not args.no_prompt and not args.ports_only:
        print(f"\n  Ready to scan ports on {len(hosts)} host(s).")
        proceed = input("  Proceed with port scanning? (y/n): ").strip().lower()
        if proceed != 'y':
            print("  [*] Scan stopped by user.")
            sys.exit(0)
    
    # Determine which ports to scan
    if args.ports:
        # User provided custom ports via -p flag
        # Example: -p 80,443,22,3306
        try:
            ports_to_scan = [int(p.strip()) for p in args.ports.split(',')]
            print(f"\n  [*] Custom ports specified: {ports_to_scan}")
        except ValueError:
            print("  [!] Invalid port format. Use comma-separated numbers: -p 80,443,22")
            sys.exit(1)
    else:
        # Use all common ports from our dictionary
        ports_to_scan = list(COMMON_PORTS.keys())
        print(f"\n  [*] Scanning {len(ports_to_scan)} common ports per host...")
    
    # Set timeout (faster for local scans, longer for remote)
    timeout = args.timeout if hasattr(args, 'timeout') else 1.0
    
    # Scan each discovered host
    for host in hosts:
        host_ip       = host['ip']
        host_hostname = host.get('hostname', 'Unknown')
        
        print(f"\n  ┌─ Scanning {host_ip} ({host_hostname})")
        
        # Run the port scan with threading
        open_ports = scan_ports_threaded(
            ip_address    = host_ip,
            ports_to_scan = ports_to_scan,
            max_threads   = 50,
            timeout       = timeout
        )
        
        # ── PHASE 3: BANNER GRABBING (Optional) ─────────────────
        if args.banners and open_ports:
            open_ports = grab_banners_bulk(host_ip, open_ports, max_grab=8)
        
        # Store results
        host['open_ports'] = open_ports
        scan_results.append(host)
        
        # Display results for this host
        display_port_results(host_ip, open_ports)
        print()
    
    # ── PHASE 4: SUMMARY & REPORTS ────────────────────────────────
    print_divider("SCAN COMPLETE")
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print(f"\n  [✓] Scan finished: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  [✓] Total time:    {duration:.1f} seconds")
    
    # Print summary
    print_scan_summary(scan_results)
    
    # Save reports
    print_divider("SAVING REPORTS")
    print()
    
    # Determine base filename for reports
    if args.output:
        base_name = args.output
        txt_filename = base_name + ".txt"
        csv_filename = base_name + ".csv"
    else:
        txt_filename = None  # Will auto-generate with timestamp
        csv_filename = None
    
    txt_path = generate_txt_report(scan_results, custom_filename=txt_filename)
    csv_path = generate_csv_report(scan_results, custom_filename=csv_filename)
    
    print(f"  [✓] TXT Report: {txt_path}")
    print(f"  [✓] CSV Report: {csv_path}")
    print()
    
    return scan_results


# ══════════════════════════════════════════════════════════════════
# CLI ARGUMENT PARSING
# ══════════════════════════════════════════════════════════════════

def create_argument_parser():
    """
    Create and configure the command-line argument parser.
    
    argparse is Python's standard library for building CLI tools.
    It handles:
      - Parsing arguments from sys.argv
      - Generating --help documentation automatically
      - Type checking and validation
    
    Returns:
        argparse.ArgumentParser: Configured parser
    """
    
    parser = argparse.ArgumentParser(
        prog        = "network-scanner",
        description = "🔍 Python Network Scanner - Cybersecurity Portfolio Project",
        epilog      = "⚠  LEGAL: Only scan networks you own or have explicit written permission to scan!",
        formatter_class = argparse.RawDescriptionHelpFormatter
    )
    
    # ── POSITIONAL ARGUMENTS (required) ──────────────────────────
    parser.add_argument(
        "target",
        nargs   = "?",              # Make optional so --list-ports works without target
        default = None,
        help    = (
            "Target to scan. Examples:\n"
            "  Network range: 192.168.1.0/24\n"
            "  Single host:   192.168.1.100\n"
            "  Find your network with: ip route (Linux) or ipconfig (Windows)"
        )
    )
    
    # ── OPTIONAL ARGUMENTS ────────────────────────────────────────
    parser.add_argument(
        "-p", "--ports",
        metavar = "PORTS",
        help    = "Specific ports to scan (comma-separated). Example: -p 22,80,443,3306",
        default = None
    )
    
    parser.add_argument(
        "-o", "--output",
        metavar = "FILENAME",
        help    = "Base name for output files (without extension). Example: -o home_network",
        default = None
    )
    
    parser.add_argument(
        "-b", "--banners",
        action  = "store_true",
        help    = "Grab service banners (software version info) from open ports"
    )
    
    parser.add_argument(
        "--ports-only",
        action  = "store_true",
        help    = "Skip host discovery. Scan ports on the target IP directly (no sudo needed)"
    )
    
    parser.add_argument(
        "--no-prompt",
        action  = "store_true",
        help    = "Run automatically without interactive prompts (good for scripts)"
    )
    
    parser.add_argument(
        "--timeout",
        type    = float,
        default = 1.0,
        metavar = "SECONDS",
        help    = "Per-port connection timeout in seconds (default: 1.0)"
    )
    
    parser.add_argument(
        "--list-ports",
        action  = "store_true",
        help    = "Show all default ports that will be scanned and exit"
    )
    
    parser.add_argument(
        "-v", "--version",
        action  = "version",
        version = "%(prog)s 1.0.0"
    )
    
    return parser


# ══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════

def main():
    """
    Main function - the program starts here.
    
    The `if __name__ == "__main__": main()` pattern at the bottom
    means this function only runs when you execute this file directly.
    If someone imports this file, main() won't auto-run.
    """
    
    # Parse command-line arguments
    parser = create_argument_parser()
    args   = parser.parse_args()
    
    # ── Handle --list-ports flag ──────────────────────────────────
    if args.list_ports:
        print("\n  Default ports scanned by this tool:")
        print(f"\n  {'PORT':<8} {'SERVICE':<20} DESCRIPTION")
        print(f"  {'─'*8} {'─'*20} {'─'*30}")
        
        for port, service in sorted(COMMON_PORTS.items()):
            print(f"  {port:<8} {service:<20}")
        
        print(f"\n  Total: {len(COMMON_PORTS)} ports")
        print()
        sys.exit(0)
    
    # ── Require target for actual scanning ────────────────────────
    if not args.target:
        parser.print_help()
        print("\n  ⚠  Error: Please provide a target (network range or IP)")
        print("  Examples:")
        print("    sudo python main.py 192.168.1.0/24")
        print("    python main.py 192.168.1.1 --ports-only")
        sys.exit(1)
    
    # ── Start the scan with error handling ────────────────────────
    try:
        run_full_scan(args)
        
    except KeyboardInterrupt:
        # User pressed Ctrl+C to stop the scan
        print("\n\n  [!] Scan interrupted by user (Ctrl+C)")
        print("  [!] Partial results may have been saved to ./output/")
        sys.exit(0)
        
    except PermissionError:
        print("\n  [!] Permission denied!")
        print("  [!] ARP scanning requires root/sudo privileges.")
        print("  [!] Try: sudo python main.py " + " ".join(sys.argv[1:]))
        print("  [!] Or use: python main.py " + args.target + " --ports-only")
        sys.exit(1)
        
    except ImportError as e:
        print(f"\n  [!] Missing dependency: {e}")
        print("  [!] Install required packages: pip install -r requirements.txt")
        sys.exit(1)


# This is the Python entry point convention
# When you run: python main.py
# Python sets __name__ = "__main__" and calls main()
if __name__ == "__main__":
    main()
