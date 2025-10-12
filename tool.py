#!/usr/bin/env python3
import os
import sys
import time
import signal
import subprocess
import threading
import psutil
import tempfile
import json
import hashlib
import pefile
import re
from datetime import datetime
from pathlib import Path
from collections import defaultdict

class MalwareAnalyzer:
    def __init__(self, malware_path, duration):
        self.malware_path = malware_path
        self.duration = duration
        self.malware_process = None
        self.monitoring_active = False
        self.current_stage = None
        self.malware_pid = None
        self.file_snapshots = {}  # Track file states
        self.monitored_dirs = []  # Important directories to monitor
        
        # Results storage
        self.results = {
            'pe_info': [],
            'network': [],
            'filesystem': [],
            'processes': [],
            'memory': []
        }
        
        # Create analysis output directory
        malware_name = os.path.splitext(os.path.basename(malware_path))[0]
        self.output_dir = f"Analysis_{malware_name}"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # System directories to ignore (constantly modified by OS) - Windows specific
        self.ignored_dirs = {
            'C:\\Windows\\System32',
            'C:\\Windows\\SysWOW64',
            'C:\\Windows\\WinSxS',
            'C:\\Windows\\Logs',
            'C:\\Windows\\Temp',
            'C:\\Windows\\Prefetch',
            'C:\\Windows\\SoftwareDistribution',
            'C:\\ProgramData\\Microsoft',
            'C:\\$Recycle.Bin',
        }
        
        # Setup monitored directories - Windows specific
        home = os.path.expanduser("~")
        self.monitored_dirs = [
            os.path.join(home, "Desktop"),
            os.path.join(home, "Downloads"),
            tempfile.gettempdir(),
        ]
        
    def calculate_file_hash(self, filepath):
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            return f"Error: {e}"
    
    def analyze_pe_file(self):
        """Analyze PE file and print section information"""
        print("\n" + "="*60)
        print("MALWARE INFORMATION")
        print("="*60)
        
        # Calculate hash
        file_hash = self.calculate_file_hash(self.malware_path)
        file_size = os.path.getsize(self.malware_path)
        
        print(f"[+] File: {self.malware_path}")
        print(f"[+] SHA256: {file_hash}")
        print(f"[+] Size: {file_size} bytes ({file_size / 1024:.2f} KB)")
        
        # Store PE info
        self.results['pe_info'].append(f"File: {self.malware_path}")
        self.results['pe_info'].append(f"SHA256: {file_hash}")
        self.results['pe_info'].append(f"Size: {file_size} bytes ({file_size / 1024:.2f} KB)")
        
        # Try to parse as PE file
        try:
            pe = pefile.PE(self.malware_path)
            print(f"\n[+] PE File Information:")
            print(f"    Machine Type: {hex(pe.FILE_HEADER.Machine)}")
            print(f"    Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
            print(f"    Timestamp: {datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)}")
            print(f"    Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
            
            self.results['pe_info'].append(f"\nPE File Information:")
            self.results['pe_info'].append(f"Machine Type: {hex(pe.FILE_HEADER.Machine)}")
            self.results['pe_info'].append(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
            self.results['pe_info'].append(f"Timestamp: {datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)}")
            self.results['pe_info'].append(f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
            
            print(f"\n[+] Section Information:")
            print(f"    {'Name':<12} {'Virtual Size':<15} {'Raw Size':<15} {'Entropy':<10}")
            print(f"    {'-'*12} {'-'*15} {'-'*15} {'-'*10}")
            
            self.results['pe_info'].append(f"\nSection Information:")
            self.results['pe_info'].append(f"{'Name':<12} {'Virtual Size':<15} {'Raw Size':<15} {'Entropy':<10}")
            
            for section in pe.sections:
                name = section.Name.decode('utf-8').rstrip('\x00')
                virt_size = section.Misc_VirtualSize
                raw_size = section.SizeOfRawData
                entropy = section.get_entropy()
                
                print(f"    {name:<12} {virt_size:<15} {raw_size:<15} {entropy:<10.2f}")
                self.results['pe_info'].append(f"{name:<12} {virt_size:<15} {raw_size:<15} {entropy:<10.2f}")
            
            pe.close()
        except Exception as e:
            print(f"\n[!] Could not parse as PE file: {e}")
            print(f"[!] File may not be a valid PE executable")
            self.results['pe_info'].append(f"\nError: Could not parse as PE file: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle CTRL+C to move to next stage"""
        print(f"\n[!] Interrupt received. Moving to next stage...")
        self.monitoring_active = False
        
    def launch_malware(self):
        """Launch the malware process"""
        try:
            print(f"[+] Launching malware: {self.malware_path}")
            # Use CREATE_NEW_PROCESS_GROUP on Windows to better track the process tree
            if sys.platform == 'win32':
                self.malware_process = subprocess.Popen(
                    [self.malware_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                )
            else:
                self.malware_process = subprocess.Popen(
                    [self.malware_path],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            self.malware_pid = self.malware_process.pid
            print(f"[+] Malware started with PID: {self.malware_pid}")
            # Give malware a moment to start
            time.sleep(2)
            return True
        except Exception as e:
            print(f"[-] Failed to launch malware: {e}")
            return False
            
    def terminate_malware(self):
        """Terminate the malware process and all children"""
        if self.malware_process:
            try:
                print(f"[+] Terminating malware process tree...")
                parent = psutil.Process(self.malware_process.pid)
                children = parent.children(recursive=True)
                
                for child in children:
                    child.terminate()
                
                gone, alive = psutil.wait_procs(children, timeout=3)
                for p in alive:
                    p.kill()
                
                parent.terminate()
                parent.wait(5)
                print(f"[+] Malware terminated successfully")
            except psutil.NoSuchProcess:
                pass
            except Exception as e:
                print(f"[-] Error terminating malware: {e}")
    
    def get_malware_descendants(self, pid):
        """Get all descendant processes of the malware"""
        try:
            process = psutil.Process(pid)
            descendants = process.children(recursive=True)
            return [pid] + [p.pid for p in descendants]
        except psutil.NoSuchProcess:
            return []
    
    def is_malware_related_process(self, pid):
        """Check if process is related to our malware"""
        if not self.malware_pid:
            return False
        malware_pids = self.get_malware_descendants(self.malware_pid)
        return pid in malware_pids
    
    def network_analysis_stage(self):
        """Stage 1: Network Analysis"""
        print("\n" + "="*60)
        print("NETWORK ANALYSIS STAGE")
        print("="*60)
        
        if not self.launch_malware():
            return
            
        print(f"[+] Monitoring network activity for {self.duration} seconds...")
        print("[+] Press CTRL+C to move to next stage early\n")
        
        # Store initial connections to filter out pre-existing ones
        initial_connections = set()
        for conn in psutil.net_connections():
            if conn.pid and self.is_malware_related_process(conn.pid):
                initial_connections.add((conn.fd, conn.laddr, conn.raddr, conn.status))
        
        start_time = time.time()
        self.monitoring_active = True
        connections_seen = set()
        
        while time.time() - start_time < self.duration and self.monitoring_active:
            try:
                for conn in psutil.net_connections():
                    if (conn.pid and self.is_malware_related_process(conn.pid) and
                        (conn.fd, conn.laddr, conn.raddr, conn.status) not in initial_connections):
                        
                        conn_id = (conn.fd, conn.laddr, conn.raddr, conn.status, conn.pid)
                        if conn_id not in connections_seen:
                            connections_seen.add(conn_id)
                            
                            protocol = "TCP" if conn.type == 1 else "UDP" if conn.type == 2 else "UNIX"
                            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                            remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                            
                            msg = f"PID {conn.pid} - {protocol} {local_addr} -> {remote_addr} [{conn.status}]"
                            print(f"[NETWORK] {msg}")
                            self.results['network'].append(msg)
                
                time.sleep(1)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                print(f"[-] Network monitoring error: {e}")
                break
        
        if not connections_seen:
            msg = "No network activity detected from malware"
            print(f"[NETWORK] {msg}")
            self.results['network'].append(msg)
            
        self.terminate_malware()
    
    def should_ignore_path(self, path):
        """Check if path should be ignored (system directories)"""
        path_str = str(path).lower()
        
        # Check if path is in one of our monitored directories - NEVER ignore these
        for monitored in self.monitored_dirs:
            monitored_lower = monitored.lower()
            if path_str.startswith(monitored_lower):
                # This is in a monitored directory, don't ignore it
                # Only ignore specific system files
                basename = os.path.basename(path_str)
                if basename in ['thumbs.db', 'desktop.ini', 'ntuser.dat', 'ntuser.dat.log']:
                    return True
                return False
        
        # For paths outside monitored directories, apply strict filtering
        for ignored in self.ignored_dirs:
            if path_str.startswith(ignored.lower()):
                return True
        
        return False
    
    def take_directory_snapshot(self, directory):
        """Take a snapshot of files in a directory"""
        snapshot = {}
        try:
            if not os.path.exists(directory):
                return snapshot
            
            for root, dirs, files in os.walk(directory):
                # Skip ignored directories
                if self.should_ignore_path(root):
                    continue
                
                # On Windows, skip directories we don't have access to
                dirs[:] = [d for d in dirs if not self.should_ignore_path(os.path.join(root, d))]
                    
                for filename in files:
                    filepath = os.path.join(root, filename)
                    if self.should_ignore_path(filepath):
                        continue
                    
                    try:
                        stat = os.stat(filepath)
                        snapshot[filepath] = {
                            'mtime': stat.st_mtime,
                            'size': stat.st_size,
                            'exists': True
                        }
                    except (OSError, FileNotFoundError, PermissionError):
                        continue
        except (PermissionError, OSError) as e:
            pass
        return snapshot
    
    def compare_snapshots(self, before, after):
        """Compare two directory snapshots and return changes"""
        changes = {
            'added': [],
            'modified': [],
            'deleted': []
        }
        
        # Find added and modified files
        for filepath, info in after.items():
            if filepath not in before:
                changes['added'].append((filepath, info))
            elif before[filepath]['mtime'] != info['mtime'] or before[filepath]['size'] != info['size']:
                changes['modified'].append((filepath, info))
        
        # Find deleted files
        for filepath in before:
            if filepath not in after:
                changes['deleted'].append(filepath)
        
        return changes
    
    def file_system_monitoring_stage(self):
        """Stage 2: File System Monitoring"""
        print("\n" + "="*60)
        print("FILE SYSTEM MONITORING STAGE")
        print("="*60)
        
        if not self.launch_malware():
            return
            
        print(f"[+] Monitoring file system activity for {self.duration} seconds...")
        print(f"[+] Watching directories: {', '.join([os.path.basename(d) for d in self.monitored_dirs])}")
        print("[+] Real-time monitoring - changes will be displayed immediately")
        print("[+] Press CTRL+C to move to next stage early\n")
        
        # Take initial snapshots
        previous_snapshots = {}
        for directory in self.monitored_dirs:
            previous_snapshots[directory] = self.take_directory_snapshot(directory)
        
        start_time = time.time()
        self.monitoring_active = True
        
        # Real-time monitoring loop
        while time.time() - start_time < self.duration and self.monitoring_active:
            try:
                # Take new snapshots and compare with previous
                for directory in self.monitored_dirs:
                    current_snapshot = self.take_directory_snapshot(directory)
                    changes = self.compare_snapshots(previous_snapshots[directory], current_snapshot)
                    
                    # Print added files immediately
                    for filepath, info in changes['added']:
                        msg = f"{filepath} ({info['size']} bytes)"
                        print(f"[FILE ADDED] {msg}")
                        self.results['filesystem'].append(f"ADDED: {msg}")
                    
                    # Print modified files immediately
                    for filepath, info in changes['modified']:
                        msg = f"{filepath} ({info['size']} bytes)"
                        print(f"[FILE MODIFIED] {msg}")
                        self.results['filesystem'].append(f"MODIFIED: {msg}")
                    
                    # Print deleted files immediately
                    for filepath in changes['deleted']:
                        print(f"[FILE DELETED] {filepath}")
                        self.results['filesystem'].append(f"DELETED: {filepath}")
                    
                    # Update previous snapshot
                    previous_snapshots[directory] = current_snapshot
                
                # Check every 1 second for faster detection
                time.sleep(1)
            except Exception as e:
                print(f"[-] File system monitoring error: {e}")
                break
        
        print("\n[+] File system monitoring completed")
        self.terminate_malware()
    
    def process_monitoring_stage(self):
        """Stage 3: Process Monitoring"""
        print("\n" + "="*60)
        print("PROCESS MONITORING STAGE")
        print("="*60)
        
        if not self.launch_malware():
            return
            
        print(f"[+] Monitoring process activity for {self.duration} seconds...")
        print("[+] Press CTRL+C to move to next stage early\n")
        
        start_time = time.time()
        self.monitoring_active = True
        processes_seen = set([self.malware_pid])
        process_details = {}  # Store detailed info about each process
        
        # Get initial parent process info
        try:
            parent_proc = psutil.Process(self.malware_pid)
            print(f"[PROCESS] Parent process started:")
            print(f"          PID: {self.malware_pid}")
            print(f"          Name: {parent_proc.name()}")
            print(f"          Command: {' '.join(parent_proc.cmdline())}")
            
            self.results['processes'].append(f"Parent process started:")
            self.results['processes'].append(f"PID: {self.malware_pid}")
            self.results['processes'].append(f"Name: {parent_proc.name()}")
            self.results['processes'].append(f"Command: {' '.join(parent_proc.cmdline())}")
            
            try:
                cwd = parent_proc.cwd()
                print(f"          CWD: {cwd}")
                self.results['processes'].append(f"CWD: {cwd}")
            except (psutil.AccessDenied, OSError):
                print(f"          CWD: N/A (Access Denied)")
                self.results['processes'].append(f"CWD: N/A (Access Denied)")
            print()
            self.results['processes'].append("")
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"[PROCESS] Parent process: PID {self.malware_pid}\n")
            self.results['processes'].append(f"Parent process: PID {self.malware_pid}")
        
        while time.time() - start_time < self.duration and self.monitoring_active:
            try:
                # Get only DIRECT children of the malware process
                try:
                    parent_proc = psutil.Process(self.malware_pid)
                    direct_children = parent_proc.children(recursive=False)
                    current_pids = [self.malware_pid] + [p.pid for p in direct_children]
                except psutil.NoSuchProcess:
                    current_pids = []
                
                # Check for new child processes (only direct children)
                for pid in current_pids:
                    if pid not in processes_seen and pid != self.malware_pid:
                        processes_seen.add(pid)
                        try:
                            proc = psutil.Process(pid)
                            with proc.oneshot():
                                name = proc.name()
                                cmdline = proc.cmdline()
                                parent_pid = proc.ppid()
                                create_time = datetime.fromtimestamp(proc.create_time())
                                try:
                                    cwd = proc.cwd()
                                except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
                                    cwd = 'N/A'
                                
                                # Get initial resource usage
                                try:
                                    cpu_percent = proc.cpu_percent(interval=0.1)
                                    memory_info = proc.memory_info()
                                    memory_mb = memory_info.rss / 1024 / 1024
                                    num_threads = proc.num_threads()
                                    status = proc.status()
                                except:
                                    cpu_percent = 0
                                    memory_mb = 0
                                    num_threads = 0
                                    status = 'unknown'
                                
                                # Store process details
                                process_details[pid] = {
                                    'name': name,
                                    'cmdline': cmdline,
                                    'parent_pid': parent_pid,
                                    'create_time': create_time
                                }
                                
                                print(f"[PROCESS] New child process detected:")
                                print(f"          PID: {pid}")
                                print(f"          Name: {name}")
                                print(f"          Parent PID: {parent_pid}")
                                print(f"          Command: {' '.join(cmdline) if cmdline else 'N/A'}")
                                print(f"          CWD: {cwd}")
                                print(f"          Status: {status}")
                                print(f"          Threads: {num_threads}")
                                print(f"          CPU: {cpu_percent:.1f}% | Memory: {memory_mb:.2f} MB")
                                print(f"          Created: {create_time}")
                                print()
                                
                                self.results['processes'].append(f"New child process detected:")
                                self.results['processes'].append(f"PID: {pid}")
                                self.results['processes'].append(f"Name: {name}")
                                self.results['processes'].append(f"Parent PID: {parent_pid}")
                                self.results['processes'].append(f"Command: {' '.join(cmdline) if cmdline else 'N/A'}")
                                self.results['processes'].append(f"CWD: {cwd}")
                                self.results['processes'].append(f"Status: {status}")
                                self.results['processes'].append(f"Threads: {num_threads}")
                                self.results['processes'].append(f"CPU: {cpu_percent:.1f}% | Memory: {memory_mb:.2f} MB")
                                self.results['processes'].append(f"Created: {create_time}")
                                self.results['processes'].append("")
                        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                            print(f"[PROCESS] New child PID {pid} (access denied or terminated)\n")
                            continue
                
                # Check for terminated processes
                terminated = []
                for pid in list(processes_seen):
                    if pid not in current_pids and pid != self.malware_pid:
                        terminated.append(pid)
                        processes_seen.discard(pid)
                        if pid in process_details:
                            details = process_details[pid]
                            print(f"[PROCESS] Child process terminated: PID {pid} ({details['name']})\n")
                
                time.sleep(2)
            except Exception as e:
                print(f"[-] Process monitoring error: {e}")
                break
        
        # Final summary - show only direct children
        print(f"\n[PROCESS] Final process tree summary:")
        try:
            parent_proc = psutil.Process(self.malware_pid)
            direct_children = parent_proc.children(recursive=False)
            final_pids = [p.pid for p in direct_children]
        except psutil.NoSuchProcess:
            final_pids = []
        
        print(f"          Total direct child processes: {len(final_pids)}")
        for pid in final_pids:
            try:
                proc = psutil.Process(pid)
                cmdline = ' '.join(proc.cmdline()[:3]) if proc.cmdline() else proc.name()
                if len(cmdline) > 80:
                    cmdline = cmdline[:77] + "..."
                print(f"          PID {pid}: {cmdline}")
            except psutil.NoSuchProcess:
                if pid in process_details:
                    print(f"          PID {pid}: [Terminated - was {process_details[pid]['name']}]")
                else:
                    print(f"          PID {pid}: [Terminated]")
        
        self.terminate_malware()
    
    def extract_strings(self, data, min_length=4):
        """Extract readable ASCII and Unicode strings from binary data"""
        strings = []
        
        # ASCII strings
        ascii_pattern = b'[\x20-\x7E]{' + str(min_length).encode() + b',}'
        for match in re.finditer(ascii_pattern, data):
            strings.append(match.group().decode('ascii'))
        
        # Unicode strings (UTF-16 LE)
        unicode_pattern = b'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + b',}'
        for match in re.finditer(unicode_pattern, data):
            try:
                strings.append(match.group().decode('utf-16-le'))
            except:
                pass
        
        return strings
    
    def memory_dump_stage(self):
        """Stage 4: Memory Dump Analysis"""
        print("\n" + "="*60)
        print("MEMORY DUMP ANALYSIS STAGE")
        print("="*60)
        
        if not self.launch_malware():
            return
            
        print(f"[+] Analyzing memory for PID: {self.malware_pid}")
        print(f"[+] Extracting memory addresses and readable strings...\n")
        
        try:
            process = psutil.Process(self.malware_pid)
            
            # Get memory maps
            memory_maps = process.memory_maps(grouped=False)
            
            print(f"[MEMORY] Process memory regions:")
            self.results['memory'].append("Process Memory Regions:")
            self.results['memory'].append("="*80)
            self.results['memory'].append(f"{'Address Range':<30} {'Size (KB)':<15} {'Permissions':<15} {'Path':<30}")
            self.results['memory'].append("-"*80)
            
            total_size = 0
            all_strings = set()
            
            for mmap in memory_maps:
                # Parse address range
                addr_range = mmap.addr
                size_kb = mmap.rss / 1024 if hasattr(mmap, 'rss') and mmap.rss else 0
                perms = mmap.perms if hasattr(mmap, 'perms') else 'N/A'
                path = mmap.path if mmap.path else '[anonymous]'
                
                total_size += size_kb
                
                # Display memory region
                region_info = f"{addr_range:<30} {size_kb:<15.2f} {perms:<15} {path:<30}"
                print(f"[MEMORY] {region_info}")
                self.results['memory'].append(region_info)
            
            print(f"\n[MEMORY] Total memory regions: {len(memory_maps)}")
            print(f"[MEMORY] Total memory size: {total_size:.2f} KB ({total_size/1024:.2f} MB)")
            
            self.results['memory'].append("")
            self.results['memory'].append(f"Total memory regions: {len(memory_maps)}")
            self.results['memory'].append(f"Total memory size: {total_size:.2f} KB ({total_size/1024:.2f} MB)")
            
            # Try to read memory and extract strings (Linux-specific)
            if sys.platform.startswith('linux'):
                print(f"\n[MEMORY] Extracting readable strings from memory...")
                self.results['memory'].append("")
                self.results['memory'].append("Readable Strings Found in Memory:")
                self.results['memory'].append("="*80)
                
                try:
                    mem_file = f"/proc/{self.malware_pid}/mem"
                    maps_file = f"/proc/{self.malware_pid}/maps"
                    
                    with open(maps_file, 'r') as maps:
                        for line in maps:
                            parts = line.split()
                            if len(parts) < 2:
                                continue
                            
                            addr_range = parts[0]
                            perms = parts[1]
                            
                            # Only read readable regions
                            if 'r' not in perms:
                                continue
                            
                            try:
                                start, end = addr_range.split('-')
                                start_addr = int(start, 16)
                                end_addr = int(end, 16)
                                size = end_addr - start_addr
                                
                                # Skip very large regions
                                if size > 10 * 1024 * 1024:  # Skip regions > 10MB
                                    continue
                                
                                with open(mem_file, 'rb') as mem:
                                    mem.seek(start_addr)
                                    data = mem.read(size)
                                    
                                    # Extract strings
                                    strings = self.extract_strings(data)
                                    all_strings.update(strings)
                            except (OSError, ValueError):
                                continue
                    
                    # Display unique strings
                    if all_strings:
                        print(f"[MEMORY] Found {len(all_strings)} unique strings")
                        print(f"[MEMORY] Sample strings (first 50):")
                        
                        for i, string in enumerate(sorted(all_strings)[:50]):
                            if len(string) > 100:
                                string = string[:97] + "..."
                            print(f"  {i+1}. {string}")
                            self.results['memory'].append(f"{i+1}. {string}")
                        
                        # Save all strings
                        self.results['memory'].append("")
                        self.results['memory'].append(f"Total unique strings found: {len(all_strings)}")
                        
                        if len(all_strings) > 50:
                            self.results['memory'].append("")
                            self.results['memory'].append("All strings:")
                            self.results['memory'].append("-"*80)
                            for i, string in enumerate(sorted(all_strings)):
                                self.results['memory'].append(f"{i+1}. {string}")
                    else:
                        print(f"[MEMORY] No readable strings found")
                        self.results['memory'].append("No readable strings found")
                        
                except PermissionError:
                    msg = "Permission denied to read process memory. Try running with sudo."
                    print(f"[MEMORY] {msg}")
                    self.results['memory'].append(msg)
                except Exception as e:
                    msg = f"Error reading memory: {e}"
                    print(f"[MEMORY] {msg}")
                    self.results['memory'].append(msg)
            else:
                msg = "Memory string extraction is only supported on Linux"
                print(f"[MEMORY] {msg}")
                self.results['memory'].append(msg)
                
        except psutil.NoSuchProcess:
            msg = "Process terminated before memory analysis could complete"
            print(f"[MEMORY] {msg}")
            self.results['memory'].append(msg)
        except psutil.AccessDenied:
            msg = "Access denied. Try running with elevated privileges."
            print(f"[MEMORY] {msg}")
            self.results['memory'].append(msg)
        except Exception as e:
            msg = f"Error during memory analysis: {e}"
            print(f"[MEMORY] {msg}")
            self.results['memory'].append(msg)
        
        self.terminate_malware()
    
    def save_results(self):
        """Save all analysis results to text files"""
        print(f"\n[+] Saving results to directory: {self.output_dir}")
        
        # Save PE Information
        if self.results['pe_info']:
            pe_file = os.path.join(self.output_dir, "PE_Information.txt")
            with open(pe_file, 'w') as f:
                f.write("PE FILE INFORMATION\n")
                f.write("="*80 + "\n\n")
                f.write("\n".join(self.results['pe_info']))
            print(f"[+] Saved: PE_Information.txt")
        
        # Save Network Analysis
        network_file = os.path.join(self.output_dir, "Network_Analysis.txt")
        with open(network_file, 'w') as f:
            f.write("NETWORK ANALYSIS\n")
            f.write("="*80 + "\n\n")
            if self.results['network']:
                f.write("\n".join(self.results['network']))
            else:
                f.write("No network activity detected\n")
        print(f"[+] Saved: Network_Analysis.txt")
        
        # Save File System Analysis
        fs_file = os.path.join(self.output_dir, "FileSystem_Analysis.txt")
        with open(fs_file, 'w') as f:
            f.write("FILE SYSTEM ANALYSIS\n")
            f.write("="*80 + "\n\n")
            if self.results['filesystem']:
                f.write("\n".join(self.results['filesystem']))
            else:
                f.write("No file system changes detected\n")
        print(f"[+] Saved: FileSystem_Analysis.txt")
        
        # Save Process Analysis
        proc_file = os.path.join(self.output_dir, "Process_Analysis.txt")
        with open(proc_file, 'w') as f:
            f.write("PROCESS ANALYSIS\n")
            f.write("="*80 + "\n\n")
            if self.results['processes']:
                f.write("\n".join(self.results['processes']))
            else:
                f.write("No process information captured\n")
        print(f"[+] Saved: Process_Analysis.txt")
        
        # Save Memory Dump Analysis
        mem_file = os.path.join(self.output_dir, "Memory_Dump.txt")
        with open(mem_file, 'w') as f:
            f.write("MEMORY DUMP ANALYSIS\n")
            f.write("="*80 + "\n\n")
            if self.results['memory']:
                f.write("\n".join(self.results['memory']))
            else:
                f.write("No memory information captured\n")
        print(f"[+] Saved: Memory_Dump.txt")
        
        print(f"\n[+] All results saved to: {os.path.abspath(self.output_dir)}")
    
    def run_analysis(self):
        """Run all analysis stages"""
        # Setup signal handler for CTRL+C
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Analyze malware file first
        self.analyze_pe_file()
        
        stages = [
            ("Network Analysis", self.network_analysis_stage),
            ("File System Monitoring", self.file_system_monitoring_stage),
            ("Process Monitoring", self.process_monitoring_stage),
            ("Memory Dump Analysis", self.memory_dump_stage)
        ]
        
        print(f"\nMalware Analysis Tool Starting")
        print(f"Target: {self.malware_path}")
        print(f"Duration per stage: {self.duration} seconds")
        print("-" * 60)
        
        for stage_name, stage_func in stages:
            self.current_stage = stage_name
            try:
                stage_func()
            except Exception as e:
                print(f"[-] Error in {stage_name}: {e}")
            
            # Small delay between stages
            if stage_name != stages[-1][0]:
                print(f"\n[+] Preparing next stage...")
                time.sleep(2)
        
        # Save all results
        self.save_results()
        
        print("\n" + "="*60)
        print("ANALYSIS COMPLETE")
        print("="*60)

def main():
    if len(sys.argv) < 2:
        print("Usage: python tool.py malware.exe [-t duration]")
        print("Example: python tool.py C:\\\\malware\\\\sample.exe -t 120")
        sys.exit(1)
    
    malware_path = sys.argv[1]
    duration = 90  # default
    
    # Parse command line arguments
    if "-t" in sys.argv:
        try:
            t_index = sys.argv.index("-t")
            duration = int(sys.argv[t_index + 1])
        except (ValueError, IndexError):
            print("Error: Invalid duration specified")
            sys.exit(1)
    
    # Validate malware path
    if not os.path.exists(malware_path):
        print(f"Error: Malware file '{malware_path}' not found")
        sys.exit(1)
    
    # On Windows, check if it's an executable file (.exe, .dll, .scr, etc.)
    if sys.platform == 'win32':
        valid_extensions = ['.exe', '.dll', '.scr', '.com', '.bat', '.cmd', '.vbs', '.ps1']
        if not any(malware_path.lower().endswith(ext) for ext in valid_extensions):
            print(f"Warning: File may not be a Windows executable")
    else:
        # On Linux/Unix, check if executable
        if not os.access(malware_path, os.X_OK):
            print(f"Error: Malware file '{malware_path}' is not executable")
            sys.exit(1)
    
    # Run analysis
    analyzer = MalwareAnalyzer(malware_path, duration)
    analyzer.run_analysis()

if __name__ == "__main__":
    main()
