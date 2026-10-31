#!/usr/bin/env python3
import subprocess
import socket
import concurrent.futures
from core.oui import get_vendor

def scan_network():
    """Tarmoqdagi faol IPv4 qurilmalarni aniqlash va brendlarini topish"""
    print("\n[*] Tarmoq qidirilmoqda (ip neigh va arp orqali)...")
    devices = []
    
    # 1. Linux ARP jadvalidan o'qish
    try:
        with open("/proc/net/arp", "r") as f:
            lines = f.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[0]
                    mac = parts[3]
                    if "." in ip and not ip.startswith("169.254") and mac != "00:00:00:00:00:00":
                        vendor = get_vendor(mac)
                        devices.append({'ip': ip, 'mac': mac, 'vendor': vendor})
    except Exception:
        pass

    # 2. `ip neigh` buyrug'i orqali qo'shnilarni olish
    try:
        result = subprocess.run(["ip", "neigh"], capture_output=True, text=True, timeout=2)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 5 and "lladdr" in parts:
                ip = parts[0]
                mac_idx = parts.index("lladdr") + 1
                if mac_idx < len(parts):
                    mac = parts[mac_idx]
                    if "." in ip and not ip.startswith("169.254") and mac != "00:00:00:00:00:00":
                        if not any(d['ip'] == ip for d in devices):
                            vendor = get_vendor(mac)
                            devices.append({'ip': ip, 'mac': mac, 'vendor': vendor})
    except Exception:
        pass

    try:
        devices = sorted(devices, key=lambda x: list(map(int, x['ip'].split('.'))))
    except Exception:
        pass

    return devices

def grab_banner(ip_address, port):
    """Ochiq portdan xizmat haqida ma'lumot (banner) yulib olish"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        s.connect((ip_address, port))
        
        # HTTP portlar uchun maxsus so'rov yuborish
        if port in [80, 443, 8080]:
            s.sendall(b"HEAD / HTTP/1.1\r\nHost: local\r\n\r\n")
        
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        
        # Faqat birinchi qatorni yoki foydali qismni olish
        if banner:
            first_line = banner.split('\n')[0]
            return first_line[:40] # Matn juda uzun bo'lib ketmasligi uchun
    except Exception:
        pass
    return "Ma'lumot topilmadi"

def scan_ports(ip_address):
    """Portlarni skanerlash va banner grabbing (versiyani aniqlash)"""
    ports_to_check = {
        21: "FTP",
        22: "SSH",
        23: "Telnet (Kritik Zaiflik!)",
        80: "HTTP (Web)",
        443: "HTTPS",
        554: "RTSP (IP Kamera)",
        1883: "MQTT (IoT)",
        8080: "HTTP-Proxy/Alt",
        8443: "HTTPS-Alt"
    }
    
    open_ports = []
    
    def check_single_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.4)
            result = s.connect_ex((ip_address, port))
            s.close()
            if result == 0:
                service = ports_to_check.get(port, "Noma'lum")
                # Banner grabbingni bajarish
                banner = grab_banner(ip_address, port)
                open_ports.append({
                    'port': port, 
                    'service': service, 
                    'banner': banner
                })
        except Exception:
            pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(check_single_port, ports_to_check.keys())
        
    return sorted(open_ports, key=lambda x: x['port'])
