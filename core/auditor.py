#!/usr/bin/env python3
import socket

# Eng ko'p tarqalgan IoT va router standart parollari
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("root", "root"),
    ("admin", "password"),
    ("admin", "1234"),
    ("root", "12345"),
    ("admin", ""),
    ("root", "")
]

# Mashhur vendorlar va xizmatlar uchun ma'lum ehtimoliy zaifliklar bazasi
KNOWN_VULNERABILITIES = {
    "TP-Link": [
        {"id": "CVE-VEND-01", "desc": "Ba'zi eski firmware versiyalarida autentifikatsiyani chetlab o'tish (Auth Bypass) xavfi mavjud."},
        {"id": "NET-TELNET-RISK", "desc": "Telnet xizmati orqali parollarni tarmoqda ochiq holda tutib qolish (Sniffing) oson."}
    ],
    "Espressif": [
        {"id": "IOT-MQTT-01", "desc": "MQTT trafigi shifrlanmagan (Plaintext) bo'lishi mumkin."}
    ]
}

def audit_credentials(ip_address, port):
    """Telnet (23) porti uchun standart parollarni avtomatik tekshirish"""
    found_creds = []
    
    if port == 23:
        for username, password in DEFAULT_CREDENTIALS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.2)
                s.connect((ip_address, port))
                
                # Banner yoki login so'rovini kutish
                s.recv(1024)
                
                # Foydalanuvchi nomini yuborish
                s.sendall((username + "\r\n").encode())
                s.recv(1024)
                
                # Parolni yuborish
                s.sendall((password + "\r\n").encode())
                response = s.recv(1024)
                s.close()
                
                resp_str = response.decode('utf-8', errors='ignore').lower()
                # Muvaffaqiyatli kirish belgilari (# yoki $ yoki welcome)
                if any(kw in resp_str for kw in ['#', '$', 'welcome', 'logged', 'busybox', 'router']):
                    found_creds.append((username, password))
                    break
            except Exception:
                pass
                
    return found_creds

def get_cve_warnings(vendor, open_ports):
    """Brend va ochiq portlarga qarab CVE/zaifliklar xulosasini tuzish"""
    warnings = []
    
    # Vendor bo'yicha bazadan qidirish
    if vendor in KNOWN_VULNERABILITIES:
        warnings.extend(KNOWN_VULNERABILITIES[vendor])
        
    # Portlar bo'yicha umumiy zaifliklar
    for p in open_ports:
        port_num = p['port']
        if port_num == 23:
            warnings.append({"id": "CRIT-TELNET", "desc": "Telnet (23) protokoli shifrlanmagan bo'lib, ma'lumotlarni ochiq uzatadi."})
        elif port_num == 80:
            warnings.append({"id": "WARN-HTTP", "desc": "HTTP (80) orqali uzatiladigan ma'lumotlar shifrlanmagan (HTTPS tavsiya etiladi)."})
            
    return warnings
