#!/usr/bin/env python3
import sys
import os

try:
    from colorama import init, Fore
    from core.scanner import scan_network, scan_ports
    from core.auditor import audit_credentials, get_cve_warnings
except ImportError:
    print("[X] Xatolik: Kerakli kutubxonalar topilmadi!")
    sys.exit(1)

init(autoreset=True)

def show_banner():
    print(Fore.CYAN + """
    ╔═══════════════════════════════════════════════╗
    ║       IoT & Smart Home Audit Station          ║
    ║       Kali Linux Security Tool v1.0           ║
    ╚═══════════════════════════════════════════════╝
    """)

def handle_scan():
    devices = scan_network()
    
    if devices:
        print(Fore.GREEN + f"\n[+] Topilgan qurilmalar soni: {len(devices)}\n")
        print(Fore.YELLOW + f"{'№':<3} | {'IP Manzil':<15} | {'MAC Manzil':<18} | {'Brend':<20}")
        print("-" * 65)
        for idx, dev in enumerate(devices, 1):
            print(Fore.WHITE + f"{idx:<3} | {dev['ip']:<15} | {dev['mac']:<18} | {dev['vendor']:<20}")
        
        print(Fore.CYAN + "\n[?] To'liq xavfsizlik auditi (Portlar, Banner, Standart Parollar va CVE) uchun raqamni tanlang")
        choice = input(Fore.WHITE + "Raqamni kiriting (Ortga qaytish uchun Enter bosing): ").strip()
        
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(devices):
                target = devices[idx]
                print(Fore.BLUE + f"\n[*] {target['ip']} ({target['vendor']}) chuqur tahlil qilinmoqda...")
                
                # 1. Portlarni va bannerlarni tekshirish
                ports = scan_ports(target['ip'])
                
                if ports:
                    print(Fore.GREEN + f"\n[+] Ochiq portlar va xizmat versiyalari ({len(ports)} ta):\n")
                    print(Fore.YELLOW + f"{'Port':<6} | {'Xizmat':<24} | {'Banner / Versiya Ma\'lumoti':<30}")
                    print("-" * 66)
                    for p in ports:
                        color = Fore.RED if p['port'] == 23 else Fore.WHITE
                        print(color + f"{p['port']:<6} | {p['service']:<24} | {p['banner']:<30}")
                    
                    # 2. Standart parollarni tekshirish (Brute-force simulation)
                    print(Fore.CYAN + "\n[*] Standart parollar (Default Credentials) tekshirilmoqda...")
                    telnet_open = any(p['port'] == 23 for p in ports)
                    
                    if telnet_open:
                        creds = audit_credentials(target['ip'], 23)
                        if creds:
                            print(Fore.RED + "[!] KRITIK XAVF: Qurilmada standart parollar topildi!")
                            for u, p_word in creds:
                                p_display = p_word if p_word else "<bo'sh parol>"
                                print(Fore.RED + f"    -> Username: {u} | Password: {p_display}")
                        else:
                            print(Fore.GREEN + "[+] Standart parollar topilmadi (parollar o'zgartirilgan yoki himoyalangan).")
                    else:
                        print(Fore.GREEN + "[-] Telnet porti yopiq, parol tekshirilmadi.")

                    # 3. CVE va Xavfsizlik xulosasi
                    print(Fore.CYAN + "\n--- CVE & XAVFSIZLIK ZAYIFLIKLari TUSHUNCHA BAZASI ---")
                    warnings = get_cve_warnings(target['vendor'], ports)
                    if warnings:
                        for w in warnings:
                            print(Fore.RED + f"[!] [{w['id']}] {w['desc']}")
                    else:
                        print(Fore.GREEN + "[+] Ma'lum bo'lgan kritik zaifliklar topilmadi.")
                else:
                    print(Fore.RED + "\n[-] Ochiq portlar topilmadi.")
            else:
                print(Fore.RED + "\n[X] Noto'g'ri raqam tanlandi!")
    else:
        print(Fore.RED + "\n[-] Hozircha qurilmalar topilmadi.")

def main():
    while True:
        show_banner()
        print(Fore.GREEN + "[+] Dastur muvaffaqiyatli ishga tushdi!")
        print(Fore.YELLOW + "[1] Tarmoqdagi IoT qurilmalarni skanerlash & Audit")
        print(Fore.YELLOW + "[2] Chiqish")
        
        choice = input(Fore.WHITE + "\nTanlovingiz (1-2): ").strip()
        
        if choice == '1':
            handle_scan()
            input(Fore.CYAN + "\nDavom etish uchun Enter tugmasini bosing...")
        elif choice == '2':
            print(Fore.RED + "\n[!] Dastur yopildi. Xayr!")
            sys.exit(0)
        else:
            print(Fore.RED + "[X] Noto'g'ri tanlov!")
            input(Fore.CYAN + "Qayta urinish uchun Enter tugmasini bosing...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n\n[!] Dastur to'xtatildi.")
        sys.exit(0)
