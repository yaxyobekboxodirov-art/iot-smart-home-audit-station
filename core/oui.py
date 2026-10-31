#!/usr/bin/env python3

VENDOR_DATABASE = {
    "60:D2:DD": "TP-Link Corporation",
    "1C:3B:F3": "TP-Link",
    "00:11:22": "Test Device / Virtual",
    "00:0C:29": "VMware Virtual",
    "00:50:56": "VMware Virtual",
    "00:15:5D": "Microsoft WSL/Hyper-V",
    "48:22:54": "Xiaomi Communications",
    "28:6C:07": "Xiaomi",
    "78:11:DC": "Apple",
    "00:1A:2B": "Intel Corporate",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Espressif (ESP8266/ESP32 IoT)",
    "24:6F:28": "Espressif Systems",
    "CC:50:E3": "Espressif Systems",
    "5C:CF:7F": "Espressif Systems",
    "3C:71:BF": "Samsung Electronics",
    "00:21:6A": "Samsung Electronics"
}

def get_vendor(mac_address):
    """MAC manzil bo'yicha brendni aniqlash"""
    if not mac_address:
        return "Noma'lum"
    
    clean_mac = mac_address.upper().strip()
    oui_prefix = clean_mac[:8]
    
    return VENDOR_DATABASE.get(oui_prefix, "Boshqa / Aniqlanmagan")
