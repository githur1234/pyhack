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
 I8               ,d8I'                                            
 I8             ,dP'8I                                             
 I8            ,8"  8I                                             
 I8            I8   8I                                             
 I8            `8, ,8I                                             
 I8             `Y8P"        
""")
    print("[0] use pyhack tool")
    print("[1] use phantomhack tool")
    print("[2] use hack tool")
    ch=input("pyhack>>>")
    if ch=="1":
        phantomhack.main()
    if ch=="2":
        hack.main()
    if ch=="0":
        Os=os.name
        if Os=="nt":
         os.system("cls")
        if Os=="posix":
         os.system("clear")
        print("yakında gelicek")
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
