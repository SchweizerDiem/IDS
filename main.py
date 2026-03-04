import os
import sys
import time
from datetime import datetime
from scapy.all import sniff, hexdump, conf
from scapy.interfaces import get_if_list
from scapy.utils import wrpcap



def menu():
    clear_screen()
    print(BANNER)
    print("1. Capturar pacotes")
    print("2. Escholher interface")
    print("3. Sair")
    choice = input("Escolha uma opção: ").strip()
    return choice

BANNER = r"""
 __  __ ___ _   _ ___ 
|  \/  |_ _| \ | |_ _|  
| |\/| || ||  \| || 
| |  | || || |\  || |
|_|  |_|___|_| \_|___| 
              MINI-WIRE

              """

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def required_root_hint():
       if os.name == "posix" and os.geteuid() != 0:
        print("  Dica: para capturar pacotes, corre com sudo:")
        print("    sudo ./miniwieshark.py\n")

def list_interfaces():
    return sorted(get_if_list())

def choose_interface(ifaces):
    while True:
        clear_screen()
        print(BANNER)
        required_root_hint()

        print("Interfaces de rede disponíveis:")
        for idx, iface in enumerate(ifaces):
            print(f"{idx + 1}. {iface}")

        print("\nOpção:")
        print(" [q]Sair")

        choice = input("Escolha uma interface para capturar: ").strip().lower()
        if choice == 'q':
            print("Saindo...")
            return None
        
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(ifaces):
                return ifaces[idx]
        print("Opção inválida. Tente novamente.")
        input()


def packet_handler(packet):

    #hora | protocolo | src -> dst | len | info

    ts = datetime.now().strftime('%H:%M:%S')

    leng = len(packet) if hasattr(packet, "__len__") else "?"

    summary = packet.summary()

    # Tentar extrair src/dst human-friendly quando existe IP
    src = dst = "-"
    if packet.haslayer("IP"):
        ip = packet.getlayer("IP")
        src, dst = ip.src, ip.dst
    elif packet.haslayer("IPv6"):
        ip6 = packet.getlayer("IPv6")
        src, dst = ip6.src, ip6.dst
    elif packet.haslayer("ARP"):
        arp = packet.getlayer("ARP")
        src, dst = getattr(arp, "psrc", "-"), getattr(arp, "pdst", "-")

    # “proto” simplificado
    proto = "-"
    for p in ("TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "TLS", "Raw"):
        if packet.haslayer(p):
            proto = p
            break

    return f"{ts} | {proto:4} | {src} -> {dst} | {leng:4} | {summary}"

def capture_loop(iface):
    clear_screen()
    print(BANNER)
    print(f"Capturando em: {iface}")
    print("Ctrl+C para parar e voltar ao menu.\n")

    packets = []

    def on_packet(pkt):
        print(packet_handler(pkt),flash=True)
    try:
        sniff(iface=iface, prn=on_packet, store=False)
    except PermissionError:
        print("\n[-] Permissão negada. Corre com sudo.")
        input("Enter para voltar ao menu...")
    except OSError as e:
        print(f"\n[-] Erro ao abrir interface '{iface}': {e}")
        input("Enter para voltar ao menu...")
    except KeyboardInterrupt:
        ans = input("\nDeseja salvar a captura? (s/n): ").strip().lower()
        if ans == 's':
            from scapy.utils import wrpcap
            filename = f"capture_{int(time.time())}.pcap"
            wrpcap(filename, packets)
            print(f"Captura salva em: {filename}")


def main():
    BANNER
    while True:
        choice = menu()

        if choice == "1":
            if iface is None:
                clear_screen()
                print("[-] Nenhuma interface selecionada. Escolha uma interface primeiro.")
                input("Enter para voltar ao menu...")
            else:
                capture_loop(iface)

        elif choice == "2":
            iface = choose_interface(ifaces=list_interfaces())

        elif choice == "3":
            clear_screen()
            print("Até já")
            return
        
        else:
            clear_screen()
            print("Opção inválida. Tente novamente.")
            input("Enter para continuar...")

if __name__ == "__main__":
    main()