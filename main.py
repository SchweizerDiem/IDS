import os
import sys
import threading
import select
import termios
import tty
import time
import shutil
import subprocess
from datetime import datetime

from scapy.all import sniff, get_if_list, wrpcap


RCLONE_CONFIG = "/home/alezandrio/.config/rclone/rclone.conf"
RCLONE_REMOTE = "gdrive:pcaps"

BANNER = r"""
 __  __ ___ _   _ ___        ____  _   _    _    ____  _  __
|  \/  |_ _| \ | |_ _|      / ___|| | | |  / \  |  _ \| |/ /
| |\/| || ||  \| || |       \___ \| |_| | / _ \ | |_) | ' /
| |  | || || |\  || |        ___) |  _  |/ ___ \|  _ <| . \
|_|  |_|___|_| \_|___|      |____/|_| |_/_/   \_\_| \_\_|\_\

                     MINI-WIRE SHARK
"""

CAPTURE_TIME = 180  # 3 minutos
RCLONE_REMOTE = "gdrive:pcaps"


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def required_root_hint():
    if os.name == "posix" and os.geteuid() != 0:
        print("Dica: para capturar pacotes, corre com sudo:")
        print("  sudo ./venv/bin/python main.py\n")


def list_interfaces():
    return sorted(get_if_list())


def choose_interface_automatic(scan_time=3):
    interfaces = list_interfaces()
    counts = {}

    print("Finding interface more active...")
    for iface in interfaces:
        try:
            packets = sniff(iface=iface, timeout=scan_time, store=True)
            counts[iface] = len(packets)
        except Exception:
            counts[iface] = 0

    if not counts:
        return None

    best = max(counts, key=counts.get)

    print("\nPackets by interface:")
    for iface, count in counts.items():
        print(f"  {iface}: {count}")

    print(f"\nChosen automatically: {best}")
    time.sleep(2)
    return best


def choose_interface_by_command(ifaces):
    while True:
        clear_screen()
        print(BANNER)
        required_root_hint()

        print("Interfaces de rede disponíveis:")
        for idx, iface in enumerate(ifaces, start=1):
            print(f"{idx}. {iface}")

        print("\nOpção:")
        print("[q] Sair")

        choice = input("Escolha uma interface para capturar: ").strip().lower()

        if choice == "q":
            print("Saindo...")
            return None

        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(ifaces):
                return ifaces[idx]

        print("Opção inválida. Tente novamente.")
        input("Enter para continuar...")


def packet_handler(packet):
    ts = datetime.now().strftime("%H:%M:%S")
    leng = len(packet) if hasattr(packet, "__len__") else "?"
    summary = packet.summary()

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

    proto = "-"
    for p in ("TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "TLS", "Raw"):
        if packet.haslayer(p):
            proto = p
            break

    return f"{ts} | {proto:4} | {src} -> {dst} | {leng:4} | {summary}"


def key_listener(stop_event, setup_event):
    if os.name != "posix":
        return

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    try:
        tty.setcbreak(fd)
        while not stop_event.is_set():
            rlist, _, _ = select.select([sys.stdin], [], [], 0.2)
            if rlist:
                key = sys.stdin.read(1).lower()
                if key == "p":
                    setup_event.set()
                    stop_event.set()
                    break
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def check_rclone():
    return shutil.which("rclone") is not None


def upload_to_drive(filepath):
    if not check_rclone():
        print("\n[-] rclone não encontrado no sistema.")
        print("    Instala e configura primeiro com: rclone config")
        return False

    print(f"\n[+] A enviar '{filepath}' para {RCLONE_REMOTE} ...")

    try:
        result = subprocess.run(
            [
                "rclone",
                "--config", RCLONE_CONFIG,
                "copy",
                filepath,
                RCLONE_REMOTE
            ],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode == 0:
            print("[+] Upload concluído com sucesso.")
            return True

        print("[-] Falha no upload para o Google Drive.")
        if result.stderr:
            print(result.stderr.strip())
        if result.stdout:
            print(result.stdout.strip())
        return False

    except Exception as e:
        print(f"[-] Erro ao executar rclone: {e}")
        return False


def save_capture(packets, iface):
    if not packets:
        print("Nenhum pacote capturado.")
        return

    safe_iface = iface.replace("/", "_").replace("\\", "_").replace(" ", "_")
    filename = f"capture_grp_{safe_iface}_{int(time.time())}.pcap"

    wrpcap(filename, packets)
    print(f"Captura guardada em: {filename}")

    try:
        success = upload_to_drive(filename)
        if not success:
            print("[!] Upload falhou, mas o ficheiro ficou guardado localmente.")
    except Exception as e:
        print(f"[!] Erro no upload, mas o ficheiro ficou guardado localmente: {e}")


def capture_loop(iface):
    clear_screen()
    print(BANNER)
    print(f"Capturando em: {iface}")
    print(f"Captura automática: {CAPTURE_TIME} segundos")
    print("Carrega 'p' para entrar no setup mode.\n")

    packets = []
    stop_event = threading.Event()
    setup_event = threading.Event()

    listener = threading.Thread(
        target=key_listener,
        args=(stop_event, setup_event),
        daemon=True
    )
    listener.start()

    start_time = time.time()

    def on_packet(pkt):
        packets.append(pkt)
        print(packet_handler(pkt), flush=True)

    def should_stop(pkt):
        if stop_event.is_set():
            return True
        if time.time() - start_time >= CAPTURE_TIME:
            stop_event.set()
            return True
        return False

    try:
        sniff(
            iface=iface,
            prn=on_packet,
            store=False,
            stop_filter=should_stop,
            timeout=CAPTURE_TIME + 1
        )
    except PermissionError:
        print("\n[-] Permissão negada. Corre com sudo.")
        input("Enter para voltar...")
        return "menu"
    except OSError as e:
        print(f"\n[-] Erro ao abrir interface '{iface}': {e}")
        input("Enter para voltar...")
        return "menu"
    except KeyboardInterrupt:
        print("\nInterrompido pelo utilizador.")
        stop_event.set()
        save_capture(packets, iface)
        input("Enter para continuar...")
        return "menu"

    save_capture(packets, iface)

    if setup_event.is_set():
        return "menu"

    print("\nCaptura terminada automaticamente ao fim de 3 minutos.")
    input("Enter para continuar...")
    return "continue"


def setup_menu(current_iface):
    while True:
        clear_screen()
        print(BANNER)
        print(f"Interface atual: {current_iface}\n")
        print("1. Continuar captura")
        print("2. Escolher interface manualmente")
        print("3. Escolher interface automaticamente")
        print("4. Sair")

        choice = input("\nEscolha uma opção: ").strip()

        if choice == "1":
            return current_iface, "capture"

        elif choice == "2":
            chosen = choose_interface_by_command(list_interfaces())
            if chosen:
                current_iface = chosen

        elif choice == "3":
            auto = choose_interface_automatic(scan_time=3)
            if auto:
                current_iface = auto

        elif choice == "4":
            return current_iface, "exit"

        else:
            print("Opção inválida.")
            input("Enter para continuar...")


def main():
    clear_screen()
    print(BANNER)
    required_root_hint()

    iface = choose_interface_automatic(scan_time=3)

    if iface is None:
        print("Não foi possível escolher uma interface automaticamente.")
        return

    capture_loop(iface)

    clear_screen()
    print("Captura terminada. Programa encerrado.")


if __name__ == "__main__":
    main()