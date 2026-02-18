from scapy.all import sniff, get_if_list, get_if_addr
from packet_parser import parse_packet
from detector import analyze_packet
import logging
import ipaddress
from datetime import datetime

class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

def format_output(parsed_data, alert = None):
    timestamp = datetime.now().strftime("%H:%M:%S")

    line = (
        f"[{timestamp}]" 
        f"{parsed_data['protocol']:>3} | "
        f"{parsed_data['src_ip']}:{parsed_data['src_port']} "
        f"->"
        f"{parsed_data['dst_ip']}:{parsed_data['dst_port']}"
    )
    if alert:
        line += f" ⚠ {alert}"
    
    return line

logging.basicConfig( # настройка логирования
    filename = "traffic.log",
    level = logging.INFO,
    filemode="w",
    format = "%(asctime)s - %(levelname)s - %(message)s"
)

def proccess_packet(packet):
    parsed_data = parse_packet(packet)
    if not parsed_data:
        return
    alert = analyze_packet(parsed_data)
    output = format_output(parsed_data, alert)

    if alert:
        print(Colors.RED + output + Colors.RESET)
        logging.warning(output)
    else:
        print(Colors.GREEN + output + Colors.RESET)
        logging.info(output)

if __name__ == "__main__":
    print("Starting Network Traffic Observer...")

    interfaces = []
    print("Active interfaces:")
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)

            ip_obj = ipaddress.ip_address(ip)

            if (
                not ip_obj.is_loopback 
                and not ip_obj.is_link_local
                and not ip_obj.is_unspecified
            ):
                interfaces.append(iface)
                print(f"{len(interfaces)-1}: {iface} ({ip})")

        except Exception:
            pass
      
    choice = int(input("Select interface number: ")) # выбор интерфейсы
    if choice < 0 or choice >= len(interfaces):
        print("Invalid choice")
        exit()

    selected_iface = interfaces[choice]
    print(f"Listening on: {selected_iface}")
        
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
       
    sniff(
        prn = proccess_packet,
        store = False,
        filter = "ip and (tcp or udp)",
        iface = selected_iface
    )