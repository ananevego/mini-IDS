from collections import defaultdict
import time

connection_counter = defaultdict(int)
dns_counter = defaultdict(int)
last_reset = time.time()

CONNECTION_THRESHOLD = 50 # пороговые значения
DNS_THRESHOLD = 30
RESET_INTERVAL = 30

def analyze_packet(data):
    global last_reset
    current_time = time.time()
    if current_time - last_reset > RESET_INTERVAL: # сброс счетчиков
        connection_counter.clear()
        dns_counter.clear()
        last_reset = current_time

    src_ip = data["src_ip"]
    dst_port = data["dst_port"] # анализируем "кто" генерирует трафик

    connection_counter[src_ip] += 1 

    if connection_counter[src_ip] > CONNECTION_THRESHOLD: # слишком много пакетов
        return f"High connection activity from {src_ip}"
    
    if data["protocol"] == "UDP" and dst_port == 53: # слишком много DNS запросов
        dns_counter[src_ip] += 1
        if dns_counter[src_ip] > DNS_THRESHOLD:
            return f"High DNS activity from {src_ip}"
        
    common_ports = [80, 443, 53, 22, 25, 110, 143]
    if data["dst_port"] not in common_ports and data["dst_port"] < 1024:
        return f"Uncommon system port {data['dst_port']}"

    return None