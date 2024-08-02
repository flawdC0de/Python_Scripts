import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((str(ip), port))
            if result == 0:
                return ip, port
    except:
        pass
    return None

def scan_ip(ip, ports):
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: scan_port(ip, p), ports)
        for result in results:
            if result:
                open_ports.append(result[1])
    if open_ports:
        print(f"Open ports for {ip}: {', '.join(map(str, open_ports))}")

def main():
    try:
        ip_range = input("Enter IP range (e.g., 192.168.1.0/24): ")
        start_port = int(input("Enter starting port: "))
        end_port = int(input("Enter ending port: "))

        network = ipaddress.ip_network(ip_range, strict=False)
        ports = range(start_port, end_port + 1)

        for ip in network.hosts():
            scan_ip(ip, ports)

    except ValueError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")

if __name__ == "__main__":
    main()
