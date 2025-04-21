from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, Raw
from utils import relative_path

# win - alternative netsh
def extract_features(scapy_packet: IP, packet) -> dict:
    src_ip = scapy_packet.src
    dst_ip = scapy_packet.dst
    proto = scapy_packet.proto
    length = len(scapy_packet)

    if scapy_packet.proto == 6:
        pr_packet = TCP(packet.get_payload())
        print(f"TCP Packet: Source Port - {pr_packet.sport}")
    elif scapy_packet.proto == 17:
        pr_packet = UDP(packet.get_payload())
        print(f"UDP Packet: Source Port - {pr_packet.sport}")

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "proto": proto,
        "length": length,
        "src_port": pr_packet.sport,
        "data": TCP(packet.get_payload())[Raw]#.load.decode("utf-8", errors="ignore")
    }


def process_packet(packet):
    # https://www.geeksforgeeks.org/python-program-to-validate-an-ip-address/
    scapy_packet = IP(packet.get_payload())
    features = extract_features(scapy_packet, packet)

    with open(relative_path("rules/blacklist/compromised-ips.txt")) as file:
        for line in file:
            if line[0] == "" or line[0] == "\n":
                continue

            if features["src_ip"] == line.strip().replace("\n", ""):
                print(f"❌ Dropping Packet: {scapy_packet.summary()}")
                packet.drop()

    packet.accept()

if __name__ ==  "__main__":
    # Start Netfilter Queue
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, process_packet)

    print("Monitoring Traffic in Real-Time")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\nStopping Firewall...")
        nfqueue.unbind()
