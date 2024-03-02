from scapy.all import DNS, DNSQR, IP, UDP, sr1

DNS_SERVER = "1.1.1.1"
DNS_A_TYPE = 1
DNS_AAAA_TYPE = 28
DNS_CNAME_TYPE = 5
DNS_DST_PORT = 53
TYPE_IPV4 = "A"
TYPE_IPV6 = "AAAA"


def nslookup(domain):
    try:
        # Create DNS query packet for IPv4 (A records)
        dns_query_packet_ipv4 = IP(dst=DNS_SERVER) / UDP(dport=DNS_DST_PORT) / DNS(rd=1, qd=DNSQR(qname=domain, qtype=TYPE_IPV4))

        # Send packet and receive response for IPv4
        response_ipv4 = sr1(dns_query_packet_ipv4, timeout=0.3, verbose=False)
        count = 0
        if response_ipv4 is None and count < 3:
            response_ipv4 = sr1(dns_query_packet_ipv4, timeout=0.3, verbose=False)
            count += 1

        # Create DNS query packet for IPv6 (AAAA records)
        dns_query_packet_ipv6 = IP(dst=DNS_SERVER) / UDP(dport=DNS_DST_PORT) / DNS(rd=1, qd=DNSQR(qname=domain, qtype=TYPE_IPV6))

        # Send packet and receive response for IPv6
        response_ipv6 = sr1(dns_query_packet_ipv6, timeout=0.3, verbose=False)
        count = 0
        if response_ipv6 is None and count < 3:
            response_ipv6 = sr1(dns_query_packet_ipv6, timeout=0.3, verbose=False)
            count += 1

        dns_answer(response_ipv4, response_ipv6)

    except UnboundLocalError as e:
        print(f"UnKnown can't find {domain}: Non-existent domain")

    except Exception as e:
        print(f"ERROR has occurred: {e}")


def dns_answer(response_ipv4, response_ipv6):
    address = []
    aliases = []

    for record in range(response_ipv6[DNS].ancount):
        if response_ipv6.an[record].type == DNS_CNAME_TYPE:  # CNAME record type
            aliases.append(response_ipv6.an[record].rrname.decode())

        elif response_ipv6.an[record].type == DNS_AAAA_TYPE:  # AAAA record type
            address.append(response_ipv6.an[record].rdata)

    for record in range(response_ipv4[DNS].ancount):
        if response_ipv4.an[record].type == DNS_A_TYPE:  # A record type
            address.append(response_ipv4.an[record].rdata)
            name = response_ipv4.an[record].rrname

    if name:
        print("\nNon-authoritative answer:")
        print("Name:", name.decode())

    if address:
        print("Addresses:", address[0])

    for addr in address:
        if addr != address[0] and addr != "":
            print("\t" + addr)

    if aliases:
        print("Aliases:", aliases[0])

    for aliasis in aliases:
        if aliasis != aliases[0] and aliasis != "":
            print("\t" + aliasis)


def main():
    domain = input("Enter domain: ")
    nslookup(domain)


if __name__ == "__main__":
    main()
