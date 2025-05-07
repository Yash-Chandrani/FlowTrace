#include <pcap.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <unordered_map>
#include <sstream>

using namespace std;

// A simple struct to key a flow by 5-tuple
struct FlowKey {
    string src_ip, dst_ip;
    int proto;
    int src_port, dst_port;

    bool operator==(FlowKey const &o) const {
        return src_ip==o.src_ip && dst_ip==o.dst_ip &&
               proto==o.proto &&
               src_port==o.src_port && dst_port==o.dst_port;
    }
};

// Hash function for FlowKey so we can use it in an unordered_map
struct FlowKeyHash {
    size_t operator()(FlowKey const &k) const {
        size_t h1 = hash<string>()(k.src_ip);
        size_t h2 = hash<string>()(k.dst_ip);
        size_t h3 = hash<int>()(k.proto);
        size_t h4 = hash<int>()(k.src_port);
        size_t h5 = hash<int>()(k.dst_port);
        return (((h1*31 + h2)*31 + h3)*31 + h4)*31 + h5;
    }
};

// Per-flow counters: packets and bytes
struct FlowCounter {
    size_t packets = 0;
    size_t bytes   = 0;
};

// Global map of flows
unordered_map<FlowKey, FlowCounter, FlowKeyHash> flowTable;

// -------------------------
// Ethernet Header (14 bytes)
// -------------------------
struct ethernet_header {
    u_char dest[6];
    u_char src[6];
    u_short type;
};

// -------------------------
// IP Header (no options)
// -------------------------
struct ip_header {
    u_char ver_ihl;
    u_char tos;
    u_short tlen;
    u_short identification;
    u_short flags_fo;
    u_char ttl;
    u_char proto;
    u_short crc;
    u_int src_addr;
    u_int dst_addr;
};

// -------------------------
// TCP Header (simplified)
// -------------------------
struct tcp_header {
    u_short src_port;
    u_short dst_port;
    u_int sequence;
    u_int ack_number;
    u_char data_offset_reserved;
    u_char flags;
    u_short window;
    u_short checksum;
    u_short urgent_pointer;
};

// -------------------------
// UDP Header (8 bytes)
// -------------------------
struct udp_header {
    u_short src_port;
    u_short dst_port;
    u_short length;
    u_short checksum;
};

// -------------------------
// ICMP Header (8 bytes)
// -------------------------
struct icmp_header {
    u_char type;
    u_char code;
    u_short checksum;
    u_short rest1;
    u_short rest2;
};

// -------------------------
// Globals: CSV, stats, UDP
// -------------------------
ofstream csvFile;
size_t totalPackets = 0;
size_t totalBytes   = 0;
unordered_map<int, size_t> protocolCounts;

int udpSock;
struct sockaddr_in udpAddr;

// -------------------------
// Print MAC helper (immediate flush)
// -------------------------
void print_mac(const u_char* mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02X", mac[i]);
        if (i < 5) printf(":");
    }
    printf("\n");
    fflush(stdout);
}

// -------------------------
// Decode TCP flags into human-readable string
// -------------------------
string decodeTcpFlags(u_char flags) {
    string s;
    if (flags & 0x01) s += "FIN ";
    if (flags & 0x02) s += "SYN ";
    if (flags & 0x04) s += "RST ";
    if (flags & 0x08) s += "PSH ";
    if (flags & 0x10) s += "ACK ";
    if (flags & 0x20) s += "URG ";
    if (flags & 0x40) s += "ECE ";
    if (flags & 0x80) s += "CWR ";
    if (s.empty()) s = "NONE";
    return s;
}

// -------------------------
// Process, log & forward
// -------------------------
void processPacketData(const pcap_pkthdr* pkthdr, const u_char* packet) {
    totalPackets++;
    totalBytes += pkthdr->len;

    cout << "[AGENT] Packet captured: " << pkthdr->len << " bytes\n";

    // --- Ethernet Header ---
    if (pkthdr->len < sizeof(ethernet_header)) {
        cout << "Packet too short for Ethernet header.\n\n";
        return;
    }
    auto* eth = reinterpret_cast<const ethernet_header*>(packet);
    cout << "Ethernet Header:\n";
    cout << "  Dest MAC: "; print_mac(eth->dest);
    cout << "  Src MAC : "; print_mac(eth->src);
    u_short ether_type = ntohs(eth->type);
    cout << "  EtherType: 0x" << hex << ether_type << dec << "\n";

    if (ether_type != 0x0800) {
        cout << "Not an IP packet.\n\n";
        return;
    }

    // --- IP Header ---
    if (pkthdr->len < sizeof(ethernet_header) + sizeof(ip_header)) {
        cout << "Packet too short for IP header.\n\n";
        return;
    }
    auto* ip = reinterpret_cast<const ip_header*>(packet + sizeof(ethernet_header));
    int ihl = (ip->ver_ihl & 0x0F) * 4;
    if (pkthdr->len < sizeof(ethernet_header) + ihl) {
        cout << "Packet too short for full IP header.\n\n";
        return;
    }
    struct in_addr src, dst;
    src.s_addr = ip->src_addr;
    dst.s_addr = ip->dst_addr;
    u_char proto = ip->proto;
    protocolCounts[proto]++;

    cout << "IP Header:\n";
    cout << "  Src IP: " << inet_ntoa(src) << "\n";
    cout << "  Dst IP: " << inet_ntoa(dst) << "\n";
    cout << "  Protocol: " << static_cast<int>(proto) << "\n";

    int sport = 0, dport = 0;

    // --- TCP Header ---
    if (proto == 6) {
        if (pkthdr->len < sizeof(ethernet_header) + ihl + sizeof(tcp_header)) {
            cout << "Packet too short for TCP header.\n\n";
            return;
        }
        auto* tcp = reinterpret_cast<const tcp_header*>(
            packet + sizeof(ethernet_header) + ihl
        );
        sport = ntohs(tcp->src_port);
        dport = ntohs(tcp->dst_port);
        int thl = ((tcp->data_offset_reserved >> 4) & 0x0F) * 4;

        cout << "TCP Header:\n";
        cout << "  Src Port: " << sport << "\n";
        cout << "  Dst Port: " << dport << "\n";
        cout << "  Header Len: " << thl << " bytes\n";
        cout << "  Flags    : " << decodeTcpFlags(tcp->flags) << "\n\n";
    }
    // --- UDP Header ---
    else if (proto == 17) {
        if (pkthdr->len < sizeof(ethernet_header) + ihl + sizeof(udp_header)) {
            cout << "Packet too short for UDP header.\n\n";
            return;
        }
        auto* udp = reinterpret_cast<const udp_header*>(
            packet + sizeof(ethernet_header) + ihl
        );
        sport = ntohs(udp->src_port);
        dport = ntohs(udp->dst_port);

        cout << "UDP Header:\n";
        cout << "  Src Port: " << sport << "\n";
        cout << "  Dst Port: " << dport << "\n";
        cout << "  Length  : " << ntohs(udp->length) << " bytes\n\n";
    }
    // --- ICMP Header ---
    else if (proto == 1) {
        if (pkthdr->len < sizeof(ethernet_header) + ihl + sizeof(icmp_header)) {
            cout << "Packet too short for ICMP header.\n\n";
            return;
        }
        auto* icmp = reinterpret_cast<const icmp_header*>(
            packet + sizeof(ethernet_header) + ihl
        );
        cout << "ICMP Header:\n";
        cout << "  Type: " << static_cast<int>(icmp->type)
             << "  Code: " << static_cast<int>(icmp->code) << "\n\n";
    }
    else {
        cout << "Other IP protocol.\n\n";
    }

    // --- Flow Tracking ---
    FlowKey key{ inet_ntoa(src), inet_ntoa(dst), static_cast<int>(proto), sport, dport };
    auto &ctr = flowTable[key];
    ctr.packets += 1;
    ctr.bytes   += pkthdr->len;

    // --- CSV Logging & UDP Forward ---
    ostringstream oss;
    long sec  = pkthdr->ts.tv_sec;
    long usec = pkthdr->ts.tv_usec;
    oss << sec << "." << setw(6) << setfill('0') << usec << setfill(' ')
        << "," << inet_ntoa(src)
        << "," << inet_ntoa(dst)
        << "," << static_cast<int>(proto)
        << "," << sport
        << "," << dport
        << "\n";
    string line = oss.str();

    csvFile << line;
    sendto(udpSock, line.c_str(), line.size(), 0,
           (struct sockaddr*)&udpAddr, sizeof(udpAddr));
}

int main() {
    // --- Disable stdout buffering for both printf and cout ---
    setvbuf(stdout, nullptr, _IONBF, 0);
    ios::sync_with_stdio(false);
    cout << unitbuf;

    char errbuf[PCAP_ERRBUF_SIZE];
    const char* device     = "enp0s3";
    const char* filter_exp = "tcp port 80 or tcp port 443 or icmp";

    // Open CSV
    csvFile.open("packets.csv");
    csvFile << "timestamp,src_ip,dst_ip,protocol,src_port,dst_port\n";

    // Setup UDP socket
    udpSock = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&udpAddr, 0, sizeof(udpAddr));
    udpAddr.sin_family = AF_INET;
    udpAddr.sin_port   = htons(9999);
    inet_pton(AF_INET, "127.0.0.1", &udpAddr.sin_addr);

    // Open pcap handle
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    cout << "Listening on " << device
         << " with filter [" << filter_exp << "]\n\n";

    // Compile & apply filter
    bpf_program fp;
    pcap_compile(handle, &fp, filter_exp, 0, 0);
    pcap_setfilter(handle, &fp);
    pcap_freecode(&fp);
    cout << "Filter applied: " << filter_exp << "\n\n";

    // Capture 10 packets
    pcap_loop(handle, 10,
      [](u_char*, const pcap_pkthdr* h, const u_char* p){
        processPacketData(h,p);
      }, nullptr);

    // Teardown
    pcap_close(handle);
    csvFile.close();
    close(udpSock);

    // Print summary
    cout << "\n--- Capture Summary ---\n";
    cout << "Total packets: " << totalPackets << "\n";
    cout << "Total bytes  : " << totalBytes << "\n";
    if (totalPackets) {
        cout << fixed << setprecision(2)
             << "Average size: " << (double)totalBytes/totalPackets
             << " bytes\n";
    }
    cout << "Protocol counts:\n";
    for (auto& kv : protocolCounts) {
        cout << "  Protocol " << kv.first
             << ": " << kv.second << "\n";
    }

    // --- Flow Summary ---
    cout << "\n--- Top Flows ---\n";
    for (auto &kv : flowTable) {
        auto &k = kv.first;
        auto &c = kv.second;
        cout << k.src_ip << ":" << k.src_port
             << " → " << k.dst_ip << ":" << k.dst_port
             << " (proto " << k.proto << ") : "
             << c.packets << " pkts, "
             << c.bytes << " bytes\n";
    }

    return 0;
}
