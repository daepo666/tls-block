#include "tls_block.h"

#include <cstdio>
#include <cstring>
#include <strings.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>


int get_my_mac(const char *dev, uint8_t mac[6]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    if (fd < 0) 
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);

    return 0;
}

uint16_t cal_checksum(uint8_t *buf, int len) {
    uint32_t sum = 0;

    for (int i = 0; i+1< len; i+=2) { // len이 짝수일때
        uint16_t word = (buf[i] << 8) + buf[i + 1];
        sum += word;
    }
    if (len & 1) {
        uint16_t word = buf[len - 1] << 8;
        sum += word;
    }

    while (sum >0xffff) {
        sum = (sum &0xffff) + (sum >>16);
    }
    uint16_t checksum = htons((uint16_t)(0xffff- sum));
    return checksum;
}

uint16_t tcp_checksum(ipv4_header *ip, tcp_header *tcp, uint8_t *data, int data_len) {
    uint8_t temp[0x1000];
    int pos = 0;
    uint16_t tcp_len = htons(sizeof(tcp_header) + data_len);

    memcpy(temp + pos, ip->src_ip, 4);
    pos += 4;
    memcpy(temp + pos, ip->dst_ip, 4);
    pos += 4;

    temp[pos] =0;
    pos++;
    temp[pos] = IP_TCP;
    pos++;

    memcpy(temp + pos, &tcp_len, 2);
    pos += 2;
    memcpy(temp + pos, tcp, sizeof(tcp_header));
    pos += sizeof(tcp_header);

    if (data_len > 0) {
        memcpy(temp + pos, data, data_len);
        pos += data_len;
    }
    uint16_t checksum = cal_checksum(temp, pos);
    return checksum;
}

int parse_tls_sni(uint8_t *data, int data_len, char *sni, int sni_size) {
    if (data_len <9) {
        return 0;
    }

    // TLS record header
    if (data[0] != 0x16) {
        return 0;
    }

    int tls_record_len = ntohs(*(uint16_t *)(data + 3));
    int tls_record_end = 5 + tls_record_len;

    if (tls_record_end > data_len) {
        return 0;
    }

    int handshake_pos = 5;
    uint8_t handshake_type = data[handshake_pos];
    int handshake_len = (int)(*(data + handshake_pos + 1)<<16 | *(data + handshake_pos + 2)<<8 | *(data + handshake_pos +3));

    if (handshake_type != 0x01) {
        return 0;
    }

    int p = handshake_pos + 4;
    int handshake_end = p + handshake_len;

    if (handshake_end > tls_record_end) {
        return 0;
    }

    if (p + 2 + 32 + 1 > handshake_end) {
        return 0;
    }
    p += 2;
    p +=32;

    int session_len = data[p];
    p += 1;

    if (p + session_len > handshake_end) {
        return 0;
    }
    p += session_len;

    // cipher check
    if (p + 2 > handshake_end) {
        return 0;
    }

    int cipher_len = ntohs(*(uint16_t *)(data + p));
    p += 2;

    if (p + cipher_len > handshake_end) {
        return 0;
    }
    p += cipher_len;

    // compression check
    if (p + 1 >handshake_end) {
        return 0;
    }

    int comp_len = data[p];
    p += 1;

    if (p + comp_len > handshake_end) {
        return 0;
    }
    p += comp_len;

    // extension check
    if (p + 2> handshake_end) {
        return 0;
    }

    int extention_total_len = ntohs(*(uint16_t *)(data + p));
    p += 2;

    int extention_end = p + extention_total_len;

    if (extention_end > handshake_end) {
        return 0;
    }

    while (p + 4 <= extention_end) {
        int ext_type = ntohs(*(uint16_t *)(data + p));
        int ext_len = ntohs(*(uint16_t *)(data + p +2));
        p += 4;

        if (p + ext_len > extention_end) {
            return 0;
        }

        // snis
        if (ext_type == 0) {
            int q = p;
            int ext_data_end = p + ext_len;

            if (q + 2 > ext_data_end) {
                return 0;
            }

            int list_len = ntohs(*(uint16_t *)(data + q));
            q += 2;

            int list_end = q + list_len;

            if (list_end > ext_data_end) {
                return 0;
            }

            while (q + 3 <=list_end) {
                uint8_t name_type = data[q];
                q += 1;

                int name_len = ntohs(*(uint16_t *)(data + q));
                q +=2;

                if (q + name_len > list_end) {
                    return 0;
                }

                if (name_type == 0) {
                    int copy_len = name_len;

                    if (copy_len >= sni_size) {
                        copy_len =sni_size - 1;
                    }
                    memcpy(sni, data +q, copy_len);
                    sni[copy_len] = 0;
                    return 1;
                }
                q += name_len;
            }
        }

        p += ext_len;
    }

    return 0;
}

int sni_cmp(uint8_t *data, int data_len, const std::string &pattern) {
    char sni[0x100];
    memset(sni, 0, sizeof(sni));
    if (parse_tls_sni(data, data_len, sni, sizeof(sni)) == 0){
        return 0;
    }

    printf("SNI: %s\n", sni);
    if (strcasecmp(sni, pattern.c_str()) ==0) {
        printf("[BLOCK] matched:%s\n", sni);
        return 1;
    }
    return 0;
}

tls_stream *find_stream(block_info *info, ipv4_header *ip, tcp_header *tcp) {
    for (int i = 0; i < MAX_STREAM; i++) {
        if (info->streams[i].use_flag == 0){
            continue;
        }
        if (memcmp(info->streams[i].src_ip, ip->src_ip, 4) !=0){
            continue;
        }
        if (memcmp(info->streams[i].dst_ip, ip->dst_ip, 4) !=0){
            continue;
        }
        if (info->streams[i].src_port !=tcp->src_port){
            continue;
        }
        if (info->streams[i].dst_port !=tcp->dst_port){
            continue;
        }
        return &info->streams[i];
    }
    //no match
    return NULL;
}

tls_stream *make_new_stream(block_info *info, ipv4_header *ip, tcp_header *tcp) {
    for (int i = 0; i < MAX_STREAM; i++) {
        if (info->streams[i].use_flag ==0) {
            //empty slot push
            info->streams[i].use_flag = 1;
            memcpy(info->streams[i].src_ip,ip->src_ip, 4);
            memcpy(info->streams[i].dst_ip, ip->dst_ip, 4);
            info->streams[i].src_port = tcp->src_port;
            info->streams[i].dst_port = tcp->dst_port;

            info->streams[i].data.clear();
            return &info->streams[i];
        }
    }
    return NULL;
}

void send_block(block_info *info, ethernet_header *origin_eth, ipv4_header *origin_ip, tcp_header *origin_tcp, int data_len) {
    uint32_t origin_seq = ntohl(origin_tcp->sequence_num);
    uint32_t origin_ack =ntohl(origin_tcp->ack_num);
    uint32_t next_seq =origin_seq + data_len;

    // forward rst
    uint8_t f_packet[sizeof(ethernet_header) + sizeof(ipv4_header) + sizeof(tcp_header)];
    memset(f_packet, 0, sizeof(f_packet));

    ethernet_header *f_eth = (ethernet_header *)f_packet;
    ipv4_header *f_ip = (ipv4_header *)(f_packet + sizeof(ethernet_header));
    tcp_header *f_tcp = (tcp_header *)(f_packet + sizeof(ethernet_header) + sizeof(ipv4_header));

    memcpy(f_eth->dst_MAC, origin_eth->dst_MAC, 6);
    memcpy(f_eth->src_MAC, info->my_mac, 6);
    f_eth->ethernet_type = htons(ETH_IP);

    f_ip->version_ihl = 0x45;
    f_ip->total_len = htons(sizeof(ipv4_header) +sizeof(tcp_header));
    f_ip->ttl = origin_ip->ttl;
    f_ip->protocol = IP_TCP;

    memcpy(f_ip->src_ip, origin_ip->src_ip, 4);
    memcpy(f_ip->dst_ip, origin_ip->dst_ip,4);
    f_ip->header_checksum = cal_checksum((uint8_t *)f_ip,sizeof(ipv4_header));

    f_tcp->src_port = origin_tcp->src_port;
    f_tcp->dst_port = origin_tcp->dst_port;
    f_tcp->sequence_num = htonl(next_seq);
    f_tcp->ack_num = htonl(origin_ack);
    uint16_t rst_flag = (0x5 <<12);
    rst_flag |=TCP_RST;
    rst_flag |= TCP_ACK;
    f_tcp->dataoffset_reversed_flags = htons(rst_flag);
    f_tcp->checksum = tcp_checksum(f_ip, f_tcp, NULL, 0);

    pcap_sendpacket(info->handle, f_packet, sizeof(f_packet));

    // backward rst
    uint8_t b_packet[sizeof(ipv4_header) + sizeof(tcp_header)];
    memset(b_packet, 0, sizeof(b_packet));

    ipv4_header *b_ip = (ipv4_header *)b_packet;
    tcp_header *b_tcp = (tcp_header *)(b_packet + sizeof(ipv4_header));

    b_ip->version_ihl = 0x45;
    b_ip->total_len = htons(sizeof(ipv4_header) + sizeof(tcp_header));
    b_ip->ttl = 0x80;
    b_ip->protocol = IP_TCP;
    memcpy(b_ip->src_ip, origin_ip->dst_ip, 4);
    memcpy(b_ip->dst_ip, origin_ip->src_ip, 4);
    b_ip->header_checksum = cal_checksum((uint8_t *)b_ip, sizeof(ipv4_header));

    b_tcp->src_port = origin_tcp->dst_port;
    b_tcp->dst_port = origin_tcp->src_port;
    b_tcp->sequence_num = htonl(origin_ack);
    b_tcp->ack_num = htonl(next_seq);
    rst_flag = (0x5 <<12);
    rst_flag |= TCP_RST;
    rst_flag |= TCP_ACK;
    b_tcp->dataoffset_reversed_flags = htons(rst_flag);
    b_tcp->checksum = tcp_checksum(b_ip, b_tcp, NULL, 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    memcpy(&addr.sin_addr.s_addr, origin_ip->src_ip, 4);

    sendto(info->raw_sock, b_packet, sizeof(b_packet), 0, (struct sockaddr *)&addr, sizeof(addr));
}

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    block_info *info = (block_info *)user;
    ethernet_header *eth = (ethernet_header *)packet;

    if (header->caplen < sizeof(ethernet_header) + sizeof(ipv4_header) + sizeof(tcp_header)){
        return; // error check
    }
    if (ntohs(eth->ethernet_type) != ETH_IP){
        return;
    }
    ipv4_header *ip = (ipv4_header*)(packet +sizeof(ethernet_header));
    if (ip->protocol != IP_TCP){
        return;
    }
    
    int ip_len = (ip->version_ihl &0xf)<< 2;
    int ip_total_len = ntohs(ip->total_len);
    tcp_header *tcp = (tcp_header *)(packet + sizeof(ethernet_header) + ip_len);
    int tcp_field = ntohs(tcp->dataoffset_reversed_flags);
    int tcp_len = (tcp_field >>12) <<2;
    int data_len = ip_total_len - ip_len - tcp_len;

    if (data_len <= 0)
        return;

    uint8_t *data = (uint8_t *)tcp + tcp_len;

    tls_stream *stream = find_stream(info, ip, tcp);

    // tls clienthello check and save
    if (data_len >=9 && data[0] == 0x16 && data[5] == 0x01) {
        if (stream == NULL) {
            stream = make_new_stream(info, ip, tcp);
            }
        }

    if (stream == NULL)
        return;

    stream->data.insert(stream->data.end(), data, data + data_len);

    if (sni_cmp(stream->data.data(), (int)stream->data.size(), info->pattern) == 0){
        return;
    }

    send_block(info, eth, ip, tcp, data_len);
}

