#pragma once

#include <pcap.h>
#include <stdint.h>
#include <string>
#include <vector>
#include "my_struct.h"

#define ETH_IP 0x0800
#define IP_TCP 6

#define TCP_FIN 0x01
#define TCP_RST 0x04
#define TCP_ACK 0x10

#define MAX_TLS_BUF 8192
#define MAX_STREAM 16

typedef struct tls_stream {
    uint8_t use_flag;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    uint16_t src_port;
    uint16_t dst_port;
    std::vector<uint8_t> data; //tls data
} tls_stream;

typedef struct block_info {
    pcap_t *handle;
    int raw_sock;
    uint8_t my_mac[6];
    std::string pattern;
    tls_stream streams[MAX_STREAM]; // 중간에 다른 연결 들어오면 구분이 어려워짐 그래서 배열로 구현
} block_info;

int get_my_mac(const char *dev, uint8_t mac[6]);
uint16_t cal_checksum(uint8_t *buf, int len);

uint16_t tcp_checksum(ipv4_header *ip, tcp_header *tcp, uint8_t *data, int data_len);
int parse_tls_sni(uint8_t *data, int data_len, char *sni, int sni_size);
int sni_cmp(uint8_t *data, int data_len, const std::string &pattern);

tls_stream *find_stream(block_info *info, ipv4_header *ip, tcp_header *tcp);
tls_stream *make_new_stream(block_info *info, ipv4_header *ip, tcp_header *tcp);

void send_block(block_info *info, ethernet_header *org_eth, ipv4_header *org_ip, tcp_header *org_tcp, int data_len);
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);
