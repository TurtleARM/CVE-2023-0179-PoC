/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * David Bouman (pql) wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Signed, David.
 * ----------------------------------------------------------------------------
 */

#pragma once
#include <stdint.h>
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define VLAN_HLEN	    4
#define VLAN_ETH_HLEN   18

enum nft_types {
    NFT_TYPE_TABLE = 0,
    NFT_TYPE_CHAIN,
    NFT_TYPE_RULE,
    NFT_TYPE_SET
};

enum mode {
    LEAK_ONLY = 1,
    LEAK_AND_PWN
};

struct unft_base_chain_param {
    uint32_t hook_num;
    uint32_t prio;
};

// build helpers
struct nftnl_table* build_table(char* name, uint16_t family);
struct nftnl_chain* build_chain(char* table_name, char* chain_name, char* dev_name, struct unft_base_chain_param* base_param);
struct nftnl_rule* build_rule(char* table_name, char* chain_name, uint16_t family, uint64_t* handle);
struct nftnl_set* build_set(char *table_name, char *set_name, uint16_t family);

// create helpers (actually commits to the kernel)
int64_t send_batch_request(struct mnl_socket* nl, uint16_t msg, uint16_t msg_flags, uint16_t family, void** object, int* seq, uint64_t (*handler)(struct mnl_socket*, int, int));

int create_table(struct mnl_socket* nl, char* name, uint16_t family, int* seq, uint64_t (*result_handler)(struct mnl_socket*, int, int));
int create_chain(struct mnl_socket* nl, char* chain_name, char* table_name, char* dev_name, uint16_t family, struct unft_base_chain_param* base_param, int* seq, uint64_t (*result_handler)(struct mnl_socket*, int, int));
int create_set(struct mnl_socket* nl, char *table_name, char* name, uint16_t family, int* seq, uint64_t (*result_handler)(struct mnl_socket*, int, int));

// expression helpers
void rule_add_bit_shift(
    struct nftnl_rule* r, uint32_t shift_type, uint32_t bitwise_len,
    uint32_t bitwise_sreg, uint32_t bitwise_dreg, void* data, uint32_t data_len);
void rule_add_memcpy(struct nftnl_rule* r, uint32_t len, uint32_t sreg, uint32_t dreg);
void rule_add_payload(struct nftnl_rule* r, uint32_t base, uint32_t offset, uint32_t len, uint32_t dreg);
void rule_add_cmp(struct nftnl_rule* r, uint32_t op, uint32_t sreg, void* data, size_t data_len);
void add_payload(struct nftnl_rule *r, uint32_t base, uint32_t dreg, uint32_t offset, uint32_t len);
void rule_add_dynset(struct nftnl_rule* r, char *set_name, uint32_t reg_key, uint32_t reg_data);
void rule_add_lookup(struct nftnl_rule* r, char *set_name, uint32_t reg_key, uint32_t reg_data);
void rule_add_immediate_data(struct nftnl_rule* r, uint32_t dreg, void* data, size_t data_len);
void rule_add_immediate_verdict(struct nftnl_rule* r, uint32_t verdict, char* chain_name);

int send_packet();
unsigned long read_from_file(int line);