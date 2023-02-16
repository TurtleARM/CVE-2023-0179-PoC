# Needle (CVE-2023-0179) exploit

This repository contains the exploit for my recently discovered vulnerability in the nftables subsystem that was assigned CVE-2023-0179, affecting all Linux versions from 5.5 to 6.2-rc3, although the exploit was tested on 6.1.6.

The vulnerability details and writeup can be found on [oss-security](https://www.openwall.com/lists/oss-security/2023/01/13/2)

## Building instructions
Just invoke the `make needle` command to generate the corresponding executable.

`libmnl` and `libnftnl` are required for the build to succeed:
```bash
sudo apt-get install libmnl-dev libnftnl-dev
```

## Infoleak

The exploit will enter an unprivileged user and network namespace and add an `nft_payload` expression via the `rule_add_payload` function which, when evaluated, will trigger the stack buffer overflow and overwrite the registers.

The content is then retrieved with the following nft command:

`nft list map netdev mytable myset12`

The output will leak several shuffled addresses relative to kernel data structures, among which we find a kernel instruction address and the regs pointer.

## LPE

The exploit creates a new user account `needle:needle` with UID 0 by abusing the `modprobe_path` variable.

Enjoy root privileges.

## Demo

[![asciicast](https://asciinema.org/a/mVTu420tWy8ocdFY70sWD9VLO.svg)](https://asciinema.org/a/mVTu420tWy8ocdFY70sWD9VLO)

## Credits
- David Bouman's `libnftnl` [implementation](https://github.com/pqlx/CVE-2022-1015) and detailed [blog post](https://blog.dbouman.nl/2022/04/02/How-The-Tables-Have-Turned-CVE-2022-1015-1016/)
