#!/bin/bash

output=$(</dev/stdin)
output=$(echo "$output" | grep -v 0xffffffff)

text=$(echo "$output" | grep -E "0x[a-f0-9]{7}" | tail -1)
lines_text=$(echo "$text" | tr -d ',' | tr -d '{' | tr -d '}')
hex_text=$(echo "$lines_text" | grep -oP "0x[a-f0-9]{7}[a-f0-9]{0,1} " | sed s/0x// | sed s/ff//)
last_byte_text=$(echo "$hex_text" | head -1 | grep -o "...$")
first_byte_regs=$(echo "$hex_text" | head -1 | grep -o "^..")

big_text=$(echo "$hex_text" | tail -1)
little_text=${big_text:4:2}${big_text:2:2}${big_text:0:2}
addr_text="0xffffffff$little_text$last_byte_text"

regs=$(echo "$output" | grep -E "0x[a-f0-9]{7}" | head -1)
lines=$(echo "$regs" | tr -d ',' | tr -d '{' | tr -d '}')
hex=$(echo "$lines" | grep -oP "0x[a-f0-9]{7}[a-f0-9]{0,1} " | sed s/0x//)
last_byte=$(echo "$hex" | head -1 | grep -o "...$")
big=$(echo "$hex" | tail -1)
if (( ${#big} == 8 ))
then
    big="0$big"
fi
little=${big:6:2}${big:4:2}${big:2:2}${big:0:2}
addr="0xffff$first_byte_regs$little$last_byte"

printf "$addr\n"
printf "$addr_text\n"