#!/bin/bash

if [ $# -lt 1 ]; then
    input=""
else
    input="$1"
fi
input="${input}XXXXXXXXXXXXXXXXXXXXXXX"
declare -a version=(0 0 0 0)
initial_version=$(IFS='.'; echo "${version[*]}")
hash=$(echo -n "$initial_version" | md5sum | cut -d' ' -f1)
declare -a hash_bytes
for ((i=0; i<32; i+=2)); do
    hex_byte="${hash:$i:2}"
    hash_bytes[$((i/2))]=$((16#$hex_byte))
done

char_val=$(printf "%d" "'${input:0:1}")
if [ $((char_val ^ 0x56)) -eq ${hash_bytes[3]} ]; then
    version[0]=$((version[0] + 1))
fi

char_val=$(printf "%d" "'${input:5:1}")
if [ $((char_val ^ 0x7)) -eq ${hash_bytes[7]} ]; then
    version[1]=$((version[1] + 1))
fi

char_val=$(printf "%d" "'${input:12:1}")
if [ $((char_val ^ 0x25)) -eq ${hash_bytes[11]} ]; then
    version[2]=$((version[2] + 1))
fi

char_val=$(printf "%d" "'${input:3:1}")
if [ $((char_val ^ 0xe2)) -eq ${hash_bytes[15]} ]; then
    version[3]=$((version[3] + 1))
fi

char_val=$(printf "%d" "'${input:8:1}")
if [ $((char_val ^ 0x4b)) -eq ${hash_bytes[2]} ]; then
    version[0]=$((version[0] + 1))
fi

char_val=$(printf "%d" "'${input:1:1}")
if [ $((char_val ^ 0xda)) -eq ${hash_bytes[6]} ]; then
    version[1]=$((version[1] + 1))
fi

char_val=$(printf "%d" "'${input:15:1}")
if [ $((char_val ^ 0x42)) -eq ${hash_bytes[10]} ]; then
    version[2]=$((version[2] + 1))
fi

char_val=$(printf "%d" "'${input:7:1}")
if [ $((char_val ^ 0xa6)) -eq ${hash_bytes[14]} ]; then
    version[3]=$((version[3] + 1))
fi

char_val=$(printf "%d" "'${input:4:1}")
if [ $((char_val ^ 0xdc)) -eq ${hash_bytes[1]} ]; then
    version[0]=$((version[0] + 1))
fi

char_val=$(printf "%d" "'${input:11:1}")
if [ $((char_val ^ 0x2e)) -eq ${hash_bytes[5]} ]; then
    version[1]=$((version[1] + 1))
fi

char_val=$(printf "%d" "'${input:18:1}")
if [ $((char_val ^ 0xff)) -eq ${hash_bytes[9]} ]; then
    version[2]=$((version[2] + 1))
fi

char_val=$(printf "%d" "'${input:2:1}")
if [ $((char_val ^ 0xd6)) -eq ${hash_bytes[13]} ]; then
    version[3]=$((version[3] + 1))
fi

char_val=$(printf "%d" "'${input:9:1}")
if [ $((char_val ^ 0xdc)) -eq ${hash_bytes[0]} ]; then
    version[0]=$((version[0] + 1))
fi

char_val=$(printf "%d" "'${input:14:1}")
if [ $((char_val ^ 0xae)) -eq ${hash_bytes[4]} ]; then
    version[1]=$((version[1] + 1))
fi

char_val=$(printf "%d" "'${input:6:1}")
if [ $((char_val ^ 0x5)) -eq ${hash_bytes[8]} ]; then
    version[2]=$((version[2] + 1))
fi

char_val=$(printf "%d" "'${input:13:1}")
if [ $((char_val ^ 0x65)) -eq ${hash_bytes[12]} ]; then
    version[3]=$((version[3] + 1))
fi

char_val=$(printf "%d" "'${input:16:1}")
if [ $((char_val ^ 0xc1)) -eq ${hash_bytes[1]} ]; then
    version[0]=$((version[0] + 1))
fi

char_val=$(printf "%d" "'${input:10:1}")
if [ $((char_val ^ 0x2e)) -eq ${hash_bytes[5]} ]; then
    version[1]=$((version[1] + 1))
fi

char_val=$(printf "%d" "'${input:19:1}")
if [ $((char_val ^ 0xa8)) -eq ${hash_bytes[9]} ]; then
    version[2]=$((version[2] + 1))
fi

char_val=$(printf "%d" "'${input:17:1}")
if [ $((char_val ^ 0xda)) -eq ${hash_bytes[13]} ]; then
    version[3]=$((version[3] + 1))
fi

final_version="${version[0]}.${version[1]}.${version[2]}.${version[3]}"

if [ "${version[0]}" -eq 5 ] && [ "${version[1]}" -eq 5 ] && [ "${version[2]}" -eq 5 ] && [ "${version[3]}" -eq 5 ]; then
    echo "SUCCESS! Flag: FlagY{$1}"
else
    echo "FAILED"
fi
