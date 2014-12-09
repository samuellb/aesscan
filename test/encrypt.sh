#!/bin/sh

key=4B4559030405060708090A0B0C0D0E0F

iv=495612131415161718191A1B1C1D1E1F
num=1

openssl enc -aes-128-cbc -e -in plaintext-$num.txt -out encrypted-txt-$num.bin -iv $iv -K $key
echo $iv | xxd -ps -r > encrypted-txt-with-iv-$num.bin
cat encrypted-txt-$num.bin >> encrypted-txt-with-iv-$num.bin
