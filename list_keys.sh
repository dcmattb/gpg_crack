#!/bin/bash

#Script / command to list all secret KeyIDs and associated Names/Emails in the gpg keyring
#These can be targeted for password cracking

gpg --list-secret-keys --keyid-format short | awk '
/sec/ && /rsa/ {
    split($2, arr, "/")
    keyid = arr[2]
}
/uid/ && /\[ .*\]/ {
    sub(/^.*\] /, "", $0)
    print " ID: " keyid " Name: " $0
}'
