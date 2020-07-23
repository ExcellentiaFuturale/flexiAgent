#!/bin/bash

username=$(head -n 1 $1)
password=$(cat $1 | head -2 | tail -1)

url="http://local.vpnflexiwan.com:5000/api/auth/token?username=${username}"

response=$(curl -H "Authorization: Bearer ${password}" --insecure --write-out '%{http_code}' --silent --output /dev/null $url)

if [[ "$response" -ne 200 ]] ; then
  exit 1
else
  exit 0
fi