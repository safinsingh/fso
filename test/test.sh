#!/usr/bin/env bash

echo "building..."
make prod >/dev/null || exit 1

echo "filling up config file..."
: >config.fso

# add some garbage to config
for _ in {0..500}; do
   trash() { xxd -u -l 5 -p /dev/urandom; }

   alias=$(trash)
   to=$(trash)

   echo "$alias:$to" >>config.fso
done

# add true record
echo "hello:http://safin.dev" >>config.fso

printf "please run \`fso\` in a separate terminal before testing... "
read -r

echo "running benchmark..."
ab -n 1000 -c 500 "http://localhost:3107/hello"
