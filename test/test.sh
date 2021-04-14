#!/usr/bin/env bash

echo 'building...'
make prod

trash() { xxd -u -l 5 -p /dev/urandom; }

: >config.fso
for _ in {0..300}; do
   # add some garbage to config
   alias=$(trash)
   to=$(trash)
   echo "/$alias:$to" >>config.fso
done

# add true record
echo '/hello:http://safin.dev' >>config.fso

printf 'please run `fso` in a separate terminal before testing...'
read -r

echo 'running benchmark...'
hyperfine 'curl -s -o /dev/null http://localhost:3107/hello'
