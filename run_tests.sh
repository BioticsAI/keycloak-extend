#!/usr/bin/env bash

docker run -d --name keycloak_extend_test -p 8180:8180 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:latest start-dev --http-port 8180
pip install pip --upgrade
pip install -r  requirements.txt
pip install .
pip install pyOpenSSL --upgrade
./wait-for-it.sh localhost:8180 -t 60
coverage run -m pytest -s tests
coverage report -m
coverage xml -o code-coverage.xml