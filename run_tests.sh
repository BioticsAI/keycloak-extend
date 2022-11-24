#!/usr/bin/env bash

# docker ps
docker run -d --name keycloak -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:latest start-dev
sleep 20
docker ps
docker logs keycloak
pip install pip --upgrade
pip install -r  requirements.txt
pip install .
pip install pyOpenSSL --upgrade
./wait-for-it.sh localhost:8080 -t 60
python -m pytest -s tests
