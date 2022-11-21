#!/usr/bin/env bash

pip install pip --upgrade
pip install -r  requirements.txt
pip install .
pip install pyOpenSSL --upgrade
./wait-for-it.sh localhost:8080 -t 60
coverage run -m pytest -s tests
coverage report -m
coverage xml -o code-coverage.xml