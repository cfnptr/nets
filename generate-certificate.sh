#!/bin/bash
openssl req -x509 -nodes -newkey rsa:2048 -sha256 -keyout private-key.pem -out certificate.pem -days 365 -subj "/CN=localhost"
