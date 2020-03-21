#!/bin/sh

./init_files/db_create.py
cd /server_files/
exec node server.js
