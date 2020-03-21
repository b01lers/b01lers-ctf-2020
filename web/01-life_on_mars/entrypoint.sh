#!/bin/sh

./init_files/db_create.py
exec /server_files/server.py
