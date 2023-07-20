#!/bin/bash

# Change directory to the specified folder
cd ..

# Stop previously running parachain instance
docker-compose rm -v -s -f interbtc

# Start parachain instance
docker-compose up -d interbtc