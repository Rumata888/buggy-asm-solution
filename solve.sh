#!/bin/bash
docker build -t barretenber-solution .
docker run -t barretenberg-solution sage --python -u mal_client.py slow cryptotraining.zone 1353
