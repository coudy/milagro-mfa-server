#!/bin/bash
sudo apt-get update
sudo apt-get install python-dev python-pip libffi-dev
sudo pip install -r requirements/common.txt
python scripts/getCommunityCredentials.py .

