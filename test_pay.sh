#!/bin/bash
cd tests
python3 -m venv ./venv
source ./venv/bin/activate
pip install -r requirements.txt
pytest -s -v test_pay.py