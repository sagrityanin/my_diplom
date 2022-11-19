#!/bin/bash
cd tests
python3 -m venv .
pip install -r requirements.txt
pytest -s -v test_pay.py