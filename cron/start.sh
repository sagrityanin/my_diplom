#!/bin/bash
cd partition
python3 patition_users_logs.py &

cd ../auto_renewal
python3 renewal.py &

cd ../reminder
python3 reminder.py