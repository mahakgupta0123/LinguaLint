#!/bin/bash

# Start backend
cd backend
source venv/bin/activate
python3 app.py &

# Start frontend
cd ../frontend/lingualist
npm run dev
