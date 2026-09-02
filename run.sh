#!/bin/bash

echo "🛡️ Enterprise Security Platform"
echo "=================================="

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Run application
echo "🚀 Starting application..."
streamlit run main_app.py --logger.level=error
Make executable:
chmod +x run.sh
