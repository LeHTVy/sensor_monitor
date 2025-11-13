#!/bin/bash
echo "🔄 Rebuilding Honeypot with Network Monitor fix..."

# Stop current container
echo "⏹️  Stopping container..."
docker-compose down

# Rebuild image
echo "🔨 Building new image..."
docker-compose build --no-cache

# Start container
echo "🚀 Starting container..."
docker-compose up -d

# Wait for startup
echo "⏳ Waiting 10 seconds for services to start..."
sleep 10

# Check logs
echo "📋 Checking logs..."
docker logs honeypot-server | tail -30

echo ""
echo "✅ Done! Check logs above for:"
echo "   ✅ Nginx started"
echo "   ✅ Network Monitor started"
echo "   ✅ Gunicorn started"
echo ""
echo "To follow logs: docker logs -f honeypot-server"
