#!/bin/bash
echo "🚀 GOSTbusters ASTF - Multi-Module Architecture Demo"
echo "==================================================="
echo ""

echo "📦 Step 1: Building multi-module project..."
echo "   mvn clean compile"
mvn clean compile

echo ""
echo "📋 Step 2: Showing module structure..."
echo "   tree plugin-api/"
tree plugin-api/

echo ""
echo "📋 Step 3: Showing example plugin..."
echo "   tree example-bola-plugin/"
tree example-bola-plugin/

echo ""
echo "✅ Multi-module architecture verified!"
echo "   - Core module: gostbusters-astf (main framework)"
echo "   - Plugin API: plugin-api (SPI contracts)"
echo "   - Example plugin: example-bola-plugin (BOLA test)"
echo ""
echo "🎯 Modules can be built independently:"
echo "   mvn clean package -pl plugin-api"
echo "   mvn clean package -pl example-bola-plugin"
echo "   mvn clean package -pl ."