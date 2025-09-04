#!/bin/bash

# Check if TinyGo is installed
if ! command -v tinygo &> /dev/null; then
    echo "TinyGo is not installed. Please install it from https://tinygo.org/getting-started/install/"
    exit 1
fi

echo "Building plugin with TinyGo..."
go mod tidy
tinygo build -o plugin.wasm -target wasip1 -buildmode=c-shared .

if [ $? -eq 0 ]; then
    echo "Plugin built successfully"
else
    echo "Build failed"
    exit 1
fi
