#!/bin/bash

# Скачиваем google/api/annotations.proto для gRPC-Gateway
mkdir -p third_party/google/api
curl -o third_party/google/api/annotations.proto https://raw.githubusercontent.com/googleapis/googleapis/master/google/api/annotations.proto
curl -o third_party/google/api/http.proto https://raw.githubusercontent.com/googleapis/googleapis/master/google/api/http.proto

echo "Proto files downloaded successfully!"

