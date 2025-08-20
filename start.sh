#!/bin/bash

# 명령어 실행 중 오류가 발생하면 즉시 스크립트를 중단합니다.
set -e

sudo docker compose down
sudo docker compose build --no-cache

echo "✅ build completed."


