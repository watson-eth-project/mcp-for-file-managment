#!/bin/bash


echo "1. Остановка MCP агента..."
pkill -f "node.*index.js"
if [ $? -eq 0 ]; then
    echo "Aгент остановлен"
else
    echo "Агент не был запущен"
fi

echo "2. Остановка сервера foundry-anvil..."
pkill -f "server.py"
if [ $? -eq 0 ]; then
    echo "Сервер foundry-anvil остановлен"
else
    echo "Сервер foundry-anvil не был запущен отдельно"
fi

echo "3. Очистка портов..."
lsof -ti:3050 | xargs kill -9 2>/dev/null || true
lsof -ti:8000 | xargs kill -9 2>/dev/null || true
echo "Порты 3050 и 8000 очищены"
