#!/bin/bash
cd "$(dirname "$0")" || exit 1

PY=""
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
fi

if [ -z "$PY" ]; then
  echo ""
  echo "  这台电脑还没装 Python 3，只差这一步就可以用了："
  echo "  打开 https://www.python.org/downloads/ 下载安装，装完后重新双击本文件。"
  echo ""
  read -r -p "按回车关闭…" _
  exit 1
fi

exec "$PY" m87.py
