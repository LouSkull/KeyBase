#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

if ! "$PYTHON" -c "import fastapi, uvicorn, multipart, psycopg, pymysql" >/dev/null 2>&1; then
  echo "Installing server dependencies..."
  "$PYTHON" -m pip install -r requirements.txt
fi

echo "Starting Key Base from config.yml"
"$PYTHON" -m keybase
