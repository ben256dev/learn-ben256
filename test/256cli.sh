#!/usr/bin/env bash
# learn-api-cli.sh: CLI wrapper for Learn API endpoints

set -euo pipefail

API_BASE_URL="https://learn.ben256.com/a"

usage() {
  cat <<EOF
Usage: $(basename "$0") <command> [arguments]

Commands:
  register <username> <password> <email>
      Register a new user.

  login <username> <password>
      Login an existing user.

  forgot-password <email>
      Request a password reset link.

  reset-password <token> <newpassword>
      Reset password using the token.

*THIS CLI WAS WRITTEN BY CHATGPT*
EOF
  exit 1
}

# Ensure at least one argument
if [ $# -lt 1 ]; then
  usage
fi

COMMAND="$1"
shift

curl_cmd() {
  # Helper to run curl and pretty-print JSON if jq is available
  local method="$1"; shift
  local endpoint="$1"; shift
  local data="$1"; shift

  if command -v jq >/dev/null 2>&1; then
    curl -s -X "$method" "$API_BASE_URL/$endpoint" \
      -H "Content-Type: application/json" \
      -d "$data" | jq .
  else
    curl -s -X "$method" "$API_BASE_URL/$endpoint" \
      -H "Content-Type: application/json" \
      -d "$data"
  fi
}

case "$COMMAND" in
  register)
    if [ $# -ne 3 ]; then
      usage
    fi
    USERNAME="$1"; PASSWORD="$2"; EMAIL="$3"
    curl_cmd POST register '{"username":"'"$USERNAME"'","password":"'"$PASSWORD"'","email":"'"$EMAIL"'"}'
    ;;

  login)
    if [ $# -ne 2 ]; then
      usage
    fi
    USERNAME="$1"; PASSWORD="$2"
    curl_cmd POST login '{"username":"'"$USERNAME"'","password":"'"$PASSWORD"'"}'
    ;;

  forgot-password)
    if [ $# -ne 1 ]; then
      usage
    fi
    EMAIL="$1"
    curl_cmd POST forgot-password '{"email":"'"$EMAIL"'"}'
    ;;

  reset-password)
    if [ $# -ne 2 ]; then
      usage
    fi
    TOKEN="$1"; NEWPASS="$2"
    curl_cmd POST reset-password '{"token":"'"$TOKEN"'","password":"'"$NEWPASS"'"}'
    ;;

  *)
    usage
    ;;
esac

