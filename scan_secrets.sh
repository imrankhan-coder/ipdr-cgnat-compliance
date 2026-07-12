#!/usr/bin/env bash
# scan_secrets.sh — fail if any secret/PII pattern is found in tracked files.
# Run before every commit/push:  ./scan_secrets.sh
set -u
ROOT="${1:-.}"
FAIL=0

# Patterns that must NEVER appear in a public repo.
# (Add your own real values here locally to catch them — but don't commit THIS
#  list with real values; keep the generic patterns for the public version.)
declare -a PATTERNS=(
  # generic credential shapes
  'password\s*=\s*["'"'"'][^"'"'"']{6,}'
  'PGPASSWORD=[A-Za-z0-9]{8,}'
  'gAAAAA[A-Za-z0-9_-]{20,}'            # Fernet ciphertext
  '[A-Za-z0-9_-]{40,}'                  # long tokens (review hits manually)
  # Fernet keys (44-char base64 ending =)
  '[A-Za-z0-9_-]{43}='
  # private keys
  '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
)

echo "== scanning ${ROOT} for secrets =="
for pat in "${PATTERNS[@]}"; do
  hits=$(grep -rnE "$pat" "$ROOT" \
    --include='*.py' --include='*.sql' --include='*.sh' \
    --include='*.html' --include='*.service' --include='*.conf' \
    --include='*.md' --include='*.txt' 2>/dev/null \
    | grep -vE 'CHANGE_ME|example|EXAMPLE|placeholder|scan_secrets\.sh')
  if [ -n "$hits" ]; then
    echo "!! potential secret (pattern: $pat):"
    echo "$hits" | head -10
    echo ""
    FAIL=1
  fi
done

# Network-specific values that identify the origin ISP (sanitize before public).
echo "== scanning for network specifics (sanitize these) =="
NETPAT='103\.115\.196|103\.151\.47|103\.115\.199|157\.20\.14|103\.209\.84|NAS-ELB|CCR-1009|elb\.com\.pk|earthlink|zcom|Earth Link'
nethits=$(grep -rniE "$NETPAT" "$ROOT" \
  --include='*.py' --include='*.sql' --include='*.sh' --include='*.html' \
  --include='*.service' --include='*.conf' --include='*.md' 2>/dev/null \
  | grep -vE 'scan_secrets\.sh')
if [ -n "$nethits" ]; then
  echo "!! network specifics found (replace with placeholders):"
  echo "$nethits" | head -20
  FAIL=1
fi

if [ "$FAIL" -eq 0 ]; then
  echo "== CLEAN: no secrets or network specifics found =="
else
  echo "== FAILED: review and sanitize the hits above before committing =="
fi
exit $FAIL
