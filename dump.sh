#!/usr/bin/env bash
# pour avoid local encoding errors
export LC_CTYPE=C

{
  find . -maxdepth 2 -type f | sort | while IFS= read -r file; do
    echo
    echo "=== $file ==="
    case "$file" in
      *.js|*.mjs|*.html|*.css|*.json|*.md)
        sed 's/^/    /' "$file"
        ;;
      *)
        echo "    [ binary or non-text file, skipped ]"
        ;;
    esac
  done
  echo
  echo "=== tree . ==="
  tree .
} > output.txt

