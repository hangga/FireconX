#!/bin/bash
PROJECT="$1"
if [ -z "$PROJECT" ]; then
  echo "Usage: $0 <project-id-or-host>"
  exit 1
fi

hosts=(
  "${PROJECT}"
  "${PROJECT}.firebaseio.com"
  "${PROJECT}.firebaseio.com/.json"
  "${PROJECT}-default-rtdb.firebaseio.com"
  "${PROJECT}-default-rtdb.firebaseio.com/.json"
  "${PROJECT}.default-rtdb.firebaseio.com"
  "${PROJECT}.default-rtdb.firebaseio.com/.json"
  "${PROJECT}.firebasedatabase.app"
  "${PROJECT}.firebasedatabase.app/.json"
)

echo "Trying variants for: $PROJECT"
for h in "${hosts[@]}"; do
  url="$h"
  # add scheme if missing
  if [[ ! "$url" =~ ^https?:// ]]; then
    url="https://$url"
  fi
  # ensure .json for DB endpoints (safe)
  if [[ "$url" != *".json" ]] && ( [[ "$url" == *"firebaseio.com"* ]] || [[ "$url" == *"firebasedatabase.app"* ]] ); then
    testurl="${url}/.json"
  else
    testurl="$url"
  fi

  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$testurl" || echo "ERR")
  echo -e "$testurl -> $status"
done
