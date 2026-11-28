#!/usr/bin/env bash
set -euo pipefail

# Run from the repository root via mise. Own only this disposable container.
cargo test -p datadeft-magic-link-aws --features aws --test dynamodb_local --no-run
container=$(docker run --rm -d -p 127.0.0.1::8000 amazon/dynamodb-local:3.3.1 \
  -jar DynamoDBLocal.jar -inMemory -sharedDb)
trap 'docker stop "$container" >/dev/null' EXIT
address=$(docker port "$container" 8000/tcp)
export DYNAMODB_LOCAL_ENDPOINT="http://$address"

ready=false
for _ in $(seq 1 60); do
  if curl --silent --output /dev/null --connect-timeout 1 "$DYNAMODB_LOCAL_ENDPOINT"; then
    ready=true
    break
  fi
  sleep 1
done
if [ "$ready" != true ]; then
  printf '%s\n' 'DynamoDB Local did not become ready' >&2
  exit 1
fi
mise -C hex/datadeft_auth run dynamodb-compatibility-test
