#!/usr/bin/env bash
# MongoDB integration test: starts a single-node replica set (auth + keyfile) in Docker, creates
# an admin user, runs `caliban-replica/tests/mongo_it.rs` (which seeds data, creates a read-only
# user, and checks introspection, bootstrap, native lane, replica snapshot, lane parity and CDC),
# then removes the container.
#
#   ./scripts/mongo-it.sh                 # mongo:8 on port 27018
#   CALIBAN_MONGO_IMAGE=mongo:7 CALIBAN_MONGO_TEST_PORT=27019 ./scripts/mongo-it.sh
#   KEEP=1 ./scripts/mongo-it.sh          # leave the container running afterwards
set -euo pipefail
cd "$(dirname "$0")/.."

NAME=${CALIBAN_MONGO_CONTAINER:-caliban-mongo-test}
PORT=${CALIBAN_MONGO_TEST_PORT:-27018}
IMAGE=${CALIBAN_MONGO_IMAGE:-mongo:8}
ADMIN_USER=caliban_admin
ADMIN_PW=caliban_admin_pw

cleanup() {
  if [ "${KEEP:-0}" != "1" ]; then docker rm -f "$NAME" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT
docker rm -f "$NAME" >/dev/null 2>&1 || true

echo "==> starting $IMAGE as $NAME on :$PORT (replica set rs0, auth)"
# A replica set with auth needs a keyfile; generate one inside the container.
docker run -d --rm -p "$PORT:27017" --name "$NAME" --entrypoint bash "$IMAGE" -c \
  'head -c 756 /dev/urandom | base64 > /tmp/keyfile && chmod 400 /tmp/keyfile && exec mongod --replSet rs0 --bind_ip_all --keyFile /tmp/keyfile --auth' >/dev/null

mongosh_() { docker exec "$NAME" mongosh --quiet "$@"; }

for _ in $(seq 1 60); do
  mongosh_ --eval 'db.adminCommand({ ping: 1 }).ok' >/dev/null 2>&1 && break
  sleep 1
done

echo "==> rs.initiate + admin user (localhost exception)"
mongosh_ --eval 'rs.initiate({ _id: "rs0", members: [{ _id: 0, host: "localhost:27017" }] })' >/dev/null
for _ in $(seq 1 60); do
  [ "$(mongosh_ --eval 'db.hello().isWritablePrimary' 2>/dev/null || true)" = "true" ] && break
  sleep 1
done
mongosh_ admin --eval "db.createUser({ user: '$ADMIN_USER', pwd: '$ADMIN_PW', roles: ['root'] })" >/dev/null

export CALIBAN_MONGO_TEST_URI="mongodb://$ADMIN_USER:$ADMIN_PW@127.0.0.1:$PORT/?directConnection=true&authSource=admin"
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$PWD/target-mongo}

echo "==> cargo test -p caliban-replica --test mongo_it"
cargo test -p caliban-replica --test mongo_it -- --nocapture
