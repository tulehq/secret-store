#!/bin/sh
# Runs IMAGE the way users do and checks it works: the container must pass its
# own health check, have created its seeded secret, and store a secret on its
# volume and serve it back to signed requests.
set -eu

image=${1:?usage: run.sh IMAGE}
name=secret-store-smoke-$$

cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		docker logs "$name" || true
	fi
	docker rm -f "$name" >/dev/null 2>&1 || true
	exit "$status"
}
trap cleanup EXIT

docker run -d --name "$name" -p 127.0.0.1::9010 \
	-e TULE_Auth_AccessKeyID=smoke -e TULE_Auth_SecretAccessKey=smoke \
	-e TULE_Store_Seed='{"smoke/seeded":{"Host":"db.internal"}}' \
	"$image" >/dev/null

# The health check first runs one interval (10s) after start.
health=
for _ in $(seq 60); do
	health=$(docker inspect -f '{{.State.Status}} {{.State.Health.Status}}' "$name")
	case $health in
	"running healthy") break ;;
	running*) sleep 1 ;;
	*) echo "container stopped: $health" >&2; exit 1 ;;
	esac
done
if [ "$health" != "running healthy" ]; then
	echo "container never became healthy: $health" >&2
	exit 1
fi

# The image must not run as root: it holds secret values in its volume.
ids=$(docker exec "$name" id -u):$(docker exec "$name" id -g)
if [ "$ids" != 65532:65532 ]; then
	echo "runs as $ids, want 65532:65532" >&2
	exit 1
fi

addr=$(docker port "$name" 9010/tcp | head -n 1)

# Every call is a signed POST / naming the operation in X-Amz-Target, which is
# what the AWS JSON protocol the SDKs speak looks like on the wire.
sm() {
	target=$1
	shift
	curl -fsS --aws-sigv4 aws:amz:us-east-1:secretsmanager --user smoke:smoke \
		-H "Content-Type: application/x-amz-json-1.1" \
		-H "X-Amz-Target: secretsmanager.$target" \
		--data-binary "$1" "http://$addr/"
}

sm CreateSecret '{"Name":"smoke/created","SecretString":"placeholder"}' >/dev/null

body=$(sm GetSecretValue '{"SecretId":"smoke/created"}')
case $body in
*'"SecretString":"placeholder"'*) ;;
*)
	echo "read back $body, want the stored secret string" >&2
	exit 1
	;;
esac

seeded=$(sm GetSecretValue '{"SecretId":"smoke/seeded"}')
case $seeded in
*'db.internal'*) ;;
*)
	echo "seeded secret read back $seeded" >&2
	exit 1
	;;
esac

echo "smoke test passed: $image"
