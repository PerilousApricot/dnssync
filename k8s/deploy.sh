#!/usr/bin/env bash
# Deploy the DNSSync test BIND server to the local Kubernetes cluster.
#
# Uses the public internetsystemsconsortium/bind9 image (pulled from Docker
# Hub by the node) -- no local image build required.
#
#   ./deploy.sh          # apply + wait ready
#   ./deploy.sh down     # tear everything down
set -euo pipefail
cd "$(dirname "$0")"

NS="dnssync-test"

if [ "${1:-up}" = "down" ]; then
  echo ">> Tearing down ${NS} ..."
  kubectl delete namespace "${NS}" --ignore-not-found --wait=true
  echo ">> Done."
  exit 0
fi

# 1. Apply manifests. The bind9 image is pulled from Docker Hub on demand.
kubectl apply -f namespace.yaml
kubectl apply -f bind-config.yaml
kubectl apply -f bind-deployment.yaml
kubectl apply -f bind-service.yaml

# 2. Force a clean Pod start (fresh baseline zone) and wait for readiness.
echo ">> Restarting bind Pod for a clean zone baseline ..."
kubectl -n "${NS}" delete pod -l app=bind --ignore-not-found --wait=false || true
kubectl -n "${NS}" rollout status deployment/bind --timeout=240s

echo ">> BIND is ready."
kubectl -n "${NS}" get pods,svc
echo ""
echo "Service (in-cluster): bind.${NS}.svc.cluster.local:53  (UDP + TCP)"
echo "TSIG key: dnssync-test-key.  (see bind-config.yaml for the secret)"
