#!/usr/bin/env bash
# Build the arm64 debian+bind9 image into k3s's containerd namespace.
#
# k3s reads images from the containerd "k8s.io" namespace, NOT the nerdctl
# default namespace, so we must build with --namespace k8s.io or the Pod will
# fail with ImagePullBackOff even though "nerdctl images" shows the image.
set -euo pipefail
cd "$(dirname "$0")"

IMG="dnssync-bind9:latest"
echo ">> Building ${IMG} into containerd namespace k8s.io ..."
nerdctl --namespace k8s.io build -t "${IMG}" -f Dockerfile.bind .
echo ">> Done."
nerdctl --namespace k8s.io images | grep -E "REPOSITORY|dnssync-bind9" || true
