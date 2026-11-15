"""Kubernetes integration test: DNSSync against a real BIND server in-cluster.

This is the "real BIND" layer of the test suite. It orchestrates, from the host:

  1. ensures the BIND server (``k8s/``) is deployed in the local cluster -- it
     uses the public ``internetsystemsconsortium/bind9`` image, which the node
     pulls from Docker Hub (no local image build),
  2. restarts the BIND Pod so the zone starts from a clean baseline,
  3. generates a ConfigMap from the *current* ``src/dnssync`` source (so the
     test always exercises the live code) plus the runner and zone fixture,
  4. launches a Job that runs ``tests/k8s/runner.py`` in-cluster -- which drives
     the real ``python -m dnssync`` CLI over the cluster network and verifies
     with independent dnspython queries,
  5. reads the Job logs, asserts every scenario passed, and cleans up the Job.

The BIND Deployment/Service are left running afterwards (they are the reusable
"test DNS BIND server" deliverable). Skips cleanly when no cluster / kubectl is
available.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

import pytest

NS = "dnssync-test"
BIND_SVC = "bind.dnssync-test.svc"
ZONE = "testsync.accre.vu."
BIND_IMG = "internetsystemsconsortium/bind9:9.18"
RUNNER_IMG = "python:3"
JOB_NAME = "dnssync-test"
FILES_CM = "dnssync-test-files"

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
K8S_DIR = os.path.join(PROJECT_ROOT, "k8s")
SRC_PKG = os.path.join(PROJECT_ROOT, "src", "dnssync")
RUNNER_PY = os.path.join(PROJECT_ROOT, "tests", "k8s", "runner.py")
ZONE_FILE = os.path.join(PROJECT_ROOT, "tests", "k8s", "zone-k8s.zone")
NAMED_CONF = os.path.join(K8S_DIR, "bind-config.yaml")


def kubectl(*args, check=True, capture=True):
    cmd = ["kubectl", *args]
    r = subprocess.run(cmd, capture_output=capture, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(args)} failed:\n{r.stderr}")
    return r


def kubectl_json(*args):
    r = kubectl(*args, "-o", "json")
    return json.loads(r.stdout)


def have_kubectl_cluster():
    if not shutil.which("kubectl"):
        return False
    try:
        r = subprocess.run(
            ["kubectl", "cluster-info"], capture_output=True, text=True, timeout=30
        )
        return r.returncode == 0
    except Exception:
        return False


def read_tsig_from_named_conf():
    """Extract (keyname, secret) from the named.conf embedded in bind-config."""
    with open(NAMED_CONF) as f:
        text = f.read()
    m = re.search(r'key\s+([A-Za-z0-9._-]+)\s*{[^}]*secret\s+"([^"]+)"', text, re.S)
    if not m:
        raise RuntimeError("TSIG key/secret not found in k8s/bind-config.yaml")
    return m.group(1), m.group(2)


def ensure_bind_deployed():
    # 1. apply manifests -- the bind9 image is pulled from Docker Hub by the
    #    node on first use (imagePullPolicy: IfNotPresent reuses the cache).
    for mf in ["namespace.yaml", "bind-config.yaml", "bind-deployment.yaml", "bind-service.yaml"]:
        kubectl("apply", "-f", os.path.join(K8S_DIR, mf))
    # 2. restart the Pod for a clean zone baseline
    kubectl("-n", NS, "delete", "pod", "-l", "app=bind", "--ignore-not-found", "--wait=false", check=False)
    # 3. wait for rollout / readiness
    r = kubectl("-n", NS, "rollout", "status", "deployment/bind", "--timeout=240s", check=False)
    if r.returncode != 0:
        pods = kubectl("-n", NS, "get", "pods", "-l", "app=bind", check=False).stdout
        pytest.fail(f"BIND deployment did not become ready:\n{r.stdout}\n{r.stderr}\n{pods}")


def make_files_configmap():
    """Create/replace the ConfigMap holding the live source + runner + zone."""
    tmp = tempfile.mkdtemp(prefix="dnssync-cm-")
    try:
        pkg = os.path.join(tmp, "dnssync")
        os.makedirs(pkg)
        for fn in os.listdir(SRC_PKG):
            if fn.endswith(".py"):          # skip __pycache__ (dir) & non-py
                shutil.copy2(os.path.join(SRC_PKG, fn), os.path.join(pkg, fn))
        kubectl("-n", NS, "delete", "configmap", FILES_CM, "--ignore-not-found", check=False)
        kubectl(
            "-n", NS, "create", "configmap", FILES_CM,
            f"--from-file={pkg}",
            f"--from-file=runner.py={RUNNER_PY}",
            f"--from-file=zone.zone={ZONE_FILE}",
        )
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def render_job(keyname, secret):
    bootstrap = (
        "set -e\n"
        "pip install -q dnspython\n"
        "mkdir -p /app/src/dnssync\n"
        'for f in /cfg/*.py; do\n'
        '  [ "$(basename "$f")" = "runner.py" ] && continue\n'
        '  cp "$f" /app/src/dnssync/\n'
        "done\n"
        "PYTHONPATH=/app/src python /cfg/runner.py\n"
    )
    return f"""apiVersion: batch/v1
kind: Job
metadata:
  name: {JOB_NAME}
  namespace: {NS}
  labels:
    app: dnssync-test
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 600
  template:
    metadata:
      labels:
        app: dnssync-test
    spec:
      restartPolicy: Never
      containers:
        - name: runner
          image: {RUNNER_IMG}
          imagePullPolicy: IfNotPresent
          command: ["sh", "-c", {json.dumps(bootstrap)}]
          env:
            - {{ name: DNSSYNC_BIND_HOST, value: {BIND_SVC} }}
            - {{ name: DNSSYNC_ZONE, value: {ZONE} }}
            - {{ name: DNSSYNC_TSIG_KEY, value: {keyname} }}
            - {{ name: DNSSYNC_TSIG_SECRET, value: {secret} }}
          volumeMounts:
            - {{ name: cfg, mountPath: /cfg }}
      volumes:
        - name: cfg
          configMap:
            name: {FILES_CM}
"""


def wait_job(timeout_s=360):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            s = kubectl_json("-n", NS, "get", "job", JOB_NAME).get("status", {})
        except RuntimeError:
            time.sleep(3)
            continue
        if s.get("succeeded"):
            return "succeeded"
        if s.get("failed"):
            return "failed"
        time.sleep(3)
    return "timeout"


def job_pod_name():
    r = kubectl("-n", NS, "get", "pods", "-l", "job-name=" + JOB_NAME,
                "-o", "jsonpath={.items[0].metadata.name}", check=False)
    return r.stdout.strip()


def job_logs():
    pod = job_pod_name()
    if not pod:
        return "<no pod found for job>"
    r = kubectl("-n", NS, "logs", pod, check=False)
    return r.stdout


def test_dnssync_against_k8s_bind():
    if not have_kubectl_cluster():
        pytest.skip("no reachable Kubernetes cluster (kubectl cluster-info failed)")

    print("\n[K8S] Ensuring BIND server is deployed ...")
    ensure_bind_deployed()

    keyname, secret = read_tsig_from_named_conf()
    print(f"[K8S] TSIG key: {keyname}")

    print("[K8S] Generating files ConfigMap from current source ...")
    make_files_configmap()

    print(f"[K8S] Launching Job {JOB_NAME} ...")
    kubectl("-n", NS, "delete", "job", JOB_NAME, "--ignore-not-found",
            "--wait=false", check=False)
    # apply the rendered Job via stdin
    r = subprocess.run(["kubectl", "apply", "-f", "-"],
                       input=render_job(keyname, secret),
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.fail(f"failed to apply Job:\n{r.stdout}\n{r.stderr}")

    status = wait_job(timeout_s=360)
    logs = job_logs()
    print("\n[K8S] ---- runner logs ----")
    print(logs)
    print("[K8S] ----------------------\n")

    # cleanup the ephemeral Job + files ConfigMap; keep the BIND server running
    kubectl("-n", NS, "delete", "job", JOB_NAME, "--ignore-not-found", check=False)
    kubectl("-n", NS, "delete", "configmap", FILES_CM, "--ignore-not-found", check=False)

    assert status == "succeeded", f"Job did not succeed (status={status})\n{logs}"
    assert "ALL_SCENARIOS_PASSED" in logs, f"runner did not report all-pass\n{logs}"
    assert "SOME_SCENARIOS_FAILED" not in logs


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v", "-s"]))
