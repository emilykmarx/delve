#!/bin/bash

# Run from delve
# Start kubeadm cluster with kube-prometheus-stack
# Assumes some once-per-machine setup has been done (some of below may be unnecessary on an already used machine)
set -ex

KUBESRC=/home/emily/go/src/k8s.io/kubernetes

# Build scannable Prometheus image
pushd ../prometheus
# Must match kube-prometheus-stack values.yaml
# prometheus-operator requires tag in format vX.Y.Z, where X is 2 or 3
docker build -f ./Dockerfile -t my/prometheus:v3.5.0 .
popd

# Build scannable k8s scheduler image
pushd $KUBESRC
# Build binary and image (this builds all components - we will only use the scheduler)
make quick-release-images DBG=1
# Load tar into local registry where kubeadm expects to find it
docker load --input _output/release-images/amd64/kube-scheduler.tar
echo 'continue manually starting with docker tag'
# TODO image name after `docker load` has a random string, e.g. registry.k8s.io/kube-scheduler-amd64:v1.31.1-1_3f3c562b1935de-dirty
# (although it sometimes seems to be the same from one build to the next)
exit
docker tag registry.k8s.io/kube-scheduler-amd64:v1.31.1-dirty registry.k8s.io/kube-scheduler:v1.31.1
# Copy in source (unsure how to do this during `make`)
docker build -f build/server-image/kube-scheduler/Dockerfile_wrapper -t registry.k8s.io/kube-scheduler:v1.31.1 .
popd

# Cleanup existing cluster
sudo kubeadm reset --force --skip-phases preflight --cri-socket unix:///var/run/cri-dockerd.sock
# Enable ptrace for dlv
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope

# Start cluster
sudo systemctl enable --now kubelet
#Use `ip a` to confirm this IP block doesn’t overlap - if need to change IPs, change calico.yaml
sudo kubeadm init --config=./prometheus_scan/kubeadm_config.yml
mkdir -p $HOME/.kube
sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
# This fixes some things and breaks others
# echo export KUBECONFIG=/etc/kubernetes/admin.conf | sudo tee -a /root/.bashrc
kubectl taint nodes --all node-role.kubernetes.io/control-plane-
kubectl apply -f prometheus_scan/calico.yaml

# Wait for calico
watch kubectl get pods -A
exit # rest isn't fully automated, but commands should work

# Edit scheduler manifest to prepare for dlv => pod will restart
pushd $KUBESRC/build/server-image/kube-scheduler
sudo cp kube-scheduler.yaml /etc/kubernetes/manifests/
popd

# Cluster checks
SONO_PATH='../sonobuoy'
$SONO_PATH run --wait --mode quick
results=$($SONO_PATH retrieve)
$SONO_PATH results $results
$SONO_PATH delete --wait

# Install kubeshark
helm repo add kubeshark https://helm.kubeshark.co
helm install kubeshark kubeshark/kubeshark
kubectl port-forward service/kubeshark-front 8899:80
# kubeshark: localhost:8899

# Install kube-prometheus-stack helm chart
pushd ../prometheus-helm-charts/charts/kube-prometheus-stack
helm dependency build # only needed once
helm install kube-prometheus-stack .
# Wait for k-p-s pods
watch kubectl get pods -A
popd

# kube-prometheus-stack checks
export GRAFANA_POD=$(kubectl --namespace default get pod -l "app.kubernetes.io/name=grafana,app.kubernetes.io/instance=kube-prometheus-stack" -oname)
kubectl port-forward $GRAFANA_POD 3000
# Grafana: localhost:3000, admin:prom-operator
export PROM_POD=prometheus-kube-prometheus-stack-prometheus-0
kubectl port-forward $PROM_POD 9090
# Prometheus: localhost:9090

# START SCANNING SCHEDULER (bind-address arg to kube-scheduler)
kubectl -n=kube-system exec -it kube-scheduler-orpheus -- bash
dlv exec /usr/local/bin/kube-scheduler -- \
  --authentication-kubeconfig=/etc/kubernetes/scheduler.conf \
  --authorization-kubeconfig=/etc/kubernetes/scheduler.conf \
  --bind-address=127.0.0.1 \
  --kubeconfig=/etc/kubernetes/scheduler.conf \
  --leader-elect=true

# (dlv) config substitute-path /go/src/k8s.io/kubernetes .
