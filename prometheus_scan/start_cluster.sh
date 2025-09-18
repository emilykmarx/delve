#!/bin/bash

# Run from delve
# Start kubeadm cluster with kube-prometheus-stack
# Assumes some once-per-machine setup has been done (some of below may be unnecessary on an already used machine)
set -ex

# Build scannable Prometheus image
pushd ../prometheus
# Must match kube-prometheus-stack values.yaml
# prometheus-operator requires tag in format vX.Y.Z, where X is 2 or 3
docker build -f ./Dockerfile -t my/prometheus:v3.5.0 .
popd

# Build scannable k8s scheduler image
pushd /home/emily/go/src/k8s.io/kubernetes
# Build binary and image
make quick-release-images DBG=1
# Load tar into local registry where kubeadm expects to find it
docker load --input _output/release-images/amd64/kube-scheduler.tar
docker tag registry.k8s.io/kube-scheduler-amd64:v1.31.1-dirty registry.k8s.io/kube-scheduler:v1.31.1
popd

# Cleanup existing cluster
sudo kubeadm reset --cri-socket unix:///var/run/cri-dockerd.sock

# Start cluster
sudo systemctl enable --now kubelet
#Use `ip a` to confirm this IP block doesn’t overlap - if need to change IPs, change calico.yaml
sudo kubeadm init --config=./prometheus_scan/kubeadm_config.yml
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
# This fixes some things and breaks others
# echo export KUBECONFIG=/etc/kubernetes/admin.conf | sudo tee -a /root/.bashrc
kubectl taint nodes --all node-role.kubernetes.io/control-plane-
kubectl apply -f prometheus_scan/calico.yaml

# Wait for calico
watch kubectl get pods -A
exit # rest isn't fully automated, but commands should work

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
