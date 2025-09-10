#!/bin/bash

# Run from delve
# Start kubeadm cluster with kube-prometheus-stack
# Assumes some once-per-machine setup has been done (some of below may be unnecessary on an already used machine)
set -ex

# Cleanup existing cluster
sudo kubeadm reset --cri-socket unix:///var/run/cri-dockerd.sock

# Start cluster
sudo swapoff -a
sudo systemctl enable --now kubelet
#Use `ip a` to confirm this IP block doesn’t overlap - if need to change IPs, change calico.yaml
sudo kubeadm init --pod-network-cidr=172.16.0.0/16 --control-plane-endpoint orpheus --cri-socket unix:///var/run/cri-dockerd.sock
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
# This fixes some things and breaks others
# echo export KUBECONFIG=/etc/kubernetes/admin.conf | sudo tee -a /root/.bashrc
kubectl taint nodes --all node-role.kubernetes.io/control-plane-
kubectl apply -f prometheus_scan/calico.yaml

# Wait for calico
kubectl get pods -A
exit # rest isn't fully automated, but commands should work

# Cluster checks
SONO_PATH='../sonobuoy'
$SONO_PATH run --wait --mode quick
results=$($SONO_PATH retrieve)
$SONO_PATH results $results
$SONO_PATH delete --wait

# Install kube-prometheus-stack helm chart
helm install kube-prometheus-stack prometheus-community/kube-prometheus-stack
# Wait for k-p-s pods
kubectl get pods -A

# kube-prometheus-stack checks
export GRAFANA_POD=$(kubectl --namespace default get pod -l "app.kubernetes.io/name=grafana,app.kubernetes.io/instance=kube-prometheus-stack" -oname)
kubectl port-forward $GRAFANA_POD 3000
# Grafana: localhost:3000, admin:prom-operator
export PROM_POD=prometheus-kube-prometheus-stack-prometheus-0
kubectl port-forward $PROM_POD 9090
# Prometheus: localhost:9090
