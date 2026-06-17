#!/bin/bash

CONTAINERD_NAMESPACE="k8s.io"
NERDCTL="nerdctl --namespace ${CONTAINERD_NAMESPACE}"

declare -A images
images["attacks/01_sudo-bruteforce"]="sudo-bruteforce"
images["attacks/02_grep-password"]="grep-password"
images["attacks/03_packet-capture"]="packet-capture"
images["attacks/04_chrome-cookie-theft"]="chrome-cookie-theft"
images["attacks/05_ssh-bruteforce"]="ssh-bruteforce"
images["attacks/06_find-netrc"]="find-netrc"
images["attacks/07_compile-c-privileged"]="compile-c-privileged"
images["attacks/08_dump-creds-lazagne"]="dump-creds-lazagne"
images["attacks/09_pam-injection-emulation"]="pam-injection-emulation"
images["attacks/10_privileged_c"]="privileged-c"

for dir in "${!images[@]}"; do
  if [ -d "$dir" ]; then
    IMAGE_NAME="attack-image-${images[$dir]}:latest"
    echo ">>> Building $IMAGE_NAME in $dir..."
    (cd "$dir" && ${NERDCTL} build -t "$IMAGE_NAME" .)
    echo ">>> Done building $IMAGE_NAME."
    echo
  else
    echo "!!! Skipping missing directory: $dir" >&2
  fi
done

echo "All images have been built successfully."
