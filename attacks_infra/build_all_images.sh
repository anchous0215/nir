#!/bin/bash

CONTAINERD_NAMESPACE="k8s.io"
NERDCTL="nerdctl --namespace ${CONTAINERD_NAMESPACE}"

declare -A images
images["attacks/01_sudo_bruteforce"]="sudo-bruteforce"
images["attacks/02_grep_password"]="grep-password"
images["attacks/03_packet_capture"]="packet-capture"
images["attacks/04_chrome_cookie_theft"]="chrome-cookie-theft"
images["attacks/05_ssh_bruteforce"]="ssh-bruteforce"
images["attacks/06_find_netrc"]="find-netrc"
images["attacks/07_compile_c_privileged"]="compile-c-privileged"
images["attacks/08_dump_creds_lazagne"]="dump-creds-lazagne"
images["attacks/09_pam_injection_emulation"]="pam-injection-emulation"
images["attacks/10_privileged_c"]="privileged_c"

for dir in "${!images[@]}"; do
  if [ -d "$dir" ]; then
    IMAGE_NAME="attack-image-${images[$dir]}:latest"
    echo ">>> Building $IMAGE_NAME in $dir..."
    (cd "$dir" && ${NERDCTL} build -t "$IMAGE_NAME" .)
    echo ">>> Done building $IMAGE_NAME."
    echo
  fi
done

echo "All images have been built successfully."
