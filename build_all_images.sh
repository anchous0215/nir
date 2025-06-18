#!/bin/bash

images["01_sudo_bruteforce"]="sudo-bruteforce"
images["02_grep_password"]="grep-password"
images["03_packet_capture"]="packet-capture"
images["04_chrome_cookie_theft"]="chrome-cookie-theft"
images["05_ssh_bruteforce"]="ssh-bruteforce"
images["06_find_netrc"]="find-netrc"
images["07_compile_c_privileged"]="compile-c-privileged"
images["08_dump_creds_lazagne"]="dump-creds-lazagne"
images["09_pam_injection_emulation"]="pam-injection-emulation"
images["10_privileged_c"]="privileged_c"

for dir in "${!images[@]}"; do
  if [ -d "$dir" ]; then
    IMAGE_NAME="attack-image-${images[$dir]}:latest"
    echo ">>> Building $IMAGE_NAME in $dir..."
    (cd "$dir" && docker build -t "$IMAGE_NAME" .)
    echo ">>> Done building $IMAGE_NAME."
    echo
  fi
done

echo "All images have been built successfully."
