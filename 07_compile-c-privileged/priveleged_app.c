#include <stdio.h>
#include <unistd.h>

int main() {
    // getuid() вернет 0, если программа запущена от root
    if (getuid() == 0) {
        printf("[+] SUCCESS: Program is running with root privileges (uid=0)!\n");
    } else {
        printf("[-] FAILURE: Program is running with user privileges (uid=%d).\n", getuid());
    }
    return 0;
}
