#include <stdio.h>
#include <unistd.h>

int main() {
    printf("[*] Malicious payload executed!\n");
    
    // Проверка привилегий
    if (getuid() == 0) {
        printf("[!] WARNING: Running as root (uid=0)!\n");
        // Здесь могла бы быть реальная вредоносная логика
    } else {
        printf("[*] Running with user privileges (uid=%d)\n", getuid());
    }
    
    // Демонстрационный payload
    printf("[*] Listing sensitive directory:\n");
    system("ls -la /etc/shadow /etc/passwd 2>/dev/null");
    
    return 0;
}
