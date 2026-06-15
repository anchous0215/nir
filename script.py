import requests
import time
from datetime import datetime, timedelta
from collections import defaultdict
import pandas as pd
import json

# ==========================
# НАСТРОЙКИ
# ==========================

LOKI_URL = "http://localhost:3100"
NAMESPACE = "study"
TIME_WINDOW_SEC = 3600
FREQ_TIME_WINDOW = 10      # секунд
FREQ_THRESHOLD = 5         # минимум событий
event_history = defaultdict(lambda: defaultdict(list))
PASS_GREP_ATACK = 'T1552.001_Password_Grep_Attack'
SUDO_BRUT_ATTACK = 'Т1110.001_Sudo_Bruteforce_Attack'
SSH_BRUT_ATTACK = 'T1110.004_SSH_Bruteforce'
SAFE_POD = 'do nothing'
SOFT_LOG = 'malicious log'
SOFT_ERROR = 'malicious error'
SOFT_POD_NAME = 'malicious pod name'

# ==========================
# LOGQL: предварительная фильтрация
# ==========================

LOGQL_QUERY = f"""
{{namespace="{NAMESPACE}"}}
| json
|~ "grep|sudo|ssh|tcpdump|pam|sed|find|\\.netrc|git clone|go build|lazagne|gcc"
|~ "password|shadow|/etc|/home|Cookies|chrome|1s,^,|debug|port|/proc|/sys|/tmp"
|~ "denied|authentication failure|failed|error|denied|Invalid user"
"""

# ==========================
# SOFT-ПРИЗНАКИ
# ==========================

SOFT_KEYWORDS = [
    "grep", "password", "passwd", "shadow", "sudo", "ssh",
    "pam", "netrc",  "token", "credential",
    "tcpdump", "lazagne", '/proc', '/sys', '/tmp',
    "denied", 'authentication failure', 'failed' 'error' ,'denied', "Invalid user"
]

SUSPICIOUS_POD_TOKENS = [
    "dump", "privileged", "sniff"
]

SOFT_WEIGHTS = {
    "log": 0.4,
    "pod_name": 0.3,
    "stderr": 0.3,
}


# ==========================
# ЗАПРОС К LOKI
# ==========================

def query_loki():
    end_ns = int(time.time() * 1e9)
    start_ns = end_ns - TIME_WINDOW_SEC * 1_000_000_000

    r = requests.get(
        f"{LOKI_URL}/loki/api/v1/query_range",
        params={
            "query": LOGQL_QUERY,
            "start": start_ns,
            "end": end_ns,
            "limit": 5000
        }
    )
    r.raise_for_status()
    return r.json()

def load_logs_from_file():
    with open("log.json", "r", encoding="utf-8") as f:
        return json.load(f)

# ==========================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ==========================

def contains_all(text, keywords):
    return all(k in text for k in keywords)

def contains_any(text, keywords):
    return any(k in text for k in keywords)

# ==========================
# ПРАВИЛА ДЕТЕКТИРОВАНИЯ АТАК
# ==========================

score = 0.0
errs_conut = 0
logs_count = 0
pod_count = 0

def soft_score(log, pod_name, stream, timestamp):
    log = log.lower()
    pod_name = pod_name.lower()
    global score
    global errs_conut
    global logs_count
    global pod_count
    if any(k in log for k in SOFT_KEYWORDS):
        event_history[pod_name][SOFT_LOG].append(timestamp)

        # очищаем старые события
        window_start = timestamp - timedelta(seconds=FREQ_TIME_WINDOW)
        event_history[pod_name][SOFT_LOG] = [
            t for t in event_history[pod_name][SOFT_LOG] if t >= window_start
        ]

        # проверка частоты
        if len(event_history[pod_name][SOFT_LOG]) >= FREQ_THRESHOLD:
            logs_count+=1
            if logs_count == 5:
                score += SOFT_WEIGHTS["log"]
                logs_count = 0

    if any(k in log for k in SUSPICIOUS_POD_TOKENS) and pod_name == SAFE_POD:
        event_history[pod_name][SOFT_POD_NAME].append(timestamp)

        # очищаем старые события
        window_start = timestamp - timedelta(seconds=FREQ_TIME_WINDOW)
        event_history[pod_name][SOFT_POD_NAME] = [
            t for t in event_history[pod_name][SOFT_POD_NAME] if t >= window_start
        ]

        # проверка высокой частоты
        if len(event_history[pod_name][SOFT_POD_NAME]) >= FREQ_THRESHOLD:
            pod_count+=1
            if pod_count == 3:
                score += SOFT_WEIGHTS["pod_name"]
                pod_count = 0

    if stream == "stderr":
        event_history[pod_name][SOFT_ERROR].append(timestamp)

        # очищаем старые события
        window_start = timestamp - timedelta(seconds=FREQ_TIME_WINDOW)
        event_history[pod_name][SOFT_ERROR] = [
            t for t in event_history[pod_name][SOFT_ERROR] if t >= window_start
        ]

        # проверка высокой частоты
        if len(event_history[pod_name][SOFT_ERROR]) >= FREQ_THRESHOLD:
            errs_conut+=1
            if errs_conut == 10:
                score += SOFT_WEIGHTS["stderr"]
                errs_conut = 0

    return score

def detect_attack(log, pod, stream, timestamp):
    log = log.lower()

    # 1. PAM injection — T1556.003
    if contains_all(log, ["1s,^"]) and contains_any(log, ["pam", "sed"]):
        return "T1556.003_PAM_Modification"

    # 2. .netrc credentials — T1552.001
    if contains_all(log, ["find", ".netrc"]):
        return "T1552.001_Unsecured_Credentials"

    # 3. Chrome cookie theft — T1539
    if contains_all(log, ["whitechocolatemacadamianut"]) and contains_any(log, ["сookies", "chrome"]):
        return "T1539_Cookie_Theft"

    # 4. Password grep
    if contains_all(log, ["grep"]) and contains_any(log, ["password", "passwd", "shadow"]):

        # сохраняем время события
        event_history[pod][PASS_GREP_ATACK].append(timestamp)

        # удаляем старые события
        window_start = timestamp - timedelta(seconds=FREQ_TIME_WINDOW)
        event_history[pod][PASS_GREP_ATACK] = [
            t for t in event_history[pod][PASS_GREP_ATACK] if t >= window_start
        ]

        # проверка высокой частоты
        if len(event_history[pod][PASS_GREP_ATACK]) >= FREQ_THRESHOLD:
            return PASS_GREP_ATACK

    # 5. Sudo bruteforce
    if contains_all(log, ["sudo"]) and contains_any(log, "authentication failure", "incorrect password", "try again", "password incorrect", "sorry"):

            # сохраняем временную метку
            event_history[pod][SUDO_BRUT_ATTACK].append(timestamp)

            # очищаем старые события
            window_start = timestamp - timedelta(seconds=FREQ_TIME_WINDOW)
            event_history[pod][SUDO_BRUT_ATTACK] = [
                t for t in event_history[pod][SUDO_BRUT_ATTACK] if t >= window_start
            ]

            # проверка высокой частоты
            if len(event_history[pod][SUDO_BRUT_ATTACK]) >= FREQ_THRESHOLD:
                return SUDO_BRUT_ATTACK


    # 6. SSH bruteforce
    if contains_all(log, ["ssh"]) and contains_any(log, ["failed password", "invalid user"]):
            # сохраняем временную метку
            event_history[pod][SSH_BRUT_ATTACK].append(timestamp)

            # очищаем старые события
            window_start = timestamp - timedelta(seconds=FREQ_TIME_WINDOW)
            event_history[pod][SSH_BRUT_ATTACK] = [
                t for t in event_history[pod][SSH_BRUT_ATTACK] if t >= window_start
            ]

            # проверка высокой частоты
            if len(event_history[pod][SSH_BRUT_ATTACK]) >= FREQ_THRESHOLD:
                return SSH_BRUT_ATTACK

    # 7. Packet capture
    if (contains_any(log, ["tcpdump"]) and contains_any(log, ["NET_RAW", "NET_ADMIN", "cap_net_raw", "cap_net_admin"])) or (contains_any(log, ["gcc"]) and contains_any(log, ["sudo"])):
        return "T1040_Packet_Capture"

    # 8. Credential dump (LaZagne)
    if contains_all(log, ["lazagne"]) and contains_any(log, ["credential", "password"]):
        return "T1555.003_Credential_Dump"
    
    global score
    if soft_score(log, pod, stream, timestamp) > 0.5:
        score = 0
        return "suspicious activity"

    return None

# ==========================
# АНАЛИЗ ЛОГОВ
# ==========================

def analyze_logs(loki_response):
    records = []

    # Loki → data → result
    for result in loki_response["data"]["result"]:
        for line, ts in result["values"]:
            try:
                # line — это JSON в виде строки
                parsed_line = json.loads(line)

                log_text = parsed_line.get("log", "")
                stream = parsed_line.get("stream", "")
                kube = parsed_line.get("kubernetes", {})

                pod_name = kube.get("pod_name", "unknown")

                timestamp = datetime.fromtimestamp(int(ts) / 1e9)

                attack = detect_attack(log_text, pod_name, stream, timestamp)

                attack = detect_attack(log_text, pod_name, stream, timestamp)

                if attack:
                    push_to_loki(
                        attack=attack,
                        pod=pod_name,
                        log_text=log_text,
                        timestamp=timestamp,
                        severity="critical" if attack != "suspicious activity" else "medium"
                    )

                records.append({
                    "timestamp": timestamp,
                    "pod": pod_name,
                    "stream": stream,
                    "log": log_text,
                    "attack_detected": attack
                })

            except json.JSONDecodeError:
                # на случай битых логов
                continue

    return pd.DataFrame(records)

# ==========================
# ЗАПУСК
# ==========================

def push_to_loki(attack, pod, log_text, timestamp, severity="high"):
    url = f"{LOKI_URL}/loki/api/v1/push"

    payload = {
        "streams": [
            {
                "stream": {
                    "job": "attack-detector",
                    "severity": severity,
                    "attack": attack,
                    "pod": pod
                },
                "values": [
                    [
                        str(int(timestamp.timestamp() * 1e9)),
                        json.dumps({
                            "message": f"Attack detected: {attack}",
                            "pod": pod,
                            "original_log": log_text
                        })
                    ]
                ]
            }
        ]
    }

    headers = {"Content-Type": "application/json"}
    r = requests.post(url, headers=headers, data=json.dumps(payload))
    r.raise_for_status()

if __name__ == "__main__":
    try:
    # Пример кода, вызывающего ошибку
        x = 10 / 0
    except Exception as e:
        # Выводим само сообщение об ошибке
        print(f"Произошла ошибка: {e}")
        # Выводим класс ошибки (например, ZeroDivisionError)
        print(f"Тип ошибки: {type(e).__name__}")

