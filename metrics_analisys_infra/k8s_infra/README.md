# Инфраструктура сбора метрик контейнеров (cAdvisor + Prometheus + Grafana)

Набор Kubernetes-манифестов для сбора метрик контейнеров со всех узлов кластера
и предоставления их детектору стадии шифрования атаки программы-вымогателя
(`cipher_detector`, см. `nir3/`). Инфраструктура построена по аналогии с
`log_analisys_infra/k8s_infra` (Loki + Fluent Bit), но вместо логов собирает
**метрики**, и вместо рантайма **docker** использует **containerd**.

Все компоненты разворачиваются в namespace `monitoring` и собирают метрики
контейнеров целевого namespace `study` (тот же объект наблюдения, что и в
log-инфраструктуре).

## Состав инфраструктуры

| Файл | Объекты Kubernetes | Назначение |
|------|--------------------|------------|
| `cadvisor-rbac.yaml` | ServiceAccount `cadvisor`, ClusterRole `cadvisor-read`, ClusterRoleBinding | Права cAdvisor на чтение `nodes`, `nodes/proxy`, `nodes/metrics`, `pods` |
| `cadvisor-ds.yaml` | headless Service `cadvisor`, DaemonSet `cadvisor` | Агент сбора метрик контейнеров на каждом узле (через сокет containerd) |
| `prometheus-rbac.yaml` | ServiceAccount `prometheus`, ClusterRole `prometheus-read`, ClusterRoleBinding | Права Prometheus на service discovery (`nodes`, `services`, `endpoints`, `pods`, `ingresses`) |
| `prometheus-config.yaml` | ConfigMap `prometheus-config` | Конфигурация Prometheus: задания scrape для cAdvisor, фильтрация метрик и namespace |
| `prometheus-grafana.yaml` | Service + StatefulSet `prometheus`, Deployment + Service `grafana`, ConfigMap `grafana-datasources` | Сервер Prometheus (хранилище TSDB) и Grafana (визуализация) |

## Поток данных

```
                    узлы кластера (containerd)
   ┌──────────────────────────────────────────────────────┐
   │  DaemonSet cadvisor  ──/run/containerd/containerd.sock │
   │  (по одному поду на узел, читает метрики контейнеров)   │
   └───────────────────────────┬──────────────────────────┘
                               │ :8080/metrics
                               ▼
           Prometheus (kubernetes_sd_configs role: pod)
           - оставляет только 5 целевых метрик
           - оставляет только namespace=study
                               │ TSDB (retention 7d)
                               ▼
        ┌──────────────────────┴───────────────────────┐
        ▼                                               ▼
  Grafana (NodePort)                       cipher_detector (nir3)
  визуализация                             /api/v1/query_range
                                           http://prometheus:9090
```

## Целевые метрики

Prometheus сохраняет (через `metric_relabel_configs` в `prometheus-config.yaml`)
только метрики, нужные методу детектирования по расстоянию Махаланобиса
(см. `nir3/` и `nir/cipher_detect/cipher_detect_method.md`):

- `container_cpu_usage_seconds_total` — загрузка CPU контейнера;
- `container_fs_usage_bytes` — занятый объём на диске (байты);
- `container_fs_io_current` — текущее число операций ввода-вывода;
- `container_fs_inodes_total` — всего inode у файловой системы;
- `container_fs_inodes_free` — свободные inode (used = total − free).

Из них формируется 4-мерный вектор признаков
`(CPU %, Disk bytes, I/O ops/s, Inodes used)` на скользящем окне 15 минут.

## Особенности containerd (отличия от docker)

Эталонная log-инфраструктура (Fluent Bit) монтирует пути docker
(`/var/lib/docker/containers`). Здесь cAdvisor настроен на containerd:

| Параметр | docker (как было бы) | containerd (как сделано) |
|----------|----------------------|--------------------------|
| Флаг рантайма cAdvisor | `--docker=unix:///var/run/docker.sock` | `--containerd=/run/containerd/containerd.sock` + `--docker=` (пусто, отключено) |
| Корень данных контейнеров | `/var/lib/docker` | `/var/lib/containerd` |
| Сокет рантайма | `/var/run/docker.sock` | `/run/containerd/containerd.sock` (volume `hostPath` с `type: Socket`) |

Остальные монтирования (`/`, `/sys`, `/var/run`, `/dev/disk`) и
`securityContext.privileged: true` остаются стандартными для cAdvisor.

## Развёртывание

Создать namespace и применить манифесты в порядке зависимостей:

```bash
# 1. Namespace (в log-инфраструктуре namespace logging предполагался существующим)
kubectl create namespace monitoring

# 2. RBAC (права доступа должны существовать до подов)
kubectl apply -f cadvisor-rbac.yaml
kubectl apply -f prometheus-rbac.yaml

# 3. Агент сбора метрик на каждом узле
kubectl apply -f cadvisor-ds.yaml

# 4. Конфигурация Prometheus (ConfigMap должен существовать до StatefulSet)
kubectl apply -f prometheus-config.yaml

# 5. Сервер Prometheus и Grafana
kubectl apply -f prometheus-grafana.yaml
```

Проверка состояния:

```bash
kubectl -n monitoring get pods -o wide
kubectl -n monitoring get ds cadvisor
kubectl -n monitoring get svc
```

## Доступ к интерфейсам

```bash
# Prometheus UI (через проброс порта)
kubectl -n monitoring port-forward svc/prometheus 9090:9090
# затем открыть http://localhost:9090/targets — должны быть UP все поды cadvisor

# Grafana опубликована через NodePort
kubectl -n monitoring get svc grafana   # посмотреть назначенный NodePort
# логин по умолчанию admin/admin, источник Prometheus подключён автоматически
```

## Связь с детектором (nir3)

`cipher_detector` обращается к Prometheus по адресу `http://prometheus:9090`
(внутри кластера) через `/api/v1/query_range`:

- подкоманда `profile` строит эталонный профиль (μ, ковариация S, порог D²_max)
  по историческим данным (требуется retention ≥ длины окна обучения; здесь
  `--storage.tsdb.retention.time=7d`);
- подкоманда `detect` на каждом 15-минутном окне вычисляет расстояние
  Махаланобиса D² и сравнивает с порогом, формируя признак атаки F(T) ∈ {0,1}.

## Связь с log-инфраструктурой

Это «зеркальная» по структуре инфраструктура для второго детектора проекта:

| | `log_analisys_infra` | `metrics_analisys_infra` (этот каталог) |
|---|----------------------|------------------------------------------|
| Что собирает | логи контейнеров | метрики контейнеров |
| Коллектор (DaemonSet) | Fluent Bit | cAdvisor |
| Хранилище | Loki | Prometheus (TSDB) |
| Визуализация | Grafana | Grafana |
| Namespace инфраструктуры | `logging` | `monitoring` |
| Целевой namespace | `study` | `study` |
| Детектор | `attack_detector` (χ², `nir2/`) | `cipher_detector` (Махаланобис, `nir3/`) |
