#!/bin/bash
set -e

# 1. 파이썬 스크립트 실행 및 바이너리 생성
echo "1. Generating BPF code and compiling C binary..."
# generate_bpf.py 스크립트가 C 코드와 컴파일된 바이너리 파일(예: bpf_runner)을 생성한다고 가정
python generate_bpf.py -f jsonlist.json

make

# 2. 최종 DaemonSet 이미지 빌드 및 푸시 (DinD 환경 또는 Kaniko 사용이 필요)
# **주의: 이 단계는 Job Pod가 Docker 데몬(DinD)에 접근할 수 있도록 설정되거나, Kaniko를 사용하는 Job으로 대체되어야 합니다.**
echo "2. Building final DaemonSet image: ${DOCKER_REGISTRY}/monitor_loader:${IMAGE_TAG}"

# DinD 환경을 가정하고 Docker CLI를 사용합니다.
docker build -f Runner.Dockerfile -t ${DOCKER_REGISTRY}/monitor_loader:${IMAGE_TAG} .
docker push ${DOCKER_REGISTRY}/monitor_loader:${IMAGE_TAG}

# 3. DaemonSet YAML 생성 및 배포
echo "3. Deploying DaemonSet..."
cat <<EOF > daemonset.yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: monitorloader-daemonset
  labels:
    app: bpf-agent
spec:
  selector:
    matchLabels:
      app: bpf-agent
  template:
    metadata:
      labels:
        app: bpf-agent
    spec:
      # Job에서 사용한 ServiceAccount와는 다른, 권한이 최소화된 SA를 사용할 수 있습니다.
      serviceAccountName: bpf-deployer-sa # (선택사항, RBAC 필요 시)
      hostPID: true # eBPF 프로그램을 커널에 로드하기 위해 필요
      containers:
      - name: monitor-loader-container
        image: ${DOCKER_REGISTRY}/monitor_loader:${IMAGE_TAG} # 새로 빌드된 이미지 사용
        securityContext:
          privileged: true # eBPF 로딩을 위해 특권 모드 필요
        volumeMounts:
        - name: lib-modules
          mountPath: /lib/modules
          readOnly: true
      volumes:
      - name: lib-modules
        hostPath:
          path: /lib/modules
EOF

kubectl apply -f daemonset.yaml

echo "Deployment complete. DaemonSet image: ${DOCKER_REGISTRY}/monitor_loader:${IMAGE_TAG}"