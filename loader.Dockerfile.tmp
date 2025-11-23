# Ubuntu 22.04 기반
FROM ubuntu:22.04

# 대화형 질의 방지 설정
ENV DEBIAN_FRONTEND=noninteractive


# 1. 필수 패키지 설치
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-tools-generic \
    linux-tools-common \
    make \
    gcc \
    git \
    python3 \
    libcap-dev \
    libelf-dev \
    zlib1g-dev \
    librdkafka-dev \
    && rm -rf /var/lib/apt/lists/*

# 2. bpftool 설정 (중요!)
# Ubuntu의 기본 bpftool은 호스트 커널 버전을 체크하는 래퍼이므로,
# 컨테이너 내부의 실제 바이너리를 찾아 /usr/local/bin/bpftool로 연결해줍니다.
RUN ln -sf $(find /usr/lib/linux-tools -name bpftool | head -n 1) /usr/local/bin/bpftool

# 3. 작업 디렉터리 설정
WORKDIR /app

# 4. 소스 코드 복사 (현재 디렉터리의 모든 파일을 컨테이너로 복사)
COPY *.py jsonlist.json vmlinux.h .


# 5. Python 스크립트로 eBPF 소스 및 Makefile 생성
# (syscalls.json 파일이 존재해야 합니다)
RUN python3 generate_bpf.py -f jsonlist.json

# 6. 컨테이너 실행 시 make로 빌드하고 monitor_loader 실행
CMD ["/bin/sh", "-c", "make && ./monitor_loader"]
