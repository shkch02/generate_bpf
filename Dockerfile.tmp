FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        llvm \
        libbpf-dev \
        libelf-dev \
        curl \
        git wget \  # wget 추가
    && rm -rf /var/lib/apt/lists/* 

# kubectl 설치
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Kaniko 설치
RUN wget -O /kaniko/executor "https://storage.googleapis.com/kaniko-build-tools/latest/executor" && \
    chmod +x /kaniko/executor

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

COPY build_and_deploy.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/build_and_deploy.sh