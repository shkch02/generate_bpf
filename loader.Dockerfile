FROM ubuntu:22.04

WORKDIR /
# make가 생성한 유저 공간 로더
COPY monitor_loader /monitor_loader 
# make가 생성한 커널 공간 eBPF 프로그램
COPY monitor.bpf.o /monitor.bpf.o 

ENTRYPOINT ["/monitor_loader"]