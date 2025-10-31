# eBPF기반 시스템콜 모니터 생성기

## 1.프로젝트 개요
본 프로젝트는 모니터링하고자 하는 리눅스 시스템 콜 목록을 입력받아 해당 시스템콜을 추적하는
eBPF 프로그램과, 이와 관련된 사용자공간 로더 코드를 자동으로 생성하는 파이썬 스크립트입니다.

특히 컨테이너가 호출하는 시스템콜에 대해 시스템콜 목록과 인자를 추적하여 보안 정책에 활용할 수 있는 로그를 제공하는것을 목적으로 합니다.

libbpf를 기반으로 하며, bpftool을 사용하여 vmlinux.h 헤더에서 BTF정보를 활용합니다

makefile 또한 자동으로 생성되기에  make명령을 통해 간단히 컴파일하여 실행파일을 얻을 수 있습니다 

## 2. 주요 기능
* **코드 자동 생성** : 추적하고자 하는 시스템콜 목록이 담긴 JSON파일을 인자로 입력받아 해당하는 시스템콜 목록을 기반으로 eBPF커널 코드(시스템콜이름.bpf.c)을 자동으로 생성합니다

*  **사용자 공간 로더 생성** : 생성된 eBPF프로그램을 커널에 로드하고 링버퍼를 통해 이벤트를 수신하여 JSON형식으로 출력하는 모니터-로더 코드(monitor_loader.c)를 생성합니다. (현재는 프린트로 찍는 중)

*  **공통 헤더 생성** : 커널과 사용자 공간에서 공유하는 이벤트 구조체 등이 정의된 공통 헤더파일(common_event.h, common_event_user.h)을 생성합니다

*  **makefile** 생성 : 생성된 코드를 컴파일하는 makefile을 생성합니다

# 3. 요구사항
* **운영체제** : Ubuntu 22.04LTS 에서 테스트됨, 타 os에서 시스템콜 인자 혹은 이름 오류발생가능
* **Python** : Python3.x
* **eBPF 개발환경**
  * clang
  * llvm
  * libbpf-dev
  * bpftool
* **커널 헤더** : BTF정보과 활성화된 커널 (/sys/kernel/btf/vmlinux <-해당 파일 필요함)

# 4. 사용 방법
1. JSON형식 시스템콜 목록 준비
```JSON
{
    "open",
    "close",
    "read",
    "write",
    "lseek",
    "mmap"
}
```
[참고] extract_syscalls.py 스크립트를 이용하면 man syscalls를 이용하여 해당 시스템의 모든 시스템콜 목록을 추출할 수 있습니다
2. eBPF 코드 생성
```bash
python3 generate_bpf.py -f syscalls.json
```
실행이 완료되면 다음과 같은 파일이 생성됩니다

* bpf/ : 각 시스템콜 별 .bpf.c 코드 저장
* inlcude/ : 공통헤더
* monitor_loader.c : 사용자 공간로더
* makefile
  
3. make명령어 실행
컴파일 성공하면 monitor_loader 실행파일이 생성됩니다

4. monitor_loader 실행
   ```bash
sudo ./monitor_loader
```
을 통해 실행파일 실행하면 해당 환경에서 컨테이너가 호출하는 특정 시스템콜 목록을 출력합니다
