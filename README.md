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

## 3. 요구사항
* **운영체제** : Ubuntu 22.04LTS 에서 테스트됨, 타 os에서 시스템콜 인자 혹은 이름 오류발생가능
* **Python** : Python3.x
* **eBPF 개발환경**
  * clang
  * llvm
  * libbpf-dev
  * bpftool
* **커널 헤더** : BTF정보과 활성화된 커널 (/sys/kernel/btf/vmlinux <-해당 파일 필요함)

## 4. 사용 방법
### 1. JSON형식 시스템콜 목록 준비
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
### 2. eBPF 코드 생성
```bash
python3 generate_bpf.py -f syscalls.json
```
실행이 완료되면 다음과 같은 파일이 생성됩니다

* bpf/ : 각 시스템콜 별 .bpf.c 코드 저장
* inlcude/ : 공통헤더
* monitor_loader.c : 사용자 공간로더
* makefile
  
### 3. make명령어 실행
컴파일 성공하면 monitor_loader 실행파일이 생성됩니다

### 4. monitor_loader 실행
   ```bash
sudo ./monitor_loader
```
을 통해 실행파일 실행하면 해당 환경에서 컨테이너가 호출하는 특정 시스템콜 목록을 출력합니다

### 5. 프로젝트 구조
```
제공해주신 generate_bpf.py, code_generator.py, extract_syscalls.py 파일 내용을 바탕으로 README.md 양식과 초안을 추천해 드립니다.

eBPF 기반 시스템 콜 모니터 생성기 (Syscall Monitor Generator)
1. 프로젝트 개요
본 프로젝트는 모니터링하고자 하는 리눅스 시스템 콜(syscall) 목록을 입력받아, 해당 시스템 콜을 추적하는 eBPF(extended Berkeley Packet Filter) 프로그램과 관련 사용자 공간(user-space) 로더 코드를 자동으로 생성하는 파이썬 스크립트입니다.

libbpf를 기반으로 하며, bpftool을 사용하여 vmlinux.h 헤더에서 BTF(BPF Type Format) 정보를 활용합니다. 생성된 코드는 make 명령어를 통해 간단히 컴파일하고 실행할 수 있습니다.

2. 주요 기능
코드 자동 생성: JSON 파일에 정의된 시스템 콜 목록을 기반으로 eBPF 커널 코드(.bpf.c)를 생성합니다.

사용자 공간 로더 생성: 생성된 eBPF 프로그램을 커널에 로드하고, 링 버퍼(ring buffer)를 통해 이벤트를 수신하여 JSON 형식으로 출력하는 C 코드(monitor_loader.c)를 생성합니다.

공통 헤더 생성: 커널과 사용자 공간에서 공유하는 이벤트 구조체 등이 정의된 공통 헤더 파일(common_event.h, common_event_user.h)을 생성합니다.

Makefile 생성: 생성된 모든 소스 코드를 쉽게 컴파일할 수 있는 Makefile을 자동으로 생성합니다.

3. 요구 사항
운영체제: Ubuntu 22.04 LTS (에서 테스트됨)

Python: Python 3.x

eBPF 개발 환경:

clang

llvm

libbpf-dev (또는 libbpf 소스)

bpftool (커널 BTF 정보 접근)

커널 헤더: BTF 정보가 활성화된 커널 (/sys/kernel/btf/vmlinux 존재 확인)

4. 사용 방법
1단계: 시스템 콜 목록 준비
모니터링할 시스템 콜의 목록을 JSON 배열 형식의 파일로 작성합니다. (예: syscalls.json)

JSON

[
    "open",
    "close",
    "read",
    "write",
    "lseek",
    "mmap"
]
[참고] extract_syscalls.py 스크립트를 사용하여 man syscalls(2) 페이지에서 범용 시스템 콜 목록을 추출할 수 있습니다.

Bash

# man 페이지 내용을 cat으로 출력하여 파이프로 전달
man -P cat syscalls(2) | python3 extract_syscalls.py
2단계: eBPF 코드 생성
generate_bpf.py 스크립트를 실행하여 코드를 생성합니다. -f 옵션으로 1단계에서 준비한 JSON 파일을 지정합니다.

Bash

python3 generate_bpf.py -f syscalls.json
실행이 완료되면 out/ 디렉터리(기본 설정) 내부에 다음과 같은 파일들이 생성됩니다.

out/bpf/: 각 시스템 콜별 .bpf.c 파일

out/include/: 공통 헤더 파일

out/monitor_loader.c: 사용자 공간 로더

out/Makefile: 컴파일용 Makefile

3단계: 컴파일
생성된 out/ 디렉터리로 이동하여 make 명령을 실행합니다.

Bash

cd out
make
컴파일이 성공하면 monitor_loader 실행 파일이 생성됩니다.

4단계: 모니터 실행
sudo 권한으로 monitor_loader를 실행합니다.

Bash

sudo ./monitor_loader
프로그램이 실행되면, 1단계에서 지정한 시스템 콜이 호출될 때마다 해당 이벤트 정보가 터미널에 JSON 형식으로 출력됩니다.

5. 프로젝트 구조
.
├── generate_bpf.py       # (메인) 코드 생성기 실행 스크립트
├── code_generator.py     # (모듈) 실제 C 코드 및 Makefile 생성 로직
├── utils.py              # (모듈) 시스템 콜 정보 파싱 등 유틸리티 함수
├── templates.py          # (모듈) C 코드 및 Makefile 템플릿
├── config.py             # (모듈) 출력 디렉터리 등 설정
├── extract_syscalls.py   # (유틸) man 페이지에서 시스템 콜 목록 추출
├── syscalls.json         # (입력) 사용자가 작성하는 시스템 콜 목록
└── out/                    # (출력) 자동 생성된 소스 코드 및 빌드 결과물
    ├── bpf/
    ├── include/
    ├── monitor_loader.c
    └── Makefile
```
