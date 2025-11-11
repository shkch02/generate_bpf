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
#### 1. JSON형식 시스템콜 목록 준비
```JSON
{
    "open",
    "close",
    "read",
    "write",
    "lseek"
}
```
[참고] extract_syscalls.py 스크립트를 사용하여 man syscalls(2) 페이지에서 범용 시스템 콜 목록을 추출할 수 있습니다.

[참고] [elf파일 받아 호출하는 시스템콜 분석하여 JSON으로 출력하는 프로그램](https://github.com/shkch02/ips_bpf)

#### 2. eBPF 코드 생성
```bash
python3 generate_bpf.py -f syscalls.json
```

실행이 완료되면 실행한 디렉터리 내부에 다음과 같은 파일들이 생성됩니다.

* bpf/: 각 시스템 콜별 .bpf.c 파일

* include/: 공통 헤더 파일

* monitor_loader.c: 사용자 공간 로더

* Makefile

#### 3. make실행
makefile이 존재하는 디렉토리에서 make,

성공하면 monitor_loader 실행파일 생성

#### 4. monitor_loader 실행
```bash
sudo ./monitor_loader
```
으로 모니터 실행하면, 해당 os에서 컨테이너가 실행하는 시스템콜중 1단계에서 입력한 시스템콜 호출시 로그 출력

## 5. 프로젝트 구조
```
.
├── generate_bpf.py       # (메인) 코드 생성기 실행 스크립트
├── code_generator.py     # (모듈) 실제 C 코드 및 Makefile 생성 로직
├── utils.py              # (모듈) 시스템 콜 정보 파싱 등 유틸리티 함수
├── templates.py          # (모듈) C 코드 및 Makefile 템플릿
├── config.py             # (모듈) 출력 디렉터리 등 설정
├── extract_syscalls.py   # (유틸) man 페이지에서 시스템 콜 목록 추출
└── syscalls.json         # (입력) 사용자가 작성하는 시스템 콜 목록
```

## 6. 향후 개선 사항

## 7. 라이센스

## ToDo

#### 룰 엔진에서 buf 인식 제대로 못하는데 어차피 쓸모없는 가상주소인데 걍 버릴까 -> 일단 가지고는 있자 why? 추후 필요한 인자들은 버퍼 읽어올수도 있지만 일단 주소값으로 두고 넘어가


### 커널 syscall 이름과 인자는 외부(웹서버와 yaml)에서 받아오고 여기서는 json토대로 eBPF코드 생성만 담당

man 2 파싱 의존성 아예 없어져야함, 최소한의 자료형 처리 로직은 남겨야할수도(eBPF 생성 로직을 위해)


#### get_aliases, parse_man 같이 메뉴얼에 의존하지말고 glibc 가서 open.c 파싱해보면 실호출하는거 나올거고, 그 실호출함수인 openat.c 가서 인자 뽑으면 되잖아 -> glibc parser로 업무 이관하기위해 파싱관련 의존성 제거 필요


#### proc/kallsyms 도 바꿔 kprobe 안쓰니까. 대신 tracepoint용 진입점 이름은 /sys/kernel/debug/tracing/events/syscalls을 참고해야함 없는 진입점 코드 생성하는 문제있음 마찬가지로 업무 이관, 여기서 고민할 내용 아님

#### (완료) buf 인자 따옴표로 감싸야함(16진수라)
주소값 내용 따오려면 엄청난 리팩토링 필요 better die