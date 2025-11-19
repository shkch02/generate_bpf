#!/usr/bin/env python3
# ubuntu 22.04 LTS에서 실행  

print(r"""
     @@@@@@@@@@     
     @  @@@@@@@             ____  _____  ______                                   _             
 @@@@@@@@@@@@@@====        |  _ \|  __ \|  ____|                                 | |            
@@@@@@@@@@@@@@@=====    ___| |_) | |__) | |__      __ _  ___ _ __   ___ _ __ __ _| |_ ___  _ __ 
@@@@@@@@@@@@@@*=====   / _ \  _ <|  ___/|  __|    / _` |/ _ \ '_ \ / _ \ '__/ _` | __/ _ \| '__|
@@@@@+==============  |  __/ |_) | |    | |      | (_| |  __/ | | |  __/ | | (_| | || (_) | |   
@@@@@===============   \___|____/|_|    |_|       \__, |\___|_| |_|\___|_|  \__,_|\__\___/|_|   
 @@@@=============+                                __/ |                                        
     =======   =                                  |___/                                         
     ==========      
      """)
    
print(" [  eBPF generator running... ]\n")

# --- 다른 모듈에서 필요한 함수들을 가져옵니다 ---
#man 2 syscall 파싱 함수로 대체필요함
from utils import analyze_syscalls_from_list,get_aliases
from extract_syscalls import get_syscalls_from_json, get_args
from code_generator import (
    generate_common_event_bpf,
    generate_common_event_user,
    generate_bpf_sources,
    generate_makefile,
    generate_loader
)


def main():
    #1 입력인자 처리
    bases = get_args()

    # 4. 각 코드/파일 생성 함수 순차 호출 (code_generator.py에 위임)
    print("\nGenerating BPF common header...")
    generate_common_event_bpf(bases)

    print("Generating user-space common header...")
    generate_common_event_user(bases)

    print("Generating BPF source files...")
    generate_bpf_sources(bases)

    print("Generating Makefile and Loader source...")
    generate_makefile(bases)
    generate_loader(bases)
    #모니터로더 static void fprint_json_escaped_str 함수 인코딩 문제인지 암튼 여기 해결해야함

    print("\n✅ Generation complete. Run 'make' to build.")


if __name__ == '__main__':
    main()