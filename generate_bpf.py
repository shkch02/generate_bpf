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
    bases = get_args()
    #TODO 지금은 list로 받지만, 나중엔 인자 포함된 dict로 받아서 처리할테니 인자를 여기서 처리하고 코드에 넣어줘야할듯
    #get_syscall_info 삭제하고 인자 리스트 넣어주면 될듯
    print("\nGenerating BPF common header...")
    generate_common_event_bpf(bases) #인자 사용하는 버전으로 수정 필요

    print("Generating user-space common header...")
    generate_common_event_user(bases)#인자 사용하는 버전으로 수정 필요

    print("Generating BPF source files...")
    generate_bpf_sources(bases) #인자 사용하는 버전으로 수정 필요

    print("Generating Makefile and Loader source...")
    generate_makefile(bases)
    generate_loader(bases)

    print("\n✅ Generation complete. Run 'make' to build.")


if __name__ == '__main__':
    main()