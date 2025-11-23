pipeline {
    agent any

    // ⚠️ 환경 변수 대신 Groovy 맵을 사용하여 노드별 접속 정보를 정의합니다.
    def NODE_MAP = [
        'k8s-worker1': [user: 'server1', dir: '/home/server1/2025-1/generate_bpf'],
        'k8s-worker2': [user: 'server2', dir: '/home/server2/2025-1/generate_bpf'],
        'k8s-master':  [user: 'server4', dir: '/home/server4/2025-1/generate_bpf']
    ]
    
    // 카프카 정보는 공통 환경 변수로 유지합니다.
    environment {
        KAFKA_BOOTSTRAP_SERVERS = "192.168.0.8:30719"
    }

    stages {
        stage('Checkout') {
            steps { checkout scm } 
        }

        stage('Deploy eBPF Agent via jump host'){
            steps{
                script{
                    // ⚠️ Groovy Map의 키(key)들을 노드 별칭 목록으로 사용합니다.
                    def nodes_list = NODE_MAP.keySet() 

                    parallel(
                        nodes_list.collectEntries{ node_alias ->
                            ["Deploy to ${node_alias}":{
                                // 해당 노드의 접속 정보 (user, dir)를 가져옵니다.
                                def node_info = NODE_MAP.get(node_alias)
                                def ssh_user = node_info.user
                                def agent_dir = node_info.dir
                                def remote_host_alias = "${ssh_user}@${node_alias}" // 예: server1@k8s-worker1
                                
                                withCredentials([sshUserPrivateKey(credentialsId: 'your-ssh-credential-id', keyFileVariable: 'KEY_FILE')]){
                                    def remoteCommands = """
                                        set -e
                                        
                                        echo "Stopping old monitor_loader on ${node_alias} (User: ${ssh_user})..."
                                        sudo pkill monitor_loader || true 

                                        echo "Changing directory to ${agent_dir}..."
                                        cd ${agent_dir}
                                        git pull origin main
                                        
                                        echo "Building agent..."
                                        make clean 
                                        python3 generate_bpf.py -f jsonlist.json
                                        make

                                        echo "Starting new monitor_loader..."
                                        # 명령어 실행 시, 에이전트 경로를 사용하여 실행합니다.
                                        nohup sudo KAFKA_BOOTSTRAP_SERVERS=${KAFKA_BOOTSTRAP_SERVERS} ./${agent_dir}/monitor_loader > /dev/null 2>&1 &

                                        echo "Deployment to ${node_alias} completed."
                                    """

                                    // SSH 접속은 사용자@노드별칭 형태로 실행됩니다.
                                    // 이 때, ~/.ssh/config 파일에 등록된 별칭(k8s-worker1 등)이 사용되어 점프 호스트를 경유합니다.
                                    sh "ssh -o StrictHostKeyChecking=no -i ${KEY_FILE} ${remote_host_alias} ${remoteCommands}"
                                }  
                            }]  
                        }
                    )   
                }       
            }
        }
    } 
}