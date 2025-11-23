pipeline {
    agent any

    environment {
        // 환경 변수는 단순 문자열로 유지합니다.
        KAFKA_BOOTSTRAP_SERVERS = "192.168.0.8:30719"
    }

    stages {
        stage('Checkout') {
            steps { checkout scm } 
        }

        stage('Deploy eBPF Agent via jump host'){
            steps{
                script { 
                    def NODE_MAP = [
                        'k8s-worker1': [user: 'server1', dir: '/home/server1/2025-1/generate_bpf'],
                        'k8s-worker2': [user: 'server2', dir: '/home/server2/2025-1/generate_bpf'],
                        'k8s-master':  [user: 'server4', dir: '/home/server4/2025-1/generate_bpf']
                    ]
                    
                    def nodes_list = NODE_MAP.keySet()

                    parallel(
                        nodes_list.collectEntries{ node_alias ->
                            ["Deploy to ${node_alias}":{
                                def node_info = NODE_MAP.get(node_alias)
                                def ssh_user = node_info.user
                                def agent_dir = node_info.dir
                                def remote_host_alias = "${ssh_user}@${node_alias}"
                                
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

                                        echo "Starting new monitor_loader on ${node_alias}..."
                                        nohup sudo KAFKA_BOOTSTRAP_SERVERS=${KAFKA_BOOTSTRAP_SERVERS} ./${agent_dir}/monitor_loader > /dev/null 2>&1 &

                                        echo "Deployment to ${node_alias} completed."
                                    """
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