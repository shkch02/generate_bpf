pipeline {
    agent any

    environment {
        // 1. Harbor 및 이미지 정보
        HARBOR_URL       = "shkch.duckdns.org"
        HARBOR_PROJECT   = "monitor_loader"
        HARBOR_CREDS_ID  = "harbor-creds"
        MONITOR_IMAGE_NAME  = "kafka"
        KUBE_CREDS_ID = "kubeconfig-creds"
        LOADER_DOCKERFILE = "loader.Dockerfile"
        IMAGE_NAME = "monitor_loader"

        // 2. SSH 터널링/K8s 접속 정보를 환경 변수로 이동 (def 제거)
        K8S_USER = "server4"
        SSH_HOST = "sangsu02.iptime.org"
        K8S_TARGET_IP = "192.168.0.10" 
        K8S_PORT = "6443"

        // DaemonSet YAML 파일 이름 정의 (루트 디렉토리에 있다고 가정)
        DAEMONSET_YAML = "monitorloader-daemonset.yaml"
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Define Image Tag') {
            steps {
                script {
                    env.IMAGE_TAG = sh(returnStdout: true, script: 'git rev-parse --short=8 HEAD').trim()
                    echo "Using Image Tag: ${env.IMAGE_TAG}"
                }
            }
        }

        stage('Build & Push Images') {
            steps {
                withCredentials([usernamePassword(credentialsId: env.HARBOR_CREDS_ID, usernameVariable: 'HARBOR_USER', passwordVariable: 'HARBOR_PASS')]) {
                    sh "docker login ${env.HARBOR_URL} -u ${HARBOR_USER} -p '${HARBOR_PASS}'" 
                }

                script{
                    def FULL_IMAGE = "${env.HARBOR_URL}/${env.HARBOR_PROJECT}/${env.IMAGE_NAME}:${env.IMAGE_TAG}"

                    echo "Building monitor_loader Image..."

                    sh "docker build -f ${env.LOADER_DOCKERFILE} -t ${FULL_IMAGE} ."
                    sh "docker push ${FULL_IMAGE}"
                }
            }
        }
    
        // 4단계: Deploy to Kubernetes (Kustomize 제거, sed 적용)
        stage('Deploy to Kubernetes') {
            steps {
                script {
                    def localPort = 8888 
                    def KUBECONFIG_PATH
                    def tunnelPid

                    // 1. SSH 터널 시작과 인증서 주입
                    sshagent(['k8s-master-ssh-key']) {
                        
                        // SSH 터널 백그라운드에서 실행하고 PID를 파일에 저장
                        sh "nohup ssh -o StrictHostKeyChecking=no -N -L ${localPort}:${env.K8S_TARGET_IP}:${env.K8S_PORT} ${env.K8S_USER}@${env.SSH_HOST} > /dev/null 2>&1 & echo \$! > tunnel.pid"
                        
                        tunnelPid = readFile('tunnel.pid').trim()
                        sleep 10 // 터널 활성화 대기

                        // 2. Kubeconfig 임시 수정 및 배포
                        withCredentials([file(credentialsId: env.KUBE_CREDS_ID, variable: 'KUBECONFIG_FILE')]) {
                            
                            sh "sed -i 's|server:.*|server: https://127.0.0.1:${localPort}|g' ${KUBECONFIG_FILE} || true" 
                            KUBECONFIG_PATH = env.KUBECONFIG_FILE
                            
                                                        
                            sh "sed -i 's|image:.*${env.IMAGE_NAME}:.*|image: ${env.HARBOR_URL}/${env.HARBOR_PROJECT}/${env.IMAGE_NAME}:${env.IMAGE_TAG}|g' ${env.DAEMONSET_YAML}"

                            echo "Deploying DaemonSet with image tag: ${env.IMAGE_TAG}"

                            // 3. kubectl apply 실행 (수정된 YAML 파일 사용)
                            sh "KUBECONFIG=${KUBECONFIG_PATH} kubectl apply -f ${env.DAEMONSET_YAML}" 
                            
                            // 4. 강제 롤아웃 재시작
                            sh "KUBECONFIG=${KUBECONFIG_PATH} kubectl rollout restart daemonset monitorloader-daemonset -n default "
                        
                            // 5. 백그라운드 SSH 터널 프로세스 종료
                            sh "kill ${tunnelPid} || true" 
                            sh "rm -f tunnel.pid || true"
                        }
                    }
                }
            }
        }
    }
    
    post {
        always {
            sh "docker logout ${env.HARBOR_URL} || true"
        }
    }
}