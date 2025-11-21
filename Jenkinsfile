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
        K8S_USER = "server4" // 이제 env.K8S_USER로 접근합니다.
        SSH_HOST = "sangsu02.iptime.org"
        K8S_TARGET_IP = "192.168.0.10" 
        K8S_PORT = "6443" // 포트는 문자열로 두어도 무방합니다.
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

                echo "Building monitor_loader Image...for makefile"

                    sh "docker build -f ${env.LOADER_DOCKERFILE} -t ${FULL_IMAGE} ."
                    sh "docker push ${FULL_IMAGE}"
                }
            }
        }
    }


        // 4단계: Deploy to Kubernetes
    stage('Deploy to Kubernetes') {
    steps {
        script {
            def localPort = 8888 
            def KUBECONFIG_PATH // Kubeconfig 경로를 저장할 변수

            // 1. SSH 터널 시작과 인증서 주입을 단일 블록에서 처리
            sshagent(['k8s-master-ssh-key']) {
                
                // SSH 터널 백그라운드에서 실행하고 PID를 파일에 저장
                // **nohup은 sshagent 블록 안에서 실행되어 키를 사용할 수 있습니다.**
                sh "nohup ssh -o StrictHostKeyChecking=no -N -L ${localPort}:${env.K8S_TARGET_IP}:${env.K8S_PORT} ${env.K8S_USER}@${env.SSH_HOST} > /dev/null 2>&1 & echo \$! > tunnel.pid"
                
                def tunnelPid = readFile('tunnel.pid').trim() // PID 파일 읽기
                sleep 10 // 터널 활성화 대기

                // 2. Kubeconfig 임시 수정 및 배포
                withCredentials([file(credentialsId: env.KUBE_CREDS_ID, variable: 'KUBECONFIG_FILE')]) {
                    
                    sh "sed -i 's|server:.*|server: https://127.0.0.1:${localPort}|g' ${KUBECONFIG_FILE} || true" 
                    KUBECONFIG_PATH = env.KUBECONFIG_FILE
                    
                    dir('k8s') {
                        // Kustomize 태그 업데이트가 이 단계에서 정확히 실행됩니다.
                        sh "kustomize edit set image ${env.HARBOR_URL}/${env.HARBOR_PROJECT}/${env.IMAGE_NAME}=${env.HARBOR_URL}/${env.HARBOR_PROJECT}/${env.IMAGE_NAME}:${env.IMAGE_TAG}"

                        sh "kustomize build . > monitorloader-daemonset.yaml"

                        // 3. kubectl apply 실행
                        sh "KUBECONFIG=${KUBECONFIG_PATH} kubectl apply -f monitorloader-daemonset.yaml || true" 
                        
                        // 4. 강제 롤아웃 재시작 (변경 사항 즉시 반영)
                        sh "KUBECONFIG=${KUBECONFIG_PATH} kubectl rollout restart daemonset monitorloader-daemonset -n default || true"
                    }
                
                // 5. 백그라운드 SSH 터널 프로세스 종료 (kill 명령은 sshagent 블록 내부에서 실행 가능)
                sh "kill ${tunnelPid} || true" 
                sh "rm -f tunnel.pid || true"
            }
        }
    }
    
    post {
        always {
            sh "docker logout ${env.HARBOR_URL}"
        }
    }
}