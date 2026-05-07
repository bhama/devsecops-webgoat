pipeline {
    agent any
    environment {
        DOJO_URL = "http://172.17.0.1:8080"
        TARGET_URL = "http://172.17.0.1:8082/WebGoat"
        DOJO_API_KEY = credentials('defectdojo-api-key')
        LOCAL_IMAGE = "my-local-webgoat:latest"
        
        // This MUST match the path you just chmodded
        HOST_WORKSPACE = "/var/lib/docker/volumes/devsecops-pipeline_jenkins_home/_data/workspace/${JOB_NAME}"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build Java Artifact') {
            steps {
                script {
                    echo "Checking for pom.xml in workspace..."
                    sh "ls -la" // This verifies files exist in Jenkins' view

                    // We mount the ROOT of the workspace to the Maven container
                    sh """
                        docker run --rm \
                        -v ${HOST_WORKSPACE}:/usr/src/mymaven \
                        -w /usr/src/mymaven \
                        maven:3.9-eclipse-temurin-21 \
                        bash -c "ls -la && mvn clean package -DskipTests"
                    """
                }
            }
        }

        stage('Build Local Docker Image') {
            steps {
                script {
                    echo "Building image from host context..."
                    // Pointing Docker to the host path where target/ was just created
                    sh "docker build -t ${LOCAL_IMAGE} ${HOST_WORKSPACE}"
                }
            }
        }

        stage('SAST & SCA') {
            parallel {
                stage('Semgrep') {
                    steps {
                        sh "docker run --rm -v ${HOST_WORKSPACE}:/src returntocorp/semgrep semgrep scan --json --config auto --output semgrep.json || true"
                    }
                }
                stage('Grype') {
                    steps {
                        sh "docker run --rm -v ${HOST_WORKSPACE}:/src anchore/syft:latest /src -o json > sbom.json"
                        sh "docker run --rm -v ${HOST_WORKSPACE}:/src anchore/grype:latest /src/sbom.json -o json > grype.json"
                    }
                }
            }
        }

        stage('DAST (ZAP)') {
            steps {
                script {
                    sh "docker run -d --name webgoat-test -p 8082:8080 ${LOCAL_IMAGE}"
                    sleep 60
                    sh "docker run --rm -v ${HOST_WORKSPACE}:/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t ${TARGET_URL} -J zap_report.json || true"
                    sh "docker stop webgoat-test && docker rm webgoat-test"
                }
            }
        }

        stage('Radiate to Dojo') {
            steps {
                script {
                    def scans = [
                        'Semgrep JSON Report': 'semgrep.json',
                        'Anchore Grype': 'grype.json',
                        'ZAP Scan': 'zap_report.json'
                    ]
                    scans.each { type, file ->
                        sh "curl -X POST '${DOJO_URL}/api/v2/import-scan/' \
                            -H 'Authorization: Token ${DOJO_API_KEY}' \
                            -F 'scan_type=${type}' \
                            -F 'file=@${file}' \
                            -F 'product_name=WebGoat' \
                            -F 'engagement_name=DevSecOps POC' \
                            -F 'auto_create_context=true'"
                    }
                }
            }
        }
    }
}