pipeline {
    agent any
    environment {
        // Networking: Using host bridge IP for inter-container communication
        DOJO_URL = "http://172.17.0.1:8080"
        TARGET_URL = "http://172.17.0.1:8082/WebGoat"
        
        // Credentials and Image naming
        DOJO_API_KEY = credentials('defectdojo-api-key')
        LOCAL_IMAGE = "devsecops-webgoat:latest"
        
        // HOST Pathing: This is the view from the Debian host's perspective
        // Ensure this matches your 'docker volume inspect' results
        HOST_WORKSPACE = "/var/lib/docker/volumes/devsecops-pipeline_jenkins_home/_data/workspace/${JOB_NAME}"
    }

    stages {
        stage('Checkout') {
            steps {
                // Ensure the repository is pulled into the root of the workspace
                checkout scm
            }
        }

        stage('Build Java Artifact') {
            steps {
                script {
                    echo "Compiling WebGoat with JDK 21+..."
                    def REPO_PATH = "${env.HOST_WORKSPACE}/devsecops-webgoat"
                    
                    // Switching from maven:3.9...-17 to the latest JDK 21 or 25-ea if available
                    sh "docker run --rm -v ${REPO_PATH}:/usr/src/mymaven -w /usr/src/mymaven maven:3.9-eclipse-temurin-21 mvn clean package -DskipTests"
                }
            }
        }

        stage('Build Local Docker Image') {
            steps {
                script {
                    echo "Building Docker image using host-path context: ${env.HOST_WORKSPACE}"
                    // Granting local permissions to ensure Docker daemon can read the new 'target' folder
                    sh "chmod -R 777 ."
                    sh "docker build -t ${LOCAL_IMAGE} ${env.HOST_WORKSPACE}"
                }
            }
        }

        stage('SAST (Semgrep)') {
            steps {
                script {
                    echo "Running SAST on source code..."
                    sh "docker run --rm -v ${HOST_WORKSPACE}:/src returntocorp/semgrep semgrep scan --json --config auto --output semgrep.json || true"
                }
            }
        }

        stage('SCA & SBOM (Syft/Grype)') {
            steps {
                script {
                    echo "Generating SBOM and Scanning for vulnerable dependencies..."
                    sh "docker run --rm -v ${HOST_WORKSPACE}:/src anchore/syft:latest /src -o json > sbom.json"
                    sh "docker run --rm -v ${HOST_WORKSPACE}:/src anchore/grype:latest /src/sbom.json -o json > grype.json"
                }
            }
        }

        stage('DAST (OWASP ZAP)') {
            steps {
                script {
                    echo "Starting local WebGoat container for dynamic testing..."
                    sh "docker run -d --name webgoat-test -p 8082:8080 ${LOCAL_IMAGE}"
                    
                    echo "Waiting 60s for Java/Spring Boot to fully initialize..."
                    sleep 60 
                    
                    echo "Running ZAP Baseline Scan against ${TARGET_URL}..."
                    sh "docker run --rm -v ${HOST_WORKSPACE}:/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t ${TARGET_URL} -J zap_report.json || true"
                    
                    echo "Cleaning up DAST environment..."
                    sh "docker stop webgoat-test && docker rm webgoat-test"
                }
            }
        }

        stage('Policy Enforcement (OPA)') {
            steps {
                script {
                    echo "Evaluating security gate via OPA..."
                    // This assumes you have a /policy folder in your repo with your .rego files
                    sh "docker run --rm -v ${HOST_WORKSPACE}:/src openpolicyagent/opa exec --decision 'pipeline/allow' --bundle /src/policy/ /src/grype.json > opa_result.json"
                    
                    def opa_output = readJSON file: 'opa_result.json'
                    if (opa_output.result[0].expressions[0].value == false) {
                        error "GATING FAILED: Security policy violation detected. Aborting build."
                    }
                }
            }
        }

        stage('Radiate Results (DefectDojo)') {
            steps {
                script {
                    echo "Pushing findings to DefectDojo..."
                    
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

    post {
        always {
            emailext body: "Build Status: ${currentBuild.currentResult}\nDetails: ${env.BUILD_URL}",
                     subject: "DevSecOps Pipeline: ${env.JOB_NAME} [${currentBuild.currentResult}]",
                     to: "admin@yourdomain.com"
        }
    }
}