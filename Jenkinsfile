pipeline {
    agent any
    environment {
        // Use the Bridge IP to reach DefectDojo on the host
        DOJO_URL = "http://172.17.0.1:8080"
        
        // This matches the port we will use in the 'docker run' command below
        TARGET_URL = "http://172.17.0.1:8082/WebGoat"
        
        DOJO_API_KEY = credentials('defectdojo-api-key')
        
        // The name for the image built from YOUR local repository
        LOCAL_IMAGE = "my-local-webgoat:latest"
        
        HOST_WORKSPACE = "/var/lib/docker/volumes/jenkins_home/_data/workspace/${JOB_NAME}"
    }
    
    stages {
        stage('Build Local WebGoat') {
            steps {
                script {
                    echo "Building Docker image from YOUR local repository..."
                    // This builds the image using the Dockerfile in your repo root
                    sh "docker build -t ${LOCAL_IMAGE} ."
                }
            }
        }

        stage('SAST (Semgrep)') {
            steps {
                script {
                    echo "Running SAST..."
                    sh "docker run --rm -v ${HOST_WORKSPACE}:/src returntocorp/semgrep semgrep scan --json --config auto --output semgrep.json || true"
                }
            }
        }

        stage('SCA & SBOM (Syft/Grype)') {
            steps {
                script {
                    echo "Generating SBOM and Scanning..."
                    sh "docker run --rm -v ${HOST_WORKSPACE}:/src anchore/syft:latest /src -o json > sbom.json"
                    sh "docker run --rm -v ${HOST_WORKSPACE}:/src anchore/grype:latest /src/sbom.json -o json > grype.json"
                }
            }
        }

        stage('DAST (OWASP ZAP)') {
            steps {
                script {
                    echo "Starting YOUR local WebGoat for Dynamic Scan..."
                    // Start the image WE JUST BUILT
                    sh "docker run -d --name webgoat-test -p 8082:8080 ${LOCAL_IMAGE}"
                    
                    echo "Waiting 60s for WebGoat to initialize..."
                    sleep 60 
                    
                    echo "Running ZAP Baseline Scan against ${TARGET_URL}..."
                    sh "docker run --rm -v ${HOST_WORKSPACE}:/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t ${TARGET_URL} -J zap_report.json || true"
                    
                    echo "Cleaning up..."
                    sh "docker stop webgoat-test && docker rm webgoat-test"
                }
            }
        }

        stage('Policy Enforcement (OPA)') {
            steps {
                script {
                    echo "Evaluating Security Policy with OPA..."
                    sh "docker run --rm -v ${HOST_WORKSPACE}:/src openpolicyagent/opa exec --decision 'pipeline/allow' --bundle /src/policy/ /src/grype.json > opa_result.json"
                    
                    def opa_output = readJSON file: 'opa_result.json'
                    if (opa_output.result[0].expressions[0].value == false) {
                        error "GATING FAILED: Security policy violation (SCA). Build aborted."
                    }
                }
            }
        }

        stage('Radiate Results (DefectDojo)') {
            steps {
                script {
                    echo "Radiating findings to DefectDojo..."
                    
                    // SAST
                    sh "curl -X POST '${DOJO_URL}/api/v2/import-scan/' -H 'Authorization: Token ${DOJO_API_KEY}' -F 'scan_type=Semgrep JSON Report' -F 'file=@semgrep.json' -F 'product_name=WebGoat' -F 'engagement_name=DevSecOps POC' -F 'auto_create_context=true'"

                    // SCA
                    sh "curl -X POST '${DOJO_URL}/api/v2/import-scan/' -H 'Authorization: Token ${DOJO_API_KEY}' -F 'scan_type=Anchore Grype' -F 'file=@grype.json' -F 'product_name=WebGoat' -F 'engagement_name=DevSecOps POC' -F 'auto_create_context=true'"

                    // DAST
                    sh "curl -X POST '${DOJO_URL}/api/v2/import-scan/' -H 'Authorization: Token ${DOJO_API_KEY}' -F 'scan_type=ZAP Scan' -F 'file=@zap_report.json' -F 'product_name=WebGoat' -F 'engagement_name=DevSecOps POC' -F 'auto_create_context=true'"
                }
            }
        }
    }
}