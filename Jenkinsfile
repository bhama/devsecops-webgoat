pipeline {
    agent any
    environment {
        DOJO_URL = "http://localhost:8081"
        TARGET_URL = "http://localhost:8000/WebGoat"
        DOJO_API_KEY = credentials('defectdojo-api-key')
        IMAGE_NAME = "local/webgoat-poc:latest"
        HOST_WORKSPACE = "/var/lib/docker/volumes/jenkins_home/_data/workspace/${JOB_NAME}"
    }
   stages {
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
                    echo "Starting WebGoat for Dynamic Scan..."
                    // Start WebGoat in the background
                    sh "docker run -d --name webgoat-test -p 8082:8080 webgoat/webgoat:latest"
                    
                    // Wait for the app to initialize
                    sleep 30 
                    
                    echo "Running ZAP Baseline Scan..."
                    // We use the ZAP baseline scan to find common web vulnerabilities
                    sh "docker run --rm -v ${HOST_WORKSPACE}:/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://172.17.0.1:8082/WebGoat -J zap_report.json || true"
                    
                    echo "Cleaning up WebGoat container..."
                    sh "docker stop webgoat-test && docker rm webgoat-test"
                }
            }
        }

        stage('Policy Enforcement (OPA)') {
            steps {
                script {
                    echo "Evaluating Security Policy with OPA..."
                    // OPA evaluates the Grype results (SCA)
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
                    echo "Radiating all findings to DefectDojo..."
                    
                    // Upload Semgrep (SAST)
                    sh "curl -X POST '${DOJO_URL}/api/v2/import-scan/' -H 'Authorization: Token ${DOJO_API_KEY}' -F 'scan_type=Semgrep JSON Report' -F 'file=@semgrep.json' -F 'product_name=WebGoat' -F 'engagement_name=DevSecOps POC' -F 'auto_create_context=true'"

                    // Upload Grype (SCA)
                    sh "curl -X POST '${DOJO_URL}/api/v2/import-scan/' -H 'Authorization: Token ${DOJO_API_KEY}' -F 'scan_type=Anchore Grype' -F 'file=@grype.json' -F 'product_name=WebGoat' -F 'engagement_name=DevSecOps POC' -F 'auto_create_context=true'"

                    // Upload ZAP (DAST)
                    sh "curl -X POST '${DOJO_URL}/api/v2/import-scan/' -H 'Authorization: Token ${DOJO_API_KEY}' -F 'scan_type=ZAP Scan' -F 'file=@zap_report.json' -F 'product_name=WebGoat' -F 'engagement_name=DevSecOps POC' -F 'auto_create_context=true'"
                }
            }
        }
    }
}
