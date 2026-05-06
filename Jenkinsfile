pipeline {
    agent any
    environment {
        DOJO_URL = "http://localhost:8081"
        DOJO_API_KEY = credentials('defectdojo-api-key')
        IMAGE_NAME = "local/webgoat-poc:latest"
    }
    stages {
        stage('Static Analysis (Semgrep)') {
            steps {
                // Scan the current directory for code flaws
                sh 'docker run --rm -v $(pwd):/src returntocorp/semgrep semgrep scan --json > semgrep.json || true'
            }
        }

        stage('SCA & SBOM (Syft & Grype)') {
            steps {
                   script {
                        // This is the path on your Debian Host, not the Jenkins container
                        def hostWorkspace = "/var/lib/docker/volumes/jenkins_home/_data/workspace/${JOB_NAME}"

                        // 1. Syft creates the SBOM
                        sh "docker run --rm -v ${hostWorkspace}:/src anchore/syft:latest /src -o json > sbom.json"

                        // 2. Grype scans the generated SBOM
                        // Note: We mount the current workspace to /src so Grype can find 'sbom.json'
                        sh "docker run --rm -v ${hostWorkspace}:/src anchore/grype:latest /src/sbom.json -o json > grype.json"
                    }
            }
        }

        stage('Policy Enforcement (OPA)') {
            steps {
                script {
                        def hostWorkspace = "/var/lib/docker/volumes/jenkins_home/_data/workspace/${JOB_NAME}"

                        // We mount the host workspace to /src so OPA can find /src/policy/ and /src/grype.json
                        sh "docker run --rm -v ${hostWorkspace}:/src openpolicyagent/opa exec --decision 'pipeline/allow' --bundle /src/policy/ /src/grype.json > opa_result.json"                    
                }
            }
        }

        stage('DAST (ZAP Scan)') {
            steps {
                script {
                    // Launch the app container locally to scan it
                    sh "docker run -d --name test-app -p 8088:8080 ${IMAGE_NAME}"
                    // Run ZAP Baseline scan
                    sh 'docker run --rm -v $(pwd):/zap/wrk/:rw owasp/zap2docker-stable zap-baseline.py -t http://localhost:8088/WebGoat -r zap_report.html || true'
                    sh "docker stop test-app && docker rm test-app"
                }
            }
        }

        stage('Reporting') {
            steps {
                // Upload Semgrep results to DefectDojo
                sh """
                curl -X POST "${DOJO_URL}/api/v2/import-scan/" \
                -H "Authorization: Token ${DOJO_API_KEY}" \
                -F "active=true" -F "verified=true" -F "scan_type=Semgrep JSON Report" \
                -F "file=@semgrep.json" -F "engagement=1"
                """
            }
        }
    }
}
