pipeline {
    agent any
    environment {
        DOJO_URL = "http://172.17.0.1:8080"
        TARGET_URL = "http://172.17.0.1:8082/WebGoat"
        DOJO_API_KEY = credentials('defectdojo-api-key')
        LOCAL_IMAGE = "my-local-webgoat:latest"
        // This MUST match the path on your Debian host
        HOST_WORKSPACE = "/var/lib/docker/volumes/devsecops-pipeline_jenkins_home/_data/workspace/${JOB_NAME}"
        GATE_FAILED = false 
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
                    echo "Compiling WebGoat with JDK 25..."
                    sh """
                        docker run --rm \
                        -v ${HOST_WORKSPACE}:/usr/src/mymaven \
                        -w /usr/src/mymaven \
                        maven:3.9-eclipse-temurin-25 \
                        mvn clean package -DskipTests
                    """
                }
            }
        }

        stage('Build Local Docker Image') {
            steps {
                script {
                    echo "Building Docker image from host path..."
                    // Using . works because Jenkins is already in the workspace root
                    sh "docker build -t ${env.LOCAL_IMAGE} ."
                }
            }
        }

        stage('SAST & SCA') {
            parallel {
                stage('Semgrep') {
                    steps {
                        // We use || true to ensure the pipeline doesn't crash before the Dojo upload
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

        stage('Security Gate') {
            steps {
                script {
                    echo "Evaluating Security Gate Thresholds using Alpine JQ..."
                    
                    // We use alpine:latest and install jq inside it to process the files
                    def criticalSca = sh(
                        script: "docker run --rm -v ${env.HOST_WORKSPACE}:/src alpine sh -c 'apk add --no-cache jq && jq \"[.matches[] | select(.vulnerability.severity == \\\"Critical\\\")] | length\" /src/grype.json'", 
                        returnStdout: true
                    ).trim().toInteger()
                    
                    def highSast = sh(
                        script: "docker run --rm -v ${env.HOST_WORKSPACE}:/src alpine sh -c 'apk add --no-cache jq && jq \"[.results[] | select(.extra.severity == \\\"ERROR\\\")] | length\" /src/semgrep.json'", 
                        returnStdout: true
                    ).trim().toInteger()

                    echo "Gate Results: ${criticalSca} Critical SCA, ${highSast} High SAST"

                    if (criticalSca > 0 || highSast > 0) {
                        echo "❌ SECURITY GATE FAILED: Policy violations detected."
                        env.GATE_FAILED = "true"
                        currentBuild.result = 'UNSTABLE'
                    } else {
                        echo "✅ SECURITY GATE PASSED."
                    }
                }
            }
        }

        stage('Radiate to Dojo') {
            steps {
                script {
                    sh "sudo chmod 644 semgrep.json grype.json zap_report.json || true"

                    // Check if ZAP report has content
                    def zapSize = sh(script: "stat -c %s zap_report.json", returnStdout: true).trim()
                    echo "ZAP Report Size: ${zapSize} bytes"



                    def scans = [
                        'Semgrep JSON Report': 'semgrep.json',
                        'Anchore Grype': 'grype.json',
                        'ZAP Scan': 'zap_report.json'
                    ]
                    scans.each { type, file ->
                        sh """
                            curl -X POST '${env.DOJO_URL}/api/v2/import-scan/' \
                            -H 'Authorization: Token ${env.DOJO_API_KEY}' \
                            -F 'scan_type=${type}' \
                            -F 'file=@${file}' \
                            -F 'product_name=WebGoat' \
                            -F 'engagement_name=DevSecOps POC' \
                            -F 'auto_create_context=true'
                        """
                    }
                }
            }
        }

        stage('Final Enforcement') {
            steps {
                script {
                    if (env.GATE_FAILED == "true") {
                        error "Failing build due to security policy violations. Review results in DefectDojo."
                    }
                }
            }
        }
    }
}