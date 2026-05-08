pipeline {
    agent any
    environment {
        DOJO_URL = "http://172.17.0.1:8080"
        TARGET_URL = "http://localhost:8082/WebGoat"
        DOJO_API_KEY = credentials('defectdojo-api-key')
        LOCAL_IMAGE = "my-local-webgoat:latest"
        HOST_WORKSPACE = "/var/lib/docker/volumes/devsecops-pipeline_jenkins_home/_data/workspace/${JOB_NAME}"
        GATE_FAILED = "false" 
        GITHUB_CRED = credentials('github-token')
        DTRACK_API_KEY = "odt_WGazJMXi_p3IdtnEmUgUxdyuICEKLB0wQGx4Xfkl7"
        DTRACK_PROJECT_UUID = "cd588d0a-e8ad-41c2-8822-3da8e9524e0f"
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
                    // Reset permissions to ensure Docker can read the JAR built by the Maven container
                    sh "sudo chown -R jenkins:jenkins target/ || true"
                    sh "docker build -t ${env.LOCAL_IMAGE} ."
                }
            }
        }

        stage('Start WebGoat for Scanning') {
            steps {
                script {
                    sh "docker rm -f webgoat-test || true"
                    sh "docker run -d --name webgoat-test -p 8082:8080 ${env.LOCAL_IMAGE}"
                    echo "Waiting for WebGoat to initialize..."
                    sleep 45 // Increased for heavy Java startup
                }
            }
        }

        stage('SCA & SBOM') {
            steps {
                script {
                    echo "Generating CycloneDX SBOM..."
                    sh "docker run --rm -v ${HOST_WORKSPACE}:/src anchore/syft:latest scan dir:/src --name WebGoat --version 1.0.0 -o cyclonedx-json > bom.json"
                    
                    echo "Uploading to Dependency-Track..."
                    // Note: Targeting API port 8081 directly
                    sh """
                        curl -X POST "http://172.17.0.1:8083/api/v1/bom" \
                        -H "Content-Type: multipart/form-data" \
                        -H "X-Api-Key: ${DTRACK_API_KEY}" \
                        -F "project=${DTRACK_PROJECT_UUID}" \
                        -F "bom=@bom.json"
                    """
                }
            }
        }

        stage('Radiate D-Track to Dojo') {
            steps {
                script {
                    echo "Fetching findings from Dependency-Track..."
                    sh """
                        curl -X GET "http://172.17.0.1:8083/api/v1/finding/project/${DTRACK_PROJECT_UUID}/export" \
                        -H "X-Api-Key: ${DTRACK_API_KEY}" > dtrack_findings.json
                    """
                    
                    echo "Pushing D-Track findings to DefectDojo..."
                    sh """
                        curl -X POST "${DOJO_URL}/api/v2/import-scan/" \
                        -H "Authorization: Token ${DOJO_API_KEY}" \
                        -F "scan_type=Dependency Track Finding Packaging" \
                        -F "file=@dtrack_findings.json" \
                        -F "product_name=WebGoat" \
                        -F "engagement_name=DevSecOps POC" \
                        -F "auto_create_context=true" \
                        -F "push_to_jira=true"
                    """
                }
            }
        }

        stage('SAST & Infrastructure Scan') {
            parallel {
                stage('Semgrep') {
                    steps {
                        sh "docker run --rm -v ${HOST_WORKSPACE}:/src returntocorp/semgrep semgrep scan --json --config auto --output semgrep.json || true"
                    }
                }
                stage('Grype') {
                    steps {
                        sh "docker run --rm -v ${HOST_WORKSPACE}:/src anchore/syft:latest scan dir:/src -o json > sbom.json"
                        sh "docker run --rm -v ${HOST_WORKSPACE}:/src anchore/grype:latest sbom:/src/sbom.json -o json > grype.json"
                    }
                }
            }
        }

        stage('DAST (ZAP)') {
            steps {
                script {
                    sh "touch zap_report.xml && chmod 777 zap_report.xml"
                    echo "Starting DAST Scan on ${env.TARGET_URL}..."
                    sh """
                        docker run --rm --network host \
                        -v ${env.HOST_WORKSPACE}:/zap/wrk/:rw \
                        ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                        -t ${env.TARGET_URL}/ \
                        -r zap_report.xml || true
                    """
                }
            }
        }

        stage('Radiate Remaining to Dojo') {
            steps {
                script {
                    def scans = [
                        'Semgrep JSON Report': 'semgrep.json',
                        'Anchore Grype': 'grype.json',
                        'ZAP XML Scan': 'zap_report.xml' 
                    ]

                    scans.each { dojoTypeName, fileName ->
                        if (fileExists(fileName)) {
                            sh "chmod 644 ${fileName} || true"
                            sh """
                                curl -X POST "${DOJO_URL}/api/v2/import-scan/" \
                                -H "Authorization: Token ${DOJO_API_KEY}" \
                                -H "Content-Type: multipart/form-data" \
                                -F "scan_type=${dojoTypeName}" \
                                -F "file=@${fileName}" \
                                -F "product_name=WebGoat" \
                                -F "engagement_name=DevSecOps POC" \
                                -F "auto_create_context=true" \
                                -F "push_to_jira=true"
                            """
                        }
                    }
                }
            }
        }

        stage('Security Gate') {    
            steps {
                script {
                    def criticalScaStr = sh(
                        script: "docker run --rm -v ${env.HOST_WORKSPACE}:/src alpine sh -c 'apk add --no-cache jq > /dev/null && jq \"[.matches[] | select(.vulnerability.severity == \\\"Critical\\\")] | length\" /src/grype.json'", 
                        returnStdout: true
                    ).trim()
                    
                    def highSastStr = sh(
                        script: "docker run --rm -v ${env.HOST_WORKSPACE}:/src alpine sh -c 'apk add --no-cache jq > /dev/null && jq \"[.results[] | select(.extra.severity == \\\"ERROR\\\")] | length\" /src/semgrep.json'", 
                        returnStdout: true
                    ).trim()

                    if (criticalScaStr.toInteger() > 0 || highSastStr.toInteger() > 0) {
                        env.GATE_FAILED = "true"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Final Enforcement') {
            steps {
                script {
                    if (env.GATE_FAILED == "true") {
                        error "Security Gate Violation: Critical Vulnerabilities Detected."
                    }
                }
            }
        }
    }
    
    post {
        always {
            script {
                def ghState = (currentBuild.result == 'SUCCESS') ? 'SUCCESS' : 'FAILURE'
                def ghMessage = (env.GATE_FAILED == "true") ? 
                                'Security Gate Violation: Critical Vulnerabilities Found' : 
                                "Build ${currentBuild.result}"

                step([$class: 'GitHubCommitStatusSetter',
                    reposSource: [$class: "ManuallyEnteredRepositorySource", url: "https://github.com/bhama/devsecops-webgoat"],
                    commitShaSource: [$class: "BuildDataRevisionShaSource"],
                    contextSource: [$class: 'ManuallyEnteredCommitContextSource', context: 'Security-Gate/Jenkins'],
                    statusResultSource: [
                        $class: 'ConditionalStatusResultSource',
                        results: [[$class: 'AnyBuildResult', message: ghMessage, state: ghState]]
                    ]
                ])
            }
        }
    }
}