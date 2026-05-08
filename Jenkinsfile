pipeline {
    agent any
    environment {
        DOJO_URL = "http://172.17.0.1:8080"
        TARGET_URL = "http://localhost:8082/WebGoat" // Changed to localhost for --network host
        DOJO_API_KEY = credentials('defectdojo-api-key')
        LOCAL_IMAGE = "my-local-webgoat:latest"
        HOST_WORKSPACE = "/var/lib/docker/volumes/devsecops-pipeline_jenkins_home/_data/workspace/${JOB_NAME}"
        GATE_FAILED = "false" 
        GITHUB_CRED = credentials('github-token')
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
                    sleep 30 // Increased sleep for Java startup
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
                        sh "docker run --rm -v ${HOST_WORKSPACE}:/src anchore/syft:latest scan dir:/src -o json > sbom.json"
                        sh "docker run --rm -v ${HOST_WORKSPACE}:/src anchore/grype:latest sbom:/src/sbom.json -o json > grype.json"
                    }
                }
            }
        }

        stage('DAST (ZAP)') {
            steps {
                script {
                    // Use --network host to reach port 8082 on the host
                    sh """
                        docker run --rm --network host \
                        -v ${env.HOST_WORKSPACE}:/zap/wrk/:rw \
                        ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
                        -t ${env.TARGET_URL} \
                        -r zap_report.xml
                    """
                }
            }
            post {
                always {
                    sh "docker stop webgoat-test && docker rm webgoat-test || true"
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

                    def criticalSca = criticalScaStr.toInteger()
                    def highSast = highSastStr.toInteger()

                    echo "Gate Results: ${criticalSca} Critical SCA, ${highSast} High SAST"

                    if (criticalSca > 0 || highSast > 0) {
                        env.GATE_FAILED = "true"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Radiate to Dojo') {
            steps {
                script {
                    def scans = [
                        'Semgrep JSON Report': 'semgrep.json',
                        'Anchore Grype': 'grype.json',
                        'ZAP Scan': 'zap_report.xml' // Matched to XML
                    ]

                    scans.each { dojoTypeName, fileName ->
                        if (fileExists(fileName)) {
                            sh "sudo chmod 644 ${fileName} || true"
                            sh """
                                curl -X POST "${DOJO_URL}/api/v2/import-scan/" \
                                -H "Authorization: Token ${DOJO_API_KEY}" \
                                -F "scan_type=${dojoTypeName}" \
                                -F "file=@${fileName}" \
                                -F "product_name=WebGoat" \
                                -F "engagement_name=DevSecOps POC" \
                                -F "auto_create_context=true"
                            """
                        }
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
                // Ensure FAILURE is sent to GitHub if build is UNSTABLE or FAILED
                def ghState = (currentBuild.result == 'SUCCESS') ? 'SUCCESS' : 'FAILURE'
                def ghMessage = (env.GATE_FAILED == "true") ? 
                                'Security Gate Violation: Critical Vulnerabilities Found' : 
                                "Build ${currentBuild.result}"

                step([$class: 'GitHubCommitStatusSetter',
                    reposSource: [$class: "ManuallyEnteredRepositorySource", url: "https://github.com/bhama/devsecops-webgoat"], 
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