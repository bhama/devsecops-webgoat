pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20', artifactNumToKeepStr: '10'))
    }

    environment {
        DOJO_URL      = "http://172.17.0.1:8080"
        TARGET_URL    = "http://localhost:8082/WebGoat"
        DOJO_API_KEY  = credentials('defectdojo-api-key')
        LOCAL_IMAGE   = "my-local-webgoat:latest"
        HOST_WORKSPACE = "/var/lib/docker/volumes/devsecops-pipeline_jenkins_home/_data/workspace/${JOB_NAME}"
        GATE_FAILED   = "false"
        GITHUB_CRED   = credentials('github-token')
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
                    sleep 30
                }
            }
        }

        stage('SAST & SCA') {
            parallel {
                stage('Semgrep') {
                    steps {
                        script {
                            def semgrepStatus = sh(
                                script: """
                                    docker run --rm \
                                      -v ${HOST_WORKSPACE}:/src \
                                      -w /src \
                                      returntocorp/semgrep \
                                      semgrep scan --json --config auto --output /src/semgrep.json
                                """,
                                returnStatus: true
                            )

                            if (semgrepStatus != 0) {
                                echo "Semgrep exited with code ${semgrepStatus}. Continuing because findings can still be exported."
                            }
                        }
                    }
                }

                stage('Grype') {
                    steps {
                        script {
                            def syftStatus = sh(
                                script: """
                                    docker run --rm \
                                      -v ${HOST_WORKSPACE}:/src \
                                      -w /src \
                                      anchore/syft:latest \
                                      dir:/src -o json > /src/sbom.json
                                """,
                                returnStatus: true
                            )

                            if (syftStatus != 0) {
                                echo "Syft exited with code ${syftStatus}. Continuing."
                            }

                            def grypeStatus = sh(
                                script: """
                                    docker run --rm \
                                      -v ${HOST_WORKSPACE}:/src \
                                      -w /src \
                                      anchore/grype:latest \
                                      sbom:/src/sbom.json -o json > /src/grype.json
                                """,
                                returnStatus: true
                            )

                            if (grypeStatus != 0) {
                                echo "Grype exited with code ${grypeStatus}. Continuing because findings can still be exported."
                            }
                        }
                    }
                }
            }
        }

        stage('DAST (ZAP)') {
            steps {
                script {
                    echo "Starting DAST Scan..."
                    sh """
                docker run --rm --network host \
                  -v ${WORKSPACE}:/zap/wrk/:rw \
                  ghcr.io/zaproxy/zaproxy:stable \
                  zap-baseline.py \
                  -t ${TARGET_URL} \
                  -r zap_report.xml
            """
            sh "ls -l ${WORKSPACE}/zap_report.xml || true"
                }
            }
        }

        stage('Security Gate') {
            steps {
                script {
                    def criticalScaStr = sh(
                        script: """
                            docker run --rm -v ${HOST_WORKSPACE}:/src alpine sh -c '
                              apk add --no-cache jq > /dev/null &&
                              jq "[.matches[] | select(.vulnerability.severity == \\"Critical\\")] | length" /src/grype.json
                            '
                        """,
                        returnStdout: true
                    ).trim()

                    def highSastStr = sh(
                        script: """
                            docker run --rm -v ${HOST_WORKSPACE}:/src alpine sh -c '
                              apk add --no-cache jq > /dev/null &&
                              jq "[.results[] | select(.extra.severity == \\"ERROR\\")] | length" /src/semgrep.json
                            '
                        """,
                        returnStdout: true
                    ).trim()

                    def criticalSca = (criticalScaStr ?: "0").toInteger()
                    def highSast = (highSastStr ?: "0").toInteger()

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
                        'Anchore Grype'      : 'grype.json',
                        'ZAP Scan'           : 'zap_report.xml'
                    ]

                    scans.each { dojoTypeName, fileName ->
                        if (fileExists(fileName)) {
                            echo "✅ Found ${fileName}. Uploading to Dojo as ${dojoTypeName}..."

                            sh "chmod 644 ${fileName} || true"

                            def dojoResponse = sh(
                                script: """
                                    curl --fail --show-error --silent \
                                      -X POST "${DOJO_URL}/api/v2/import-scan/" \
                                      -H "Authorization: Token ${DOJO_API_KEY}" \
                                      -F "scan_type=${dojoTypeName}" \
                                      -F "file=@${fileName}" \
                                      -F "product_name=WebGoat" \
                                      -F "engagement_name=DevSecOps POC" \
                                      -F "auto_create_context=true"
                                """,
                                returnStdout: true
                            ).trim()

                            if (dojoResponse) {
                                echo "DefectDojo response for ${fileName}: ${dojoResponse}"
                            }
                        } else {
                            echo "⚠️ WARNING: ${fileName} not found in workspace. Skipping ${dojoTypeName} upload."
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
                def ghState = (currentBuild.currentResult == 'SUCCESS') ? 'SUCCESS' : 'FAILURE'
                def ghMessage = (env.GATE_FAILED == "true") ?
                    'Security Gate Violation: Critical Vulnerabilities Found' :
                    "Build ${currentBuild.currentResult}"

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

        cleanup {
            script {
                sh "docker rm -f webgoat-test || true"
            }
        }
    }
}