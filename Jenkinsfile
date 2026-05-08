pipeline {
    agent any
    environment {
        DOJO_URL = "http://172.17.0.1:8080"
        DOJO_API_KEY = credentials('defectdojo-api-key')
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
                    // This creates the target/ folder needed for SCA scanning
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

        stage('SBOM Analysis') {
            steps {
                script {
                    echo "Generating CycloneDX SBOM..."
                    sh "docker run --rm -v ${HOST_WORKSPACE}:/src anchore/syft:latest scan dir:/src -o cyclonedx-json > bom.json"
                    
                    echo "Uploading to Dependency-Track..."
                    // Target the API port 8081 directly for the backend
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

        stage('Radiate D-Track to Dojo') {
            steps {
                script {
                    echo "Fetching findings from Dependency-Track..."
                    sleep 20
                    sh """
                        curl -X GET "http://172.17.0.1:8083/api/v1/finding/project/${DTRACK_PROJECT_UUID}/export" \
                        -H "X-Api-Key: ${DTRACK_API_KEY}" > dtrack_findings.json
                    """
                    
                    echo "Pushing D-Track findings to DefectDojo..."
                    sh """
                        curl -X POST "${DOJO_URL}/api/v2/import-scan/" \
                        -H "Authorization: Token ${DOJO_API_KEY}" \
                        -F "scan_type=Dependency Track Finding Packaging Format (FPF) Export" \                                      
                        -F "file=@dtrack_findings.json" \
                        -F "product_name=WebGoat" \
                        -F "engagement_name=DevSecOps POC" \
                        -F "auto_create_context=true"
                    """
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

        stage('Radiate Remaining to Dojo') {
            steps {
                script {
                    def scans = [
                        'Semgrep JSON Report': 'semgrep.json',
                        'Anchore Grype': 'grype.json'
                    ]

                    scans.each { dojoTypeName, fileName ->
                        if (fileExists(fileName)) {
                            sh "chmod 644 ${fileName} || true"
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