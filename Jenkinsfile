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

       /* stage('Radiate D-Track to Dojo') {
    steps {
        script {
            echo "Fetching findings from Dependency-Track..."
            sleep 20

            // 1. Export findings from Dependency-Track
            sh """
                curl -f -s -X GET \
                    "http://172.17.0.1:8083/api/v1/finding/project/${DTRACK_PROJECT_UUID}/export" \
                    -H "X-Api-Key: ${DTRACK_API_KEY}" \
                    -o dtrack_findings.json
            """

            // 2. Validate the file exists, is non-empty, and is valid JSON
            def fileSize = sh(
                script: "stat -c%s dtrack_findings.json 2>/dev/null || echo 0",
                returnStdout: true
            ).trim().toInteger()

            if (fileSize == 0) {
                error "dtrack_findings.json is empty or missing — aborting Dojo upload"
            }

            def isValidJson = sh(
                script: "cat dtrack_findings.json | python3 -c 'import sys,json; json.load(sys.stdin)' 2>/dev/null && echo valid || echo invalid",
                returnStdout: true
            ).trim()

            if (isValidJson != "valid") {
                sh "cat dtrack_findings.json"   // print the bad response for debugging
                error "dtrack_findings.json is not valid JSON — aborting Dojo upload"
            }

            sh "echo 'File size: ${fileSize} bytes — JSON valid, proceeding to upload'"
            sh "cat dtrack_findings.json | head -c 500"   // preview first 500 chars

            // 3. Push findings to DefectDojo
            echo "Pushing D-Track findings to DefectDojo..."
            def dojoResponse = sh(
                script: """
                    curl -s -w "\\nHTTP_STATUS:%{http_code}" \
                        -X POST "${DOJO_URL}/api/v2/import-scan/" \
                        -H "Authorization: Token ${DOJO_API_KEY}" \
                        -F "scan_type=Dependency Track Finding Packaging Format (FPF) Export" \
                        -F "file=@dtrack_findings.json" \
                        -F "product_name=WebGoat" \
                        -F "engagement_name=DevSecOps POC" \
                        -F "auto_create_context=true"
                """,
                returnStdout: true
            ).trim()

            // 4. Parse and validate Dojo response
            def httpStatus = dojoResponse.tokenize('\n')
                                         .find { it.startsWith('HTTP_STATUS:') }
                                         ?.replace('HTTP_STATUS:', '')
                                         ?.trim()
            def responseBody = dojoResponse
                                    .replaceAll('HTTP_STATUS:\\d+', '')
                                    .trim()

            echo "DefectDojo HTTP Status : ${httpStatus}"
            echo "DefectDojo Response    : ${responseBody}"

            if (httpStatus != "201") {
                error "DefectDojo upload failed — HTTP ${httpStatus}: ${responseBody}"
            }

            echo "D-Track findings successfully uploaded to DefectDojo"
        }
    }
} */

        stage('Security Gate') {
    steps {
        script {

            // Write the check script to a file — zero quoting issues
            writeFile file: 'gate_check.sh', text: '''\
#!/bin/sh
set -e

apk add --no-cache jq > /dev/null 2>&1

# Grype SCA — Critical vulnerabilities
if [ ! -f /src/grype.json ]; then
    echo "ERROR: grype.json not found" >&2
    exit 1
fi

# Semgrep SAST — ERROR severity
if [ ! -f /src/semgrep.json ]; then
    echo "ERROR: semgrep.json not found" >&2
    exit 1
fi

CRIT=$(jq '[.matches[] | select(.vulnerability.severity == "Critical")] | length' /src/grype.json)
SAST=$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' /src/semgrep.json)

echo "${CRIT} ${SAST}"
'''

            def result = sh(
                script: """
                    docker run --rm \
                        -v ${env.HOST_WORKSPACE}:/src \
                        -v ${env.WORKSPACE}/gate_check.sh:/gate_check.sh \
                        alpine sh /gate_check.sh
                """,
                returnStdout: true
            ).trim()

            echo "Raw gate output: '${result}'"

            // Validate output before parsing
            if (!result || !result.contains(' ')) {
                error "Security Gate: unexpected jq output — got: '${result}'"
            }

            def parts = result.tokenize(' ')
            if (parts.size() != 2 || !parts[0].isInteger() || !parts[1].isInteger()) {
                error "Security Gate: could not parse gate output — got: '${result}'"
            }

            def criticalSca = parts[0].toInteger()
            def highSast    = parts[1].toInteger()

            echo "Gate Results: ${criticalSca} Critical SCA, ${highSast} High SAST"

            if (criticalSca > 0 || highSast > 0) {
                env.GATE_FAILED = "true"
                currentBuild.result = 'UNSTABLE'
                error "Security Gate: ${criticalSca} Critical SCA, ${highSast} High SAST findings exceed threshold"
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
            // 1. Safely determine build state — currentBuild.result can be null mid-build
            def buildResult = currentBuild.result ?: 'FAILURE'

            def ghState
            def ghMessage

            if (env.GATE_FAILED == "true") {
                ghState   = 'FAILURE'
                ghMessage = 'Security Gate: Critical/High vulnerabilities found'
            } else if (buildResult == 'SUCCESS') {
                ghState   = 'SUCCESS'
                ghMessage = 'All checks passed'
            } else if (buildResult == 'UNSTABLE') {
                ghState   = 'FAILURE'          // GitHub only accepts: PENDING, SUCCESS, ERROR, FAILURE
                ghMessage = "Build UNSTABLE — check pipeline logs"
            } else {
                ghState   = 'FAILURE'
                ghMessage = "Build ${buildResult}"
            }

            echo "GitHub Commit Status → state: ${ghState}, message: ${ghMessage}"

            // 2. Wrap in try/catch so a GitHub API failure never masks the real build result
            try {
                step([
                    $class: 'GitHubCommitStatusSetter',
                    reposSource: [
                        $class: 'ManuallyEnteredRepositorySource',
                        url: 'https://github.com/bhama/devsecops-webgoat'
                    ],
                    commitShaSource: [
                        $class: 'BuildDataRevisionShaSource'
                    ],
                    contextSource: [
                        $class: 'ManuallyEnteredCommitContextSource',
                        context: 'Security-Gate/Jenkins'
                    ],
                    errorHandlers: [
                        [$class: 'ChangingBuildStatusErrorHandler', result: 'UNSTABLE']
                    ],
                    statusResultSource: [
                        $class: 'ConditionalStatusResultSource',
                        results: [[
                            $class: 'AnyBuildResult',
                            message: ghMessage,
                            state: ghState
                        ]]
                    ]
                ])
                echo "GitHub commit status updated successfully"
            } catch (Exception e) {
                echo "WARNING: Failed to update GitHub commit status — ${e.message}"
            }
        }
    }
}
}