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
            DTRACK_API_KEY="odt_WGazJMXi_p3IdtnEmUgUxdyuICEKLB0wQGx4Xfkl7"
            DTRACK_PROJECT_UUID="cd588d0a-e8ad-41c2-8822-3da8e9524e0f"
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

            stage('SBOM Analysis') {
                steps {
                    script {
                        echo "Generating CycloneDX SBOM..."
                        // Generate SBOM in CycloneDX format
                        sh "docker run --rm -v ${HOST_WORKSPACE}:/src anchore/syft:latest scan dir:/src -o cyclonedx-json > bom.json"
                        
                        echo "Uploading to Dependency-Track..."
                        // Use your new API Key and Project UUID from the D-Track UI
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

            stage('DAST (ZAP)') {
                steps {
                    script {
                            // Create an empty file and give it 777 permissions so the Docker user can write to it
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
                            'ZAP Scan': 'zap_report.xml' 
                        ]

                        scans.each { dojoTypeName, fileName ->
                            // Logging for your visibility in Jenkins Console
                            if (fileExists(fileName)) {
                                echo "✅ Found ${fileName}. Uploading to Dojo as ${dojoTypeName}..."
                                
                                // Removed 'sudo' as it fails in the Jenkins container
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
                        def ghState = (currentBuild.result == 'SUCCESS') ? 'SUCCESS' : 'FAILURE'
                        def ghMessage = (env.GATE_FAILED == "true") ? 
                                        'Security Gate Violation: Critical Vulnerabilities Found' : 
                                        "Build ${currentBuild.result}"

                        step([$class: 'GitHubCommitStatusSetter',
                            reposSource: [$class: "ManuallyEnteredRepositorySource", url: "https://github.com/bhama/devsecops-webgoat"],
                            // Add this to ensure the SHA is never lost
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