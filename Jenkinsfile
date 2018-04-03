pipeline {
    agent any
    stages {
        stage('Build') {
            parallel {
                stage('Build Debug Firmware') {
                    steps {
                        sh '''./scripts/build/docker/device/debug.sh'''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'bin/*', fingerprint: true
                        }
                    }
                }
                stage('Build Release Firmware') {
                    steps {
                        sh '''./scripts/build/docker/device/debug.sh'''
                    }
                    post {
                        always {
                            archiveArtifacts artifacts: 'bin/*', fingerprint: true
                        }
                    }
                }
            }
        }
    }

}
