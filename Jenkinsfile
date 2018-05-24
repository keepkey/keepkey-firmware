pipeline {
    agent any
    stages {
        stage('Build Debug Firmware') {
            steps {
                sh '''
                    rm -rf bin
                    ./scripts/build/docker/device/debug.sh
                    tar cjvf debug.tar.bz2 bin/*'''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'debug.tar.bz2', fingerprint: true
                }
            }
        }
        stage('Build Release Firmware') {
            steps {
                sh '''
                    rm -rf bin
                    ./scripts/build/docker/device/release.sh
                    tar cjvf release.tar.bz2 bin/*'''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'release.tar.bz2,bin/*.bin', fingerprint: true
                }
            }
        }
    }
}
