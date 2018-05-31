pipeline {
    agent any
    stages {
        stage('Build Debug Firmware') {
            steps {
                ansiColor('xterm') {
                    sh '''
                        rm -rf bin
                        ./scripts/build/docker/device/debug.sh
                        tar cjvf debug.tar.bz2 bin/*'''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'debug.tar.bz2', fingerprint: true
                }
            }
        }
        stage('Build Release Firmware') {
            steps {
                ansiColor('xterm') {
                    sh '''
                        rm -rf bin
                        ./scripts/build/docker/device/release.sh
                        tar cjvf release.tar.bz2 bin/*'''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'release.tar.bz2,bin/*.bin', fingerprint: true
                }
            }
        }
        stage('Build Debug Emulator + Unittests') {
            steps {
                ansiColor('xterm') {
                    sh '''
                        ./scripts/build/docker/emulator/debug.sh'''
                }
                step([$class: 'XUnitPublisher',
                        thresholds: [[$class: 'FailedThreshold', unstableThreshold: '1']],
                        tools: [[$class: 'GoogleTestType',
                                   pattern: 'build/unittests/*.xml',
                                   skipNoTestFiles: false,
                                   failIfNotNew: false,
                                   deleteOutputFiles: false,
                                   stopProcessingIfError: false]]])

            }
        }
    }
}
