pipeline {
    agent any
    stages {
        stage('Debug Firmware') {
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
                failure {
                    script {
                        if (env.CHANGE_ID) {
                            pullRequest.comment("Build ${env.BUILD_ID} - Failed 🚨")
                        }
                    }
                }
            }
        }
        stage('Release Firmware') {
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
                failure {
                    script {
                        if (env.CHANGE_ID) {
                            pullRequest.comment("Build ${env.BUILD_ID} - Failed 🚨")
                        }
                    }
                }
            }
        }
        stage('Debug Emulator + Unittests') {
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
            post {
                failure {
                    script {
                        if (env.CHANGE_ID) {
                            pullRequest.comment("Build ${env.BUILD_ID} - Failed 🚨")
                        }
                    }
                }
            }
        }
        stage('Post') {
            steps { sh '''echo "Success!"''' }
            post {
                always {
                    script {
                        if (env.CHANGE_ID) {
                            pullRequest.comment("Build ${env.BUILD_ID} - Success! 😍🦊")
                        }
                    }
                }
            }
        }
    }
}
