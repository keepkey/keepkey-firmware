pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'echo "Building with cmake"'
                sh '''
                    git submodule update --init --recursive
                    ./scripts/build/docker/device/debug.sh
                '''
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'bin/*', fingerprint: true
        }
    }
}
