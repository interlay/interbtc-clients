def output_files = ['staked-relayer', 'oracle', 'vault', 'faucet', 'testdata-gen']

pipeline {
    agent none
    environment {
        RUSTC_WRAPPER = '/usr/local/bin/sccache'
        CI = 'true'
        GITHUB_TOKEN = credentials('ns212-github-token')
    }

    options {
        timestamps()
        ansiColor('xterm')
    }

    stages {
    stage('Build & Test') {
            matrix {
                agent {
                    kubernetes {
                        yamlFile '.deploy/rust-builder-pod.yaml'
                    }
                }
                axes {
                    axis {
                        name 'PLATFORM'
                        values 'x86_64-unknown-linux-gnu', 'x86_64-pc-windows-gnu'
                    }
                }
                stages {
                    stage('build') {
                        steps {
                container('rust') {
                sh '''
                    rustc --version
                    SCCACHE_START_SERVER=1 SCCACHE_IDLE_TIMEOUT=0 /usr/local/bin/sccache
                    /usr/local/bin/sccache -s
                    cargo fmt -- --check
                    cargo check --workspace --release --target $PLATFORM
                    cargo build --workspace --release --target $PLATFORM
                '''
                }
            }
                    }
                }
            }
    }
    }
}

def runKaniko() {
    sh '''#!/busybox/sh
    set -x
    GIT_BRANCH_SLUG=$(echo $GIT_BRANCH | sed -e 's/\\//-/g')
    /kaniko/executor -f `pwd`/.deploy/Dockerfile -c `pwd` --build-arg BINARY=${IMAGE} \
        --destination=${REGISTRY}/${REPOSITORY}/${IMAGE}:${GIT_BRANCH_SLUG} \
        --destination=${REGISTRY}/${REPOSITORY}/${IMAGE}:${GIT_BRANCH_SLUG}-${GIT_COMMIT:0:6}
    '''
}
