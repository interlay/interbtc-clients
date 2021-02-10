pipeline {
    agent {
        kubernetes {
            yamlFile '.deploy/rust-builder-pod.yaml'
        }
    }
    environment {
        RUSTC_WRAPPER = '/usr/local/bin/sccache'
    }

    options {
        gitLabConnection 'Gitlab-Interlay'
        gitlabBuilds(builds: ['test', 'build'])
    }

    stages {
        stage('Test') {
            steps {
                container('rust') {
                    updateGitlabCommitStatus name: 'test', state: 'running'

                    sh 'rustc --version'
                    sh 'SCCACHE_START_SERVER=1 SCCACHE_IDLE_TIMEOUT=0 /usr/local/bin/sccache'
                    sh '/usr/local/bin/sccache -s'

                    sh 'cargo fmt -- --check'
                    sh 'cargo check --workspace --release'
                    sh 'cargo test -j1 --workspace --release'

                    sh '/usr/local/bin/sccache -s'
                }
            }
            post {
                success {
                    updateGitlabCommitStatus name: 'test', state: 'success'
                }
                failure {
                    updateGitlabCommitStatus name: 'test', state: 'failed'
                }
                unstable {
                    updateGitlabCommitStatus name: 'test', state: 'failed'
                }
                aborted {
                    updateGitlabCommitStatus name: 'test', state: 'canceled'
                }
            }
        }

        stage('Build binaries') {
            steps {
                container('rust') {
                    updateGitlabCommitStatus name: 'build-parachain', state: 'running'

                    sh 'SCCACHE_START_SERVER=1 SCCACHE_IDLE_TIMEOUT=0 /usr/local/bin/sccache'
                    sh '/usr/local/bin/sccache -s'

                    sh 'cargo build --workspace --release'

                    sh 'mkdir -p target/release/_artifacts && find target/release/ -type f -executable -exec mv {} target/release/_artifacts/ \\;'
                    archiveArtifacts 'target/release/_artifacts/*'
//                    stash(name: "btc-parachain-parachain", includes: 'Dockerfile_release, target/release/btc-parachain-parachain')

                    sh '/usr/local/bin/sccache -s'
                }
            }
            post {
                success {
                    updateGitlabCommitStatus name: 'build', state: 'success'
                }
                failure {
                    updateGitlabCommitStatus name: 'build', state: 'failed'
                }
                unstable {
                    updateGitlabCommitStatus name: 'build', state: 'failed'
                }
                aborted {
                    updateGitlabCommitStatus name: 'build', state: 'canceled'
                }
            }
        }
    }
}

