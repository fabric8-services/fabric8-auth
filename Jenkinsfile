#!/usr/bin/groovy
@Library('github.com/fabric8io/fabric8-pipeline-library@master')
def utils = new io.fabric8.Utils()
def initServiceGitHash
def releaseVersion
goTemplate{
  dockerNode{
    ws {
      checkout scm

      if (utils.isCI()){
        def v = goCI{
          githubOrganisation = 'fabric8-services'
          dockerOrganisation = 'fabric8'
          project = 'fabric8-auth'
          dockerBuildOptions = '--file Dockerfile.deploy'
          makeTarget = 'build check-go-format test-unit-junit'
        }
      } else if (utils.isCD()){
        def v = goRelease{
          githubOrganisation = 'fabric8-services'
          dockerOrganisation = 'fabric8'
          project = 'fabric8-auth'
          dockerBuildOptions = '--file Dockerfile.deploy'
          makeTarget = 'build check-go-format test-unit-junit'
        }

        initServiceGitHash = sh(script: 'git rev-parse HEAD', returnStdout: true).toString().trim()

        pushPomPropertyChangePR{
            propertyName = 'auth.version'
            projects = [
                    'fabric8io/fabric8-platform'
            ]
            version = v
            containerName = 'go'
            autoMerge = true
        }
      }

      junit allowEmptyResults: true, testResults: '/home/jenkins/go/src/github.com/fabric8-services/fabric8-auth/tmp/junit.xml'
    }
  }
}
