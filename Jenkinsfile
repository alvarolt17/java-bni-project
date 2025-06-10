pipeline {
	agent any

	environment {
		PROJECT_NAME = "alvarolt17-dev"
		BUILD_NAME = "devsecops-starter"
	}

	stages {
		stage('Trigger Build in OpenShift'){
			steps {
				sh "oc start-build ${BUILD_NAME} --from-dir=. --follow -n ${PROJECT_NAME}"
			}
		}

		stage("Deploy to OpenShift") {
			steps {
				sh "oc rollout latest dc/${BUILD_NAME} -n ${PROJECT_NAME}"
			}
		}
	}

	post {
		success {
			echo "Build and deployment successful!"
		}
		failure {
			echo "Build or deployment failed."
		}
		always {
			echo "Pipeline execution completed."
		}
	}
}