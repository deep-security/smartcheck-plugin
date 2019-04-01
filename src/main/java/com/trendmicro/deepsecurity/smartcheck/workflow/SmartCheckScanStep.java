package com.trendmicro.deepsecurity.smartcheck.workflow;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import javax.annotation.Nonnull;

import org.apache.commons.lang.StringUtils;
import org.jenkinsci.plugins.workflow.steps.Step;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.StepDescriptor;
import org.jenkinsci.plugins.workflow.steps.StepExecution;
import org.jenkinsci.plugins.workflow.steps.SynchronousNonBlockingStepExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

import com.trendmicro.deepsecurity.smartcheck.Messages;
import com.trendmicro.deepsecurity.smartcheck.SmartCheckAction;

import hudson.AbortException;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.ArtifactArchiver;
import hudson.util.ArgumentListBuilder;

public class SmartCheckScanStep extends Step {
	private static final Logger LOGGER = Logger.getLogger(SmartCheckScanStep.class.getName());

	// TODO take a version
	private static final String DSSC_SCAN_IMAGE = "deepsecurity/smartcheck-scan-action";
	private static final String DEFAULT_RESULTS_FILE = "scan-results.json";

	private String smartcheckHost;
	private boolean insecureSkipTLSVerify = false;
	private String smartcheckUser;
	private String smartcheckPassword;
	private String imageName;
	private String imagePullAuth;
	private boolean insecureSkipRegistryTLSVerify = false;
	private String resultsFile;
	private String findingsThreshold;

	private boolean preregistryScan = false;
	private String preregistryHost;
	private String preregistryUser;
	private String preregistryPassword;

	private boolean debug = false;

	@DataBoundConstructor
	public SmartCheckScanStep(
		String imageName, String smartcheckHost, String smartcheckUser, String smartcheckPassword
	) {
		if (StringUtils.stripToNull(imageName) == null) {
			throw new IllegalArgumentException("imageName cannot be empty");
		}
		if (StringUtils.stripToNull(smartcheckHost) == null) {
			throw new IllegalArgumentException("smartcheckHost cannot be empty");
		}
		if (StringUtils.stripToNull(smartcheckUser) == null) {
			throw new IllegalArgumentException("smartcheckUser cannot be empty");
		}
		if (StringUtils.stripToNull(smartcheckPassword) == null) {
			throw new IllegalArgumentException("smartcheckPassword cannot be empty");
		}
		SmartCheckAction.validateSmartcheckUrl(smartcheckHost);

		this.imageName = imageName;
		this.smartcheckHost = smartcheckHost;
		this.smartcheckUser = smartcheckUser;
		this.smartcheckPassword = smartcheckPassword;
	}

	public String getSmartcheckHost() {
		return smartcheckHost;
	}

	@DataBoundSetter
	public void setSmartCheckHost(String smartcheckHost) {
		this.smartcheckHost = smartcheckHost;
	}

	public boolean isInsecureSkipTLSVerify() {
		return insecureSkipTLSVerify;
	}

	@DataBoundSetter
	public void setInsecureSkipTLSVerify(boolean insecureSkipTLSVerify) {
		this.insecureSkipTLSVerify = insecureSkipTLSVerify;
	}

	public String getSmartcheckUser() {
		return smartcheckUser;
	}

	@DataBoundSetter
	public void setSmartcheckUser(String smartcheckUser) {
		this.smartcheckUser = smartcheckUser;
	}

	public String getSmartcheckPassword() {
		return smartcheckPassword;
	}

	@DataBoundSetter
	public void setSmartcheckPassword(String smartcheckPassword) {
		this.smartcheckPassword = smartcheckPassword;
	}

	public String getImageName() {
		return imageName;
	}

	@DataBoundSetter
	public void setImageName(String imageName) {
		this.imageName = imageName;
	}

	public String getImagePullAuth() {
		return imagePullAuth;
	}

	@DataBoundSetter
	public void setImagePullAuth(String imagePullAuth) {
		this.imagePullAuth = imagePullAuth;
	}

	public boolean isInsecureSkipRegistryTLSVerify() {
		return insecureSkipRegistryTLSVerify;
	}

	@DataBoundSetter
	public void setInsecureSkipRegistryTLSVerify(boolean insecureSkipRegistryTLSVerify) {
		this.insecureSkipRegistryTLSVerify = insecureSkipRegistryTLSVerify;
	}

	public String getResultsFile() {
		return resultsFile;
	}

	@DataBoundSetter
	public void setResultsFile(String resultsFile) {
		this.resultsFile = resultsFile;
	}

	public String getFindingsThreshold() {
		return findingsThreshold;
	}

	@DataBoundSetter
	public void setFindingsThreshold(String findingsThreshold) {
		this.findingsThreshold = findingsThreshold;
	}

	public boolean isDebug() {
		return debug;
	}

	@DataBoundSetter
	public void setDebug(boolean debug) {
		this.debug = debug;
	}

	public boolean isPreregistryScan() {
		return preregistryScan;
	}

	@DataBoundSetter
	public void setPreregistryScan(boolean preregistryEnabled) {
		this.preregistryScan = preregistryEnabled;
	}

	public String getPreregistryHost() {
		return preregistryHost;
	}

	@DataBoundSetter
	public void setPreregistryHost(String preregistryHost) {
		this.preregistryHost = preregistryHost;
	}

	public String getPreregistryUser() {
		return preregistryUser;
	}

	@DataBoundSetter
	public void setPreregistryUser(String preregistryUser) {
		this.preregistryUser = preregistryUser;
	}

	public String getPreregistryPassword() {
		return preregistryPassword;
	}

	@DataBoundSetter
	public void setPreregistryPassword(String preregistryPassword) {
		this.preregistryPassword = preregistryPassword;
	}

	@Override
	public StepExecution start(StepContext context) throws Exception {
		return new SmartCheckScanStepExecution(context, this);
	}

	@Extension
	public static class DescriptorImpl extends StepDescriptor {

		@Override
		public Set<? extends Class<?>> getRequiredContext() {
			return Collections
				.unmodifiableSet(Arrays.asList(Run.class, TaskListener.class).stream().collect(Collectors.toSet()));
		}

		@Override
		public String getFunctionName() {
			return "smartcheckScan";
		}

		@Nonnull
		@Override
		public String getDisplayName() {
			return Messages.SmartCheckBuilder_DescriptorImpl_DisplayName();
		}
	}

	public static class SmartCheckScanStepExecution extends SynchronousNonBlockingStepExecution<Void> {

		private static final long serialVersionUID = 1L;

		private static final int EXIT_OK = 0;
		private static final int EXIT_THRESHOLD_FAILURE = 2;

		private transient SmartCheckScanStep step;

		protected SmartCheckScanStepExecution(StepContext context, SmartCheckScanStep step) {
			super(context);
			this.step = step;
		}

		@Override
		protected Void run() throws IOException, InterruptedException {
			LOGGER.fine("Starting scan step");
			TaskListener listener = getContext().get(TaskListener.class);
			PrintStream logger = listener.getLogger();
			Launcher launcher = getContext().get(Launcher.class);
			Run<?, ?> currentBuild = getContext().get(Run.class);
			FilePath workspaceFilePath = getContext().get(FilePath.class);
			if (workspaceFilePath == null) {
				getContext()
					.onFailure(
						new AbortException(
							"No workspace found. Please check your pipeline script and ensure it's running within a `node` block."
						)
					);
				return null;
			}
			String workspacePath = workspaceFilePath.getRemote();

			ArgumentListBuilder dockerCommandArgs = new ArgumentListBuilder();
			dockerCommandArgs.add("docker", "run", "-i", "--rm", "--read-only");
			dockerCommandArgs.add("--cap-drop", "ALL");

			dockerCommandArgs.add("-e", "DSSC_SMARTCHECK_HOST=" + step.getSmartcheckHost());
			dockerCommandArgs.add("-e", "DSSC_IMAGE_NAME=" + step.getImageName());
			dockerCommandArgs.add("-e", "DSSC_SMARTCHECK_USER=" + step.getSmartcheckUser());
			dockerCommandArgs.add("-e", "DSSC_SMARTCHECK_PASSWORD=" + step.getSmartcheckPassword());
			if (step.isInsecureSkipTLSVerify()) {
				dockerCommandArgs.add("-e", "DSSC_INSECURE_SKIP_TLS_VERIFY=" + step.isInsecureSkipTLSVerify());
			}
			if (step.isInsecureSkipRegistryTLSVerify()) {
				dockerCommandArgs
					.add("-e", "DSSC_INSECURE_SKIP_REGISTRY_TLS_VERIFY=" + step.isInsecureSkipRegistryTLSVerify());
			}
			if (StringUtils.stripToNull(step.getImagePullAuth()) != null) {
				dockerCommandArgs.add("-e", "DSSC_IMAGE_PULL_AUTH=" + step.getImagePullAuth());
			}
			if (StringUtils.stripToNull(step.getFindingsThreshold()) != null) {
				dockerCommandArgs.add("-e", "DSSC_FINDINGS_THRESHOLD=" + step.getFindingsThreshold());
			}
			if (step.isPreregistryScan()) {
				dockerCommandArgs.add("--mount", "type=tmpfs,destination=/root/.docker");
				dockerCommandArgs.add("-v", "/var/run/docker.sock:/var/run/docker.sock");
				dockerCommandArgs.add("-e", "DSSC_PREREGISTRY_SCAN=true");
			}
			if (StringUtils.stripToNull(step.getPreregistryHost()) != null) {
				dockerCommandArgs.add("-e", "DSSC_PREREGISTRY_HOST=" + step.getPreregistryHost());
			}
			if (StringUtils.stripToNull(step.getPreregistryUser()) != null) {
				dockerCommandArgs.add("-e", "DSSC_PREREGISTRY_USER=" + step.getPreregistryUser());
			}
			if (StringUtils.stripToNull(step.getPreregistryPassword()) != null) {
				dockerCommandArgs.add("-e", "DSSC_PREREGISTRY_PASSWORD=" + step.getPreregistryPassword());
			}

			dockerCommandArgs.add(DSSC_SCAN_IMAGE);

			if (step.isDebug()) {
				logger.println("command = " + dockerCommandArgs.toString());
			}

			logger.println("Starting Deep Security Smart Check scan...");

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			int status = launcher
				.launch()
				.cmds(dockerCommandArgs)
				.stderr(logger)
				.stdout(baos)
				.quiet(!step.isDebug())
				.join();
			String output = new String(baos.toByteArray(), "UTF-8");

			if (step.isDebug()) {
				logger.println("Status code was: " + status);
			}

			String resultsFile;
			// can't validate resultsFile path earlier because we don't have the workspace path
			// context
			if (step.getResultsFile() != null) {
				Path normalized = Paths.get(workspacePath, step.getResultsFile()).normalize();
				// avoid traversal
				if (!normalized.startsWith(workspacePath)) {
					getContext()
						.onFailure(new IllegalArgumentException("Results file must be in the current workspace."));
					return null;
				}
				resultsFile = Paths.get(workspacePath).relativize(normalized).toString();
			} else {
				resultsFile = DEFAULT_RESULTS_FILE;
			}

			if (output.length() > 0) {
				boolean fileWritten = false;
				try {
					workspaceFilePath.child(resultsFile).write(output, "UTF-8");
					fileWritten = true;
				} catch (IOException e) {
					logger.println("Failed to write results to file.");
					if (step.isDebug()) {
						logger.println(e);
					}
				}
				if (fileWritten) {
					ArtifactArchiver artifactArchiver = new ArtifactArchiver(resultsFile);
					if (step.isDebug()) {
						logger.println(String.format("Build root directory: %s", currentBuild.getRootDir()));
						logger.println(String.format("Workspace remote: %s", workspaceFilePath.getRemote()));
						logger.println(String.format("Archiving artifacts: %s", artifactArchiver.getArtifacts()));
					}
					LOGGER.fine(String.format("Archiving artifacts: %s", artifactArchiver.getArtifacts()));

					try {
						artifactArchiver.perform(currentBuild, workspaceFilePath, launcher, listener);
					} catch (IOException e) {
						logger.println("Failed to archive results file");
						if (step.isDebug()) {
							logger.println(e);
						}
					}
					LOGGER.fine("Archiving complete.");
				}
			}

			if (status != EXIT_OK && status != EXIT_THRESHOLD_FAILURE) {
				String errorMessage = "Deep Security Smart Check scan returned an error.";
				logger.println(errorMessage);
				logger.println(output);
				throw new AbortException(errorMessage);
			} else {

				currentBuild.addAction(new SmartCheckAction(workspacePath, output, step.getSmartcheckHost()));

				if (status == EXIT_OK) {
					logger.println("Scan successful");
					getContext().onSuccess(null);
					return null;
				} else if (status == EXIT_THRESHOLD_FAILURE) {
					String errorMessage = "Deep Security Smart Check scan found issues with the image";
					logger.println(errorMessage);
					throw new AbortException(errorMessage);
				}
			}
			return null;
		}

	}
}
