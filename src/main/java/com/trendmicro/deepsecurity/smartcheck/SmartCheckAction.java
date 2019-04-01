package com.trendmicro.deepsecurity.smartcheck;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.logging.Logger;

import org.apache.http.client.utils.URIBuilder;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.json.JsonSanitizer;
import com.trendmicro.deepsecurity.smartcheck.model.ScanResult;

import hudson.model.Run;
import jenkins.model.RunAction2;

/*
 * This class gets invoked from the {@link SmartCheckScanStepExecution} when a scan has completed
 * without errors. This object is then consumed by the index.jelly file in the resources folder to
 * render an HTML page.
 */
public class SmartCheckAction implements RunAction2 {
	private static final Logger LOGGER = Logger.getLogger(SmartCheckAction.class.getName());

	private transient Run<?, ?> run;
	private ScanResult scanResult;
	private String scanUIUrl;

	public SmartCheckAction(String workspace, String resultsOutput, String smartcheckHost) {

		ScanResult scanResult;
		try {
			scanResult = parseScanResults(workspace, resultsOutput);
		} catch (BuildScanResultsException e) {
			LOGGER.severe(e.getMessage());
			LOGGER.fine(e.getStackTrace().toString());
			return;
		}
		this.setScanResult(scanResult);

		String smartcheckUrl = validateSmartcheckUrl(smartcheckHost);
		String uiUrl;
		try {
			uiUrl = new URIBuilder(smartcheckUrl).setPath("scans/" + getScanResult().getId()).build().toString();
			this.setScanUIUrl(uiUrl);
		} catch (URISyntaxException e) {
			// this shouldn't happen because the parameter has been validated when the step was
			// invoked
			throw new IllegalArgumentException("smartcheckHost is not a valid url");
		}
	}

	public static String validateSmartcheckUrl(String smartcheckHost) throws IllegalArgumentException {
		String smartcheckUrl = smartcheckHost.startsWith("http") ? smartcheckHost : "https://" + smartcheckHost;
		try {
			new URIBuilder(smartcheckUrl);
		} catch (URISyntaxException e) {
			throw new IllegalArgumentException("smartcheckHost is not a valid url");
		}
		return smartcheckUrl;
	}

	class BuildScanResultsException extends Exception {
		private static final long serialVersionUID = 1L;

		public BuildScanResultsException(String string) {
			super(string);
		}

		public BuildScanResultsException(String string, Throwable t) {
			super(string, t);
		}
	}

	private ScanResult parseScanResults(String workspace, String results) throws BuildScanResultsException {
		String sanitizedJson = JsonSanitizer.sanitize(results);
		ObjectMapper mapper = new ObjectMapper();
		mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		try {
			ScanResult scanResult = mapper.readerFor(ScanResult.class).readValue(sanitizedJson);
			return scanResult;
		} catch (IOException e) {
			throw new BuildScanResultsException("Failed to parse scan results.", e);
		}
	}

	@Override
	public String getIconFileName() {
		return "/plugin/deepsecurity-smartcheck/images/smartcheck.png";
	}

	@Override
	public String getDisplayName() {
		return "Deep Security Smart Check Scan Report";
	}

	@Override
	public String getUrlName() {
		return "smartcheck-scan";
	}

	@Override
	public void onAttached(Run<?, ?> r) {
		this.run = r;
	}

	@Override
	public void onLoad(Run<?, ?> r) {
		this.run = r;
	}

	public Run<?, ?> getRun() {
		return run;
	}

	public ScanResult getScanResult() {
		return scanResult;
	}

	public void setScanResult(ScanResult scanResult) {
		this.scanResult = scanResult;
	}

	public String getScanUIUrl() {
		return scanUIUrl;
	}

	public void setScanUIUrl(String scanUIUrl) {
		this.scanUIUrl = scanUIUrl;
	}
}
