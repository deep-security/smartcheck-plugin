package com.trendmicro.deepsecurity.smartcheck.model;

public class ScanResult {
	private String id;
	private String status;
	private ScanFindings findings;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public ScanFindings getFindings() {
		return findings;
	}

	public void setFindings(ScanFindings findings) {
		this.findings = findings;
	}
}
