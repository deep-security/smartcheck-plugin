package com.trendmicro.deepsecurity.smartcheck.model;

public class ScanFindings {
	private Integer malware = 0;
	private ResolvableSeverityCounts contents;
	private ResolvableSeverityCounts vulnerabilities;
	private ResolvableSeverityCounts checklists;

	public Integer getMalware() {
		return malware;
	}

	public void setMalware(Integer malware) {
		this.malware = malware;
	}

	public ResolvableSeverityCounts getContents() {
		return contents;
	}

	public void setContents(ResolvableSeverityCounts contents) {
		this.contents = contents;
	}

	public ResolvableSeverityCounts getVulnerabilities() {
		return vulnerabilities;
	}

	public void setVulnerabilities(ResolvableSeverityCounts vulnerabilities) {
		this.vulnerabilities = vulnerabilities;
	}

	public ResolvableSeverityCounts getChecklists() {
		return checklists;
	}

	public void setChecklists(ResolvableSeverityCounts checklists) {
		this.checklists = checklists;
	}
}
