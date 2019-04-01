package com.trendmicro.deepsecurity.smartcheck.model;

public class ResolvableSeverityCounts {
	private SeverityCounts total;
	private SeverityCounts unresolved;

	public SeverityCounts getTotal() {
		return total;
	}

	public void setTotal(SeverityCounts total) {
		this.total = total;
	}

	public SeverityCounts getUnresolved() {
		return unresolved;
	}

	public void setUnresolved(SeverityCounts unresolved) {
		this.unresolved = unresolved;
	}
}
