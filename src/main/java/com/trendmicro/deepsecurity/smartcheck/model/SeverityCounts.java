package com.trendmicro.deepsecurity.smartcheck.model;

public class SeverityCounts {

	private Integer defcon1 = 0;
	private Integer critical = 0;
	private Integer high = 0;
	private Integer medium = 0;
	private Integer low = 0;
	private Integer negligible = 0;
	private Integer unknown = 0;

	public Integer getDefcon1() {
		return defcon1;
	}

	public void setDefcon1(Integer defcon1) {
		this.defcon1 = defcon1;
	}

	public Integer getCritical() {
		return critical;
	}

	public void setCritical(Integer critical) {
		this.critical = critical;
	}

	public Integer getHigh() {
		return high;
	}

	public void setHigh(Integer high) {
		this.high = high;
	}

	public Integer getMedium() {
		return medium;
	}

	public void setMedium(Integer medium) {
		this.medium = medium;
	}

	public Integer getLow() {
		return low;
	}

	public void setLow(Integer low) {
		this.low = low;
	}

	public Integer getNegligible() {
		return negligible;
	}

	public void setNegligible(Integer negligible) {
		this.negligible = negligible;
	}

	public Integer getUnknown() {
		return unknown;
	}

	public void setUnknown(Integer unknown) {
		this.unknown = unknown;
	}
}
