package com.trendmicro.deepsecurity.smartcheck;

import static org.junit.Assert.assertNotNull;

import java.io.File;

import org.apache.commons.io.FilenameUtils;
import org.junit.Test;

public class SmartCheckActionTest {

	@Test
	public void testAction() throws Exception {
		String fixturePath = new File("src/test/resources/scan-result-sample.json").toString();
		String dirName = FilenameUtils.getFullPath(fixturePath);
		String fileName = FilenameUtils.getName(fixturePath);

		SmartCheckAction action = new SmartCheckAction(dirName, fileName, "0.0.0.0:8443");
		// if not null then we can assume that the reading and parsing happened ok.
		assertNotNull(action.getScanResult());
	}
}
