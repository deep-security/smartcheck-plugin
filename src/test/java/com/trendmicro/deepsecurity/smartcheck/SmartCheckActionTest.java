package com.trendmicro.deepsecurity.smartcheck;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.io.FilenameUtils;
import org.junit.Test;

public class SmartCheckActionTest {

	@Test
	public void testParseScan() throws Exception {
		String fixturePath = new File("src/test/resources/scan-result-sample.json").toString();
		String contents = new String(Files.readAllBytes(Paths.get("src/test/resources/scan-result-sample.json")));
		String dirName = FilenameUtils.getFullPath(fixturePath);

		SmartCheckAction action = new SmartCheckAction(dirName, contents, "0.0.0.0:8443");
		// if not null then we can assume that the reading and parsing happened ok.
		assertNotNull(action.getScanResult());
	}
}
