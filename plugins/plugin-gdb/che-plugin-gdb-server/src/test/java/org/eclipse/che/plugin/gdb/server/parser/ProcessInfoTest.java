/*******************************************************************************
 * Copyright (c) 2012-2016 Codenvy, S.A.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *   Codenvy, S.A. - initial API and implementation
 *******************************************************************************/
package org.eclipse.che.plugin.gdb.server.parser;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * @author Roman Nikitenko
 */
public class ProcessInfoTest {

    private static String OUTPUT = " 436 /projects/cpp/a.out";

    @Test
    public void testParseFileInfo() throws Exception {
        final ProcessInfo processInfo = ProcessInfo.parse(OUTPUT);
        final String processName = processInfo.getProcessName();
        final int pid = processInfo.getProcessId();

        assertEquals(processName, "/projects/cpp/a.out");
        assertEquals(pid, 436);
    }
}
