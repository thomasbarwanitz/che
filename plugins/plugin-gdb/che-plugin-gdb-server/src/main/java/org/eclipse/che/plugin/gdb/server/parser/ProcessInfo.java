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

import org.eclipse.che.plugin.gdb.server.exception.GdbParseException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser to get info about running process.
 *
 * @author Roman Nikitenko
 */
public class ProcessInfo {

    private static final Pattern PROCESS_INFO = Pattern.compile(".*([0-9]*) (.*)", Pattern.DOTALL);

    private final int    pid;
    private final String name;

    public ProcessInfo(String name, int pid) {
        this.name = name;
        this.pid = pid;
    }

    public String getProcessName() {
        return name;
    }

    public int getProcessId() {
        return pid;
    }

    /**
     * Factory method.
     */
    public static ProcessInfo parse(String output) throws GdbParseException {
        final Matcher matcher = PROCESS_INFO.matcher(output);
        if (matcher.find()) {
            try {
                String group1 = matcher.group(1);
                String group2 = matcher.group(2);
                final int processId = Integer.parseInt(matcher.group(1));
                final String processName = matcher.group(2).replaceAll("\\s+","");

                return new ProcessInfo(processName, processId);
            } catch (NumberFormatException e) {
                throw new GdbParseException(ProcessInfo.class, output);
            }
        }
        throw new GdbParseException(ProcessInfo.class, output);
    }
}
