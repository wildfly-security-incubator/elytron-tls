/*
 * Copyright 2022 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.extension.elytron.tls.subsystem;

import org.jboss.msc.Service;
import org.wildfly.common.function.ExceptionFunction;

/**
 * Captures a {@link Service} method as an {@link ExceptionFunction} to make it available to runtime
 * operations.
 * 
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */

public class RuntimeServiceFunction<I, T> extends RuntimeServiceObject<String, ExceptionFunction<?, ?, ? extends Exception>> {
    
    public RuntimeServiceFunction(ExceptionFunction<?, ?, ? extends Exception> function,
        String functionName) {
        
        object = function;
        objectId = functionName;
    }
    
    public String getFunctionName() {
        return objectId;
    }

    /** Provides the {@link ExceptionFunction} */
    public ExceptionFunction<?, ?, ? extends Exception> getFunction() {
        return object;
    }

    /** Alias for {@code getFunction()} */
    public ExceptionFunction<?, ?, ? extends Exception> execute() {
        return object;
    }
}
