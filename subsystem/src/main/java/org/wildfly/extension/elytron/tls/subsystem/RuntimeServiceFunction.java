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

public class RuntimeServiceFunction<T, R, E extends Exception> extends RuntimeServiceObject implements ExceptionFunction<T, R, E> {
    
    private ExceptionFunction<T, R, E> constructorFunction;
    private final Class<R> returnClass;

    public RuntimeServiceFunction(String functionName, Class<R> returnClass) {
        super(RuntimeServiceFunction.class, functionName);
        this.returnClass = returnClass;
        this.constructorFunction = null;
    }
    
    public RuntimeServiceFunction(ExceptionFunction<T, R, E> function, String functionName,
        Class<R> returnClass) {
        this(functionName, returnClass);
        this.constructorFunction = function;
    }

    public Class<R> getReturnClass() {
        return returnClass;
    }

    /** Defaults to run constructorFunction function if a function was passed in. */
    @Override
    public R apply(T t) throws E {
        return constructorFunction.apply(t);
    }
}
