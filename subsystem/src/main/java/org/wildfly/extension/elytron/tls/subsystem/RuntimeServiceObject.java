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

import static org.wildfly.extension.elytron.tls.subsystem._private.ElytronTLSLogger.LOGGER;

import java.util.function.Consumer;

import org.wildfly.common.function.ExceptionFunction;

/**
 * Captures a {@link Service} value to make available to runtime operations.
 * Derived from {@link org.jboss.as.clustering.controller.ServiceValueCaptor<T>}.
 * 
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class RuntimeServiceObject<T> implements Consumer<T> {

    protected T object = null;
    protected Class<?> objectClass;
    protected boolean objectAccepted = false;
    protected String name = null;

    /**
     * Sets the class of the service object. Will be overridden when an object is accepted.
     * 
     * @return the object class if successfully set, or null if not
     */
    public synchronized Class<?> setRuntimeClass(Class<T> clazz) {
        if (!objectAccepted) {
            objectClass = clazz;
            return objectClass;
        }
        
        return null;
    }

    public synchronized Class<?> getRuntimeClass()  {
        return objectClass;
    }

    public String getRuntimeName() {
        return name;
    }

    public synchronized void accept(T acceptedValue) {
        object = acceptedValue;
        objectClass = acceptedValue.getClass();
        objectAccepted = true;
    }

    /**
     * Use the service object as an argument to the {@link ExceptionFunction}.
     * 
     * @param function the function to be executed
     * @return the function result
     * @throws UnsupportedOperationException if both the service object and function input are instances 
     * of the same {@link RuntimeServiceFunction}.
     * @throws E if a function exception occurs
     */
    public synchronized <R, E extends Exception> R execute(ExceptionFunction<T, R, E> function) throws E {
        if (((RuntimeServiceFunction<?,?,?>) function).getRuntimeName() == name) {
            throw LOGGER.nestedRuntimeServiceFunctionExecution(name);
        }
        return object != null ? function.apply(object) : null;
    }
}
