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

import java.util.concurrent.ConcurrentHashMap;

import org.jboss.msc.service.ServiceName;
import org.wildfly.common.function.ExceptionFunction;

/**
 * Provides the functions of a {@link org.jboss.msc.Service} at runtime. 
 * 
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class RuntimeServiceFunctionSupplier<I, O> implements RuntimeServiceSupplier<String,
    RuntimeServiceFunction<String, ExceptionFunction<?, ?, ? extends Exception>>> {
    
    protected ConcurrentHashMap<ServiceName,
        ConcurrentHashMap<String, RuntimeServiceFunction<String,
            ExceptionFunction<?, ?, ? extends Exception>>>> runtimeFunctions = new ConcurrentHashMap<>();

    @Override
    public void addService(ServiceName serviceName) {
        runtimeFunctions.putIfAbsent(serviceName, new ConcurrentHashMap<>());
    }

    public void add(ServiceName serviceName, ExceptionFunction<?, ?, ? extends Exception> function,
        String functionName) {

        RuntimeServiceFunction<String,
            ExceptionFunction<?, ?, ? extends Exception>> serviceObject = new RuntimeServiceFunction<>(function, functionName);
        add(serviceName, serviceObject);
    }

    @Override
    public void add(ServiceName serviceName, RuntimeServiceFunction<String,
                    ExceptionFunction<?, ?, ? extends Exception>> serviceFunction) {
        
        runtimeFunctions.putIfAbsent(serviceName, new ConcurrentHashMap<>());
        runtimeFunctions.get(serviceName).put(serviceFunction.getFunctionName(), serviceFunction);
    }

    @Override
    public RuntimeServiceFunction<String, ExceptionFunction<?, ?, ? extends Exception>> get(ServiceName serviceName,
                String functionName) {

        ConcurrentHashMap<String, RuntimeServiceFunction<String,
            ExceptionFunction<?, ?, ? extends Exception>>> service = runtimeFunctions.getOrDefault(serviceName, null);

        if (service != null) {
            RuntimeServiceFunction<String, ExceptionFunction<?, ?,
                    ? extends Exception>> serviceFunction = service.getOrDefault(functionName, null);
            return serviceFunction;
        }
        return null;
    }

    
}
