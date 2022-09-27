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
public class RuntimeServiceFunctionSupplier<O> implements RuntimeServiceSupplier<RuntimeServiceFunction> {
    
    protected ConcurrentHashMap<ServiceName,
        ConcurrentHashMap<String, RuntimeServiceFunction>> runtimeFunctions = new ConcurrentHashMap<>();

    @Override
    public void addService(ServiceName serviceName) {
        runtimeFunctions.putIfAbsent(serviceName, new ConcurrentHashMap<>());
    }

    public <T, R, E extends Exception> void add(ServiceName serviceName, ExceptionFunction<T, R, E> function,
        String functionName, Class<R> returnClass) {

        RuntimeServiceFunction<T, R, E> serviceFunction = new RuntimeServiceFunction<>(function, functionName, returnClass);
        add(serviceName, serviceFunction);
    }

    @Override
    public void add(ServiceName serviceName, RuntimeServiceFunction serviceFunction) {
        
        runtimeFunctions.putIfAbsent(serviceName, new ConcurrentHashMap<>());
        runtimeFunctions.get(serviceName).put(serviceFunction.getObjectName(), serviceFunction);
    }

    @SuppressWarnings("unchecked")
    public <T, R, E extends Exception> RuntimeServiceFunction<T, R, E> get(ServiceName serviceName,
                String functionName, Class<R> returnClass) {

        ConcurrentHashMap<String, RuntimeServiceFunction> service = runtimeFunctions.getOrDefault(serviceName, null);

        if (service != null) {
            RuntimeServiceFunction<T, R, E> serviceFunction = (RuntimeServiceFunction<T, R, E>) service.getOrDefault(functionName, null);
            if (serviceFunction.getReturnClass() == returnClass) return serviceFunction;
        }
        return null;
    }

    
}
