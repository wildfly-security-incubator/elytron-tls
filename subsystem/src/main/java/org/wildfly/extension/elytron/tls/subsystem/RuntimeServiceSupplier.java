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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import org.jboss.msc.Service;
import org.jboss.msc.service.ServiceName;

/**
 * Makes the values and functions of a {@link Service} available for execution by runtime operations.
 * Derived from {@link org.jboss.as.clustering.controller.ServiceValueExecutorRegistry<T>}.
 * 
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class RuntimeServiceSupplier {

    private Map<ServiceName, Map<Class<?>, RuntimeServiceObject<?>>> runtimeValues = new ConcurrentHashMap<>();
    private Map<ServiceName, Map<String, RuntimeServiceFunction<?, ?, ? extends Exception>>> runtimeFunctions = new ConcurrentHashMap<>();

    public void addService(ServiceName serviceName) {
        runtimeValues.putIfAbsent(serviceName, new ConcurrentHashMap<>());
        runtimeFunctions.putIfAbsent(serviceName, new ConcurrentHashMap<>());
    }

    public <T> void add(ServiceName serviceName, Consumer<T> consumer, Class<T> consumerClass) {
        RuntimeServiceObject<T> serviceObject = (RuntimeServiceObject<T>) consumer;
        serviceObject.setRuntimeClass(consumerClass);
        add(serviceName, serviceObject);
    }

    public <T> void add(ServiceName serviceName, RuntimeServiceObject<T> serviceObject) {
        if (serviceObject.getRuntimeClass() == null) {
            throw LOGGER.runtimeServiceValueClassUndefined();
        }

        runtimeValues.putIfAbsent(serviceName, new ConcurrentHashMap<>());
        runtimeValues.get(serviceName).put(serviceObject.getRuntimeClass(), serviceObject);       
    }

    public <T, R, E extends Exception> void add(ServiceName serviceName,
        RuntimeServiceFunction<T, R, E> serviceFunction, String functionName) {

        runtimeFunctions.putIfAbsent(serviceName, new ConcurrentHashMap<>());
        runtimeFunctions.get(serviceName).put(functionName, serviceFunction);
    }

    @SuppressWarnings("unchecked")
    public <T> RuntimeServiceObject<T> get(ServiceName name, Class<T> clazz) {
        Map<Class<?>, RuntimeServiceObject<?>> service = runtimeValues.getOrDefault(name, null);
        
        if (service != null) {
            RuntimeServiceObject<?> runtimeValue = service.getOrDefault(clazz, null);
            if (runtimeValue != null && runtimeValue.getRuntimeClass() == clazz) {
                return (RuntimeServiceObject<T>) runtimeValue;
            } 
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public <T, R, E extends Exception> RuntimeServiceFunction<T, R, E> get(ServiceName serviceName, String functionName) {
        Map<String, RuntimeServiceFunction<?,?,? extends Exception>> service = runtimeFunctions.getOrDefault(serviceName, null);

        if (service != null) {
            RuntimeServiceFunction<?,?,? extends Exception> runtimeFunction = service.getOrDefault(functionName, null);
            if (runtimeFunction != null && runtimeFunction.getRuntimeName() == functionName) {
                return (RuntimeServiceFunction<T, R, E>) runtimeFunction;
            }
        }
        return null;
    }
}

