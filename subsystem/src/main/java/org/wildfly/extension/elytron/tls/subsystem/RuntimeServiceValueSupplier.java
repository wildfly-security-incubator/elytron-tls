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

import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import org.jboss.msc.service.ServiceName;

/**
 * Provides the values of a {@link org.jboss.msc.Service} at runtime. 
 * 
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class RuntimeServiceValueSupplier<I, O> implements RuntimeServiceSupplier<Class<?>,
                                                                RuntimeServiceValue<Class<?>, ?>> {

    protected ConcurrentHashMap<ServiceName,
                ConcurrentHashMap<Class<?>, RuntimeServiceValue<Class<?>, ?>>> runtimeValues = new ConcurrentHashMap<>();

    @Override
    public void addService(ServiceName serviceName) {
        runtimeValues.putIfAbsent(serviceName, new ConcurrentHashMap<>());
    }

    @SuppressWarnings("unchecked")
    public <T> void add(ServiceName serviceName, Consumer<T> consumer, Class<?> consumerClass) {
        RuntimeServiceValue<I, T> serviceObject = (RuntimeServiceValue<I, T>) consumer;
        serviceObject.setRuntimeClass(consumerClass);
        add(serviceName, serviceObject, consumerClass);
    }

    @Override
    public void add(ServiceName serviceName, RuntimeServiceValue<Class<?>, ?> serviceValue) {
        if (serviceValue.getRuntimeClass() == null) {
            throw LOGGER.undefinedServiceValueClass(serviceName.getCanonicalName());
        }

        runtimeValues.putIfAbsent(serviceName, new ConcurrentHashMap<>());
        runtimeValues.get(serviceName).put(serviceValue.getRuntimeClass(), serviceValue);
    }

    @Override
    public RuntimeServiceValue<Class<?>, ?> get(ServiceName name, Class<?> objectId) {
        ConcurrentHashMap<Class<?>, RuntimeServiceValue<Class<?>, ?>> service = runtimeValues.getOrDefault(name, null);
        
        if (service != null) {
            RuntimeServiceValue<Class<?>, ?> serviceValue = service.getOrDefault(objectId, null);
            return serviceValue;
        }
        return null;
    }
}

