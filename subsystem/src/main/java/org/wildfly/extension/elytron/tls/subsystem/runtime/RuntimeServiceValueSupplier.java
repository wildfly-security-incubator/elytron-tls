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

package org.wildfly.extension.elytron.tls.subsystem.runtime;

import static org.wildfly.extension.elytron.tls.subsystem._private.ElytronTLSLogger.LOGGER;

import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

import org.jboss.msc.service.ServiceName;

/**
 * Provides the values of a {@link org.jboss.msc.Service} at runtime. 
 * 
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class RuntimeServiceValueSupplier implements RuntimeServiceSupplier {

    protected ConcurrentHashMap<ServiceName,
        ConcurrentHashMap<String, RuntimeServiceValue>> runtimeValues = new ConcurrentHashMap<>();

    @Override
    public void addService(ServiceName serviceName) {
        runtimeValues.putIfAbsent(serviceName, new ConcurrentHashMap<>());
    }

    public <T> void add(ServiceName serviceName, Consumer<T> consumer, Class<?> consumerClass) {
        RuntimeServiceValue<T> serviceValue = (RuntimeServiceValue<T>) consumer;
        serviceValue.setObjectName(consumerClass);
        add(serviceName, serviceValue, consumerClass);
    }

    @Override
    public <T extends RuntimeServiceObject> String add(ServiceName serviceName, T serviceValue) {
        if (serviceValue.getObjectName() == "unset") {
            throw LOGGER.undefinedServiceValueClass(serviceName.getSimpleName());
        }

        ConcurrentHashMap<String, RuntimeServiceValue> service = runtimeValues.getOrDefault(serviceName, null);
        if (service != null) {
            RuntimeServiceValue result = runtimeValues.get(serviceName).put(serviceValue.getObjectName(), (RuntimeServiceValue) serviceValue);
            return result != null ? result.getRuntimeObjectDetails() : null;
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public <T> RuntimeServiceValue<T> get(ServiceName name, Class<T> objectClass) {
        ConcurrentHashMap<String, RuntimeServiceValue> service = runtimeValues.getOrDefault(name, null);
        
        if (service != null) {
            RuntimeServiceValue<T> serviceValue = (RuntimeServiceValue<T>) service.getOrDefault(objectClass, null);
            return serviceValue;
        }
        return null;
    }
}

