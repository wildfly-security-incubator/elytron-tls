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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.jboss.msc.Service;
import org.jboss.msc.service.ServiceName;

/**
 * Makes the values and functions of a {@link Service} available to runtime operations.
 * Derived from {@link org.jboss.as.clustering.controller.ServiceValueExecutorRegistry<T>}.
 * 
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class RuntimeServiceProvider {

    private Map<ServiceName, Map<Class<?>, RuntimeServiceObject<?>>> runtimeServices = new ConcurrentHashMap<>();

    public void addService(ServiceName name) {
        runtimeServices.putIfAbsent(name, new ConcurrentHashMap<>());
    }

    public <T> void addValue(ServiceName name, RuntimeServiceObject<T> consumer) {
        runtimeServices.putIfAbsent(name, new ConcurrentHashMap<>());
        runtimeServices.get(name).put(consumer.getRuntimeClass(), consumer);       
    }

    @SuppressWarnings("unchecked")
    public <T> RuntimeServiceObject<T> get(ServiceName name, Class<T> clazz) {
        Map<Class<?>, RuntimeServiceObject<?>> service = runtimeServices.getOrDefault(name, null);
        
        if (service != null) {
            RuntimeServiceObject<?> runtimeObject = service.getOrDefault(clazz, null);
            if (runtimeObject != null && runtimeObject.getRuntimeClass() == clazz) {
                return (RuntimeServiceObject<T>) runtimeObject;
            } 
        }
        return null;
    }
}

