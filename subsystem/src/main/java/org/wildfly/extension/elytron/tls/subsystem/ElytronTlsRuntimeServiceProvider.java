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
 * Makes the values and instances of a {@link Service} available to runtime operations.
 * Derived from {@link org.jboss.as.clustering.controller.ServiceValueExecutorRegistry<T>}.
 * 
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class ElytronTlsRuntimeServiceProvider {

    private Map<ServiceName, Map<Class<?>, ElytronTlsRuntimeServiceObject<?>>> serviceValues = new ConcurrentHashMap<>();

    public <T> void addValue(ServiceName name, ElytronTlsRuntimeServiceObject<T> consumer) {
        serviceValues.putIfAbsent(name, new ConcurrentHashMap<>());
        serviceValues.get(name).put(consumer.getRuntimeClass(), consumer);       
    }

    public ElytronTlsRuntimeServiceObject<?> get(ServiceName name, Class<?> clazz) {
        ConcurrentHashMap<Class<?>, ElytronTlsRuntimeServiceObject<?>> service =
            (ConcurrentHashMap<Class<?>, ElytronTlsRuntimeServiceObject<?>>) serviceValues.getOrDefault(name, null);
        return service != null ? service.getOrDefault(clazz, null) : null;
    }
}

