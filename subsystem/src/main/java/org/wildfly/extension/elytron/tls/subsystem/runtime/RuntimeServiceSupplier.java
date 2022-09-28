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

import java.util.ArrayList;

import org.jboss.msc.service.ServiceName;

/**
 * Makes the objects of a {@link Service} available for execution by runtime operations . Derived
 * from {@link org.jboss.as.clustering.controller.FunctionExecutorRegistry}.
 * 
 * @implSpec the method {@code get(ServiceName, Object)} using an identifier, to return the {@link RuntimeServiceObject}.
 * Must be converted to a {@link String}.
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */

interface RuntimeServiceSupplier {

    /**
     * Adds a service to a {@link java.util.Collection} to store its related objects
     * 
     * @param serviceName the name of the service
     */
    public void addService(ServiceName serviceName);

    /**
     * Adds a {@link RuntimeServiceObject} to the collection of objects provided by the service.
     * 
     * @param serviceName the name of the service providing the object 
     * @param serviceObject the object available when requested
     * @return the details of the object added, or null if failed to add
     */
    public <T extends RuntimeServiceObject> String add(ServiceName serviceName, T serviceObject);

    /**
     * Adds a {@link RuntimeServiceObject} to the collection of objects provided by the service.
     * 
     * @param serviceName the name of the service providing the object 
     * @param serviceObjects the objects available when requested
     * @return an {@link ArrayList} of the added objects, substituting an empty String on failures
     */
    default public ArrayList<String> add(ServiceName serviceName, RuntimeServiceObject... serviceObjects){
        ArrayList<String> results = new ArrayList<>(); 
        
        for (RuntimeServiceObject obj : serviceObjects) {
            String result = add(serviceName, obj);
            results.add(result != null ? result : new String());
        }
        return results;
    }
}