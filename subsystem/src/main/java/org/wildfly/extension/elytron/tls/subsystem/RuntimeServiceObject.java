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

/**
 * Captures a {@link Service} object to make it available to runtime operations. Derived from 
 * {@link org.jboss.as.clustering.controller.FunctionExecutor}
 * 
 * @param runtimeObjectType the implementation of this class
 * @param objectName an identifier for the object, such as a name or class in string form
 * @implSpec Create an appropriate object field
 * 
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public abstract class RuntimeServiceObject {
    protected final String runtimeObjectType;
    protected String objectName;

    public RuntimeServiceObject(Class<? extends RuntimeServiceObject> runtimeObjectType, String objectName) {
        this.runtimeObjectType = runtimeObjectType.getName();
        this.objectName = objectName;
    }

    public final String getRuntimeObjectDetails() {
        return new StringBuilder(runtimeObjectType).append(':').append(objectName).toString();
    }

    public final String getObjectName() {
        return objectName;
    }
}
