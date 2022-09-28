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

import org.jboss.msc.Service;

/**
 * Captures the methods of a {@link Service} to make it available to runtime
 * operations.
 * 
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public abstract class RuntimeServiceMethods extends RuntimeServiceObject {
    
    private final Class<? extends RuntimeServiceMethods> methodsClass;

    public RuntimeServiceMethods(Class<? extends RuntimeServiceMethods> methodsClass) {
        super(methodsClass, methodsClass.getName());
        this.methodsClass = methodsClass;
    }

    public Class<? extends RuntimeServiceMethods> getMethodsClass() {
        return methodsClass;
    }
}
