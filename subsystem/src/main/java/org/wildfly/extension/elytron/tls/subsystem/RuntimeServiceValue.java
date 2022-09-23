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

import java.util.function.Consumer;

import org.jboss.msc.Service;
import org.wildfly.common.function.ExceptionFunction;

/**
 * Captures a {@link Service} value from its {@link Consumer} to make it available to runtime
 * operations.
 * 
 * @param objectAccepted indicates if the class has provided the object
 * @author <a href="mailto:carodrig@redhat.com">Cameron Rodriguez</a>
 */
public class RuntimeServiceValue<I, T> extends RuntimeServiceObject<Class<?>, T> implements Consumer<T> {
    
    private boolean objectAccepted = false;

    @Override
    public synchronized void accept(T acceptedValue) {
        object = acceptedValue;
        objectId = acceptedValue.getClass();
        objectAccepted = true;
    }

    /**
     * Sets the class of the service object. Will be overridden when an object is accepted.
     * 
     * @return the object class if successfully set, or null if not
     */
    public synchronized Class<?> setRuntimeClass(Class<?> clazz) {
        if (!objectAccepted) {
            objectId = clazz;
            return objectId;
        }
        return null;
    }

    public synchronized Class<?> getRuntimeClass()  {
        return objectId;
    }

    public synchronized <R, E extends Exception> R execute(ExceptionFunction<T, R, E> function) throws E {
        return (this.object != null) ? function.apply(this.object) : null;
    }
}
