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
public class RuntimeServiceValue<T> extends RuntimeServiceObject implements Consumer<T> {
    
    private T object = null;
    
    public RuntimeServiceValue(Class<?> valueClass) {
        super(RuntimeServiceValue.class, valueClass.getName());
    }

    public RuntimeServiceValue() {
        super(RuntimeServiceValue.class, "unset");
    }

    public void setObjectName(Class<?> valueClass) {
        objectName = valueClass.getName();
    }

    @Override
    public synchronized void accept(T acceptedValue) {
        object = acceptedValue;
    }

    public synchronized <R, E extends Exception> R execute(ExceptionFunction<T, R, E> function) throws E {
        return (this.object != null) ? function.apply(this.object) : null;
    }
}
