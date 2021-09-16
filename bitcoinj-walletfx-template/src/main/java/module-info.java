/*
 * Copyright by the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 *
 */
module wallettemplate {
    requires java.logging;
    requires java.desktop;

    requires javafx.graphics;
    requires javafx.controls;
    requires javafx.fxml;

    requires app.supernaut.fx;
    requires javax.inject;
    /*
     * Although the classes in a SupernautFX app (like this one, hopefully) use annotations
     * from javax.inject and do not import any Micronaut classes,
     * the Bean Definition classes generated by the Micronaut annotation process
     * run inside this module and do require Micronaut classes.
     */
    requires io.micronaut.inject;

    requires org.bitcoinj.walletfx;

    //requires jsr305;  // This is only needed for IntelliJ because IntelliJ doesn't know about the patch-module command apparently
    requires org.slf4j;
    requires org.slf4j.jul;

    requires org.bitcoinj.core;     // Automatic module

    requires org.bouncycastle.provider;
    requires com.google.common;

    requires protobuf.java;
    requires com.google.zxing;
    requires fontawesomefx;         // Filename-based automatic module name
    
    /* Export/Open the WalletTemplate App itself -- will eventually be its own module */
    exports wallettemplate;

    opens wallettemplate to org.bitcoinj.walletfx, javafx.fxml, java.base;

}