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
module wallettemplate {
    requires java.desktop;
    requires java.logging;

    requires javafx.controls;
    requires javafx.fxml;

    requires jakarta.annotation;

    requires org.slf4j;
    requires com.google.zxing;

    requires org.bitcoinj.core;

    exports wallettemplate;
    exports org.bitcoinj.walletfx.controls;
    opens wallettemplate to javafx.fxml;
    opens org.bitcoinj.walletfx.controls to javafx.fxml;
}
