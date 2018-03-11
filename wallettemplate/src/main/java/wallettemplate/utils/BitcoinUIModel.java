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

package wallettemplate.utils;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.listeners.DownloadProgressTracker;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.listeners.WalletChangeEventListener;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyDoubleProperty;
import javafx.beans.property.ReadOnlyObjectProperty;
import javafx.beans.property.SimpleDoubleProperty;
import javafx.beans.property.SimpleObjectProperty;

import java.util.Date;

/**
 * A class that exposes relevant bitcoin stuff as JavaFX bindable properties.
 */
public class BitcoinUIModel {
    private SimpleObjectProperty<Address> address = new SimpleObjectProperty<>();
    private SimpleObjectProperty<Coin> balance = new SimpleObjectProperty<>(Coin.ZERO);
    private SimpleDoubleProperty syncProgress = new SimpleDoubleProperty(-1);
    private ProgressBarUpdater syncProgressUpdater = new ProgressBarUpdater();

    public BitcoinUIModel() {
    }

    public BitcoinUIModel(Wallet wallet) {
        setWallet(wallet);
    }

    public final void setWallet(Wallet wallet) {
        wallet.addChangeEventListener(Platform::runLater, new WalletChangeEventListener() {
            @Override
            public void onWalletChanged(Wallet wallet) {
                update(wallet);
            }
        });
        update(wallet);
    }

    private void update(Wallet wallet) {
        balance.set(wallet.getBalance());
        address.set(wallet.currentReceiveAddress());
    }

    private class ProgressBarUpdater extends DownloadProgressTracker {
        @Override
        protected void progress(double pct, int blocksLeft, Date date) {
            super.progress(pct, blocksLeft, date);
            Platform.runLater(() -> syncProgress.set(pct / 100.0));
        }

        @Override
        protected void doneDownload() {
            super.doneDownload();
            Platform.runLater(() -> syncProgress.set(1.0));
        }
    }

    public DownloadProgressTracker getDownloadProgressTracker() { return syncProgressUpdater; }

    public ReadOnlyDoubleProperty syncProgressProperty() { return syncProgress; }

    public ReadOnlyObjectProperty<Address> addressProperty() {
        return address;
    }

    public ReadOnlyObjectProperty<Coin> balanceProperty() {
        return balance;
    }
}
