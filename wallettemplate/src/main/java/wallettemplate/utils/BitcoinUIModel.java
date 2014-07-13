package wallettemplate.utils;

import com.google.bitcoin.core.*;
import javafx.application.Platform;
import javafx.beans.property.ReadOnlyObjectProperty;
import javafx.beans.property.SimpleObjectProperty;

/**
 * A class that exposes relevant bitcoin stuff as JavaFX bindable properties.
 */
public class BitcoinUIModel {
    private SimpleObjectProperty<Address> address = new SimpleObjectProperty<>();
    private SimpleObjectProperty<Coin> balance = new SimpleObjectProperty<>(Coin.ZERO);

    public BitcoinUIModel(Wallet wallet) {
        wallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onWalletChanged(Wallet wallet) {
                super.onWalletChanged(wallet);
                update(wallet);
            }
        }, Platform::runLater);
        update(wallet);
    }

    private void update(Wallet wallet) {
        balance.set(wallet.getBalance());
        address.set(wallet.currentReceiveAddress());
    }

    public ReadOnlyObjectProperty<Address> addressProperty() {
        return address;
    }

    public ReadOnlyObjectProperty<Coin> balanceProperty() {
        return balance;
    }
}
