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

package wallettemplate.controls;

import javafx.animation.Interpolator;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.Timeline;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.value.ObservableDoubleValue;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import javafx.scene.Node;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.util.Duration;
import wallettemplate.utils.GuiUtils;
import wallettemplate.utils.easing.EasingMode;
import wallettemplate.utils.easing.ElasticInterpolator;

import javax.annotation.Nullable;

/**
 * Wraps the given Node in a BorderPane and allows a thin bar to slide in from the bottom or top, squeezing the content
 * node. The API allows different "items" to be added/removed and they will be displayed one at a time, fading between
 * them when the topmost is removed. Each item is meant to be used for e.g. a background task and can contain a button
 * and/or a progress bar.
 */
public class NotificationBarPane extends BorderPane {
    public static final Duration ANIM_IN_DURATION = GuiUtils.UI_ANIMATION_TIME.multiply(2);
    public static final Duration ANIM_OUT_DURATION = GuiUtils.UI_ANIMATION_TIME;

    private HBox bar;
    private Label label;
    private double barHeight;
    private ProgressBar progressBar;

    public class Item {
        public final SimpleStringProperty label;
        @Nullable public final ObservableDoubleValue progress;

        public Item(String label, @Nullable ObservableDoubleValue progress) {
            this.label = new SimpleStringProperty(label);
            this.progress = progress;
        }

        public void cancel() {
            items.remove(this);
        }
    }

    public final ObservableList<Item> items;

    public NotificationBarPane(Node content) {
        super(content);
        progressBar = new ProgressBar();
        label = new Label("infobar!");
        bar = new HBox(label);
        bar.setMinHeight(0.0);
        bar.getStyleClass().add("info-bar");
        bar.setFillHeight(true);
        setBottom(bar);
        // Figure out the height of the bar based on the CSS. Must wait until after we've been added to the parent node.
        sceneProperty().addListener(o -> {
            if (getParent() == null) return;
            getParent().applyCss();
            getParent().layout();
            barHeight = bar.getHeight();
            bar.setPrefHeight(0.0);
        });
        items = FXCollections.observableArrayList();
        items.addListener((ListChangeListener<? super Item>) change -> {
            config();
            showOrHide();
        });
    }

    private void config() {
        if (items.isEmpty()) return;
        Item item = items.get(0);

        bar.getChildren().clear();
        label.textProperty().bind(item.label);
        label.setMaxWidth(Double.MAX_VALUE);
        HBox.setHgrow(label, Priority.ALWAYS);
        bar.getChildren().add(label);
        if (item.progress != null) {
            progressBar.setMinWidth(200);
            progressBar.progressProperty().bind(item.progress);
            bar.getChildren().add(progressBar);
        }
    }

    private void showOrHide() {
        if (items.isEmpty())
            animateOut();
        else
            animateIn();
    }

    public boolean isShowing() {
        return bar.getPrefHeight() > 0;
    }

    private void animateIn() {
        animate(barHeight);
    }

    private void animateOut() {
        animate(0.0);
    }

    private Timeline timeline;
    protected void animate(Number target) {
        if (timeline != null) {
            timeline.stop();
            timeline = null;
        }
        Duration duration;
        Interpolator interpolator;
        if (target.intValue() > 0) {
            interpolator = new ElasticInterpolator(EasingMode.EASE_OUT, 1, 2);
            duration = ANIM_IN_DURATION;
        } else {
            interpolator = Interpolator.EASE_OUT;
            duration = ANIM_OUT_DURATION;
        }
        KeyFrame kf = new KeyFrame(duration, new KeyValue(bar.prefHeightProperty(), target, interpolator));
        timeline = new Timeline(kf);
        timeline.setOnFinished(x -> timeline = null);
        timeline.play();
    }

    public Item pushItem(String string, @Nullable ObservableDoubleValue progress) {
        Item i = new Item(string, progress);
        items.add(i);
        return i;
    }
}