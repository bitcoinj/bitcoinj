/**
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

import javafx.application.Platform;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A simple wrapper around {@link javafx.application.Platform#runLater(Runnable)} which will do nothing if the previous
 * invocation of runLater didn't execute on the JavaFX UI thread yet. In this way you can avoid flooding
 * the event loop if you have a background thread that for whatever reason wants to update the UI very
 * frequently. Without this class you could end up bloating up memory usage and causing the UI to stutter
 * if the UI thread couldn't keep up with your background worker.
 */
public class ThrottledRunLater implements Runnable {
    private final Runnable runnable;
    private final AtomicBoolean pending = new AtomicBoolean();

    /** Created this way, the no-args runLater will execute this classes run method. */
    public ThrottledRunLater() {
        this.runnable = null;
    }

    /** Created this way, the no-args runLater will execute the given runnable. */
    public ThrottledRunLater(Runnable runnable) {
        this.runnable = runnable;
    }

    public void runLater(Runnable runnable) {
        if (!pending.getAndSet(true)) {
            Platform.runLater(() -> {
                pending.set(false);
                runnable.run();
            });
        }
    }

    public void runLater() {
        runLater(runnable != null ? runnable : this);
    }

    @Override
    public void run() {
    }
}
