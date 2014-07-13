package wallettemplate.utils;

import javafx.beans.binding.StringBinding;
import javafx.beans.value.ObservableValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Function;

/**
 * Some generic utilities to make Java a bit less annoying.
 */
public class WTUtils {
    private static final Logger log = LoggerFactory.getLogger(WTUtils.class);

    public interface UncheckedRun<T> {
        public T run() throws Throwable;
    }

    public interface UncheckedRunnable {
        public void run() throws Throwable;
    }

    public static <T> T unchecked(UncheckedRun<T> run) {
        try {
            return run.run();
        } catch (Throwable throwable) {
            throw new RuntimeException(throwable);
        }
    }

    public static void uncheck(UncheckedRunnable run) {
        try {
            run.run();
        } catch (Throwable throwable) {
            throw new RuntimeException(throwable);
        }
    }

    public static void ignoreAndLog(UncheckedRunnable runnable) {
        try {
            runnable.run();
        } catch (Throwable t) {
            log.error("Ignoring error", t);
        }
    }

    public static <T> T ignoredAndLogged(UncheckedRun<T> runnable) {
        try {
            return runnable.run();
        } catch (Throwable t) {
            log.error("Ignoring error", t);
            return null;
        }
    }

    public static boolean didThrow(UncheckedRun run) {
        try {
            run.run();
            return false;
        } catch (Throwable throwable) {
            return true;
        }
    }

    public static boolean didThrow(UncheckedRunnable run) {
        try {
            run.run();
            return false;
        } catch (Throwable throwable) {
            return true;
        }
    }

    // Why isn't this a part of the JFX Bindings class?
    public static <T> StringBinding bindToString(ObservableValue<T> value, Function<T, String> function) {
        return new StringBinding() {
            {
                super.bind(value);
            }

            @Override
            protected String computeValue() {
                return function.apply(value.getValue());
            }
        };
    }
}
