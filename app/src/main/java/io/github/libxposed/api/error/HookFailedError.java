package io.github.libxposed.api.error;

@SuppressWarnings("unused")
public class HookFailedError extends XposedFrameworkError {

    public HookFailedError(String message) {
        super(message);
    }

    public HookFailedError(String message, Throwable cause) {
        super(message, cause);
    }

    public HookFailedError(Throwable cause) {
        super(cause);
    }
}