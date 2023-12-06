/**
 * A [Rust](https://doc.rust-lang.org/std/result/enum.Result.html) inspired type for error handling
 *
 * `Result` is a type that represents either success ({@link Ok `Ok`}) or failure ({@link `Err` Err}).
 */
export type Result<T, E> = (OkVariant<T> | ErrVariant<E>) & ResultImpl<T, E>;

export type OkVariant<T> = {
    /** The stored value */
    ok: T;

    isOk: true;
    isErr: false;

    /** Cast the `Err` type into any `E` */
    cast<E>(): Result<T, E> & OkVariant<T>;
};
export type ErrVariant<E> = {
    /** The stored error value */
    err: E;

    isOk: false;
    isErr: true;

    /** Cast the `Ok` type into any `T` */
    cast<T>(): Result<T, E> & ErrVariant<E>;
};

export interface ResultImpl<T, E> {
    match<R>(ifOk: (ok: T) => R, ifErr: (err: E) => R): R;

    /**
     * Calls `func` if the result is `Ok`, otherwise returns the `Err` value of `this`.
     *
     * This function can be used for control flow based on `Result` values.
     *
     * @param func function to process the `OK` value
     */
    andThen<U>(func: (ok: T) => Result<U, E>): Result<U, E>;

    /**
     * Maps a `Result<T, E>` to `Result<U, E>` by applying a function to a contained `Ok` value, leaving an `Err` value untouched.
     *
     * This function can be used to compose the results of two functions.
     *
     * @param func function to apply to a potential `Ok`
     */
    map<U>(func: (ok: T) => U): Result<U, E>;

    /**
     * Maps a `Result<T, E>` to `Result<T, F>` by applying a function to a contained `Err` value, leaving an `Ok` value untouched.
     *
     * This function can be used to pass through a successful result while handling an error.
     *
     * @param func function to apply to a potential `Err`
     */
    mapErr<F>(func: (err: E) => F): Result<T, F>;

    /**
     * Returns the contained `Ok` value, consuming the `this` value.
     *
     * Because this method may panic, its use is generally discouraged.
     * Instead, prefer to use pattern matching and handle the `Err` case explicitly,
     * or call `unwrapOr` or `unwrapOrElse`.
     *
     * @throws UnwrapError<E> if the value is an `Err`, with a panic message provided by the `Err`’s `toString()` implementation.
     */
    unwrap(): T;

    /**
     * Returns the contained `Ok` value or a provided `default_`.
     *
     * Arguments passed to `unwrapOr` are eagerly evaluated; if you are passing the result of a function call,
     * it is recommended to use `unwrapOrElse`, which is lazily evaluated.
     *
     * @param default_ a default value to return in case of an `Err`
     */
    unwrapOr(default_: T): T;

    /**
     * Returns the contained `Ok` value or computes it from a closure.
     *
     * @param default_ a function producing a default value in case of an `Err`
     */
    unwrapOrElse(default_: () => T): T;
}

/** Namespace of helper function operating on `Result`s */
export namespace Result {
    /**
     * Takes each element in the iterable of `Result`s:
     * - if it is an `Err`, no further elements are taken, and the `Err` is returned
     * - should no `Err` occur, an array with the values of each `Result` is returned
     *
     * @param iterable an iterable yielding results
     */
    function collect<T, E>(iterable: Iterable<Result<T, E>>): Result<Array<T>, E> {
        const array = [];
        for (const result of iterable) {
            if (result.isOk) {
                array.push(result.ok);
            } else {
                return result.cast();
            }
        }
        return new Ok(array);
    }
}

export class Ok<T, E> implements OkVariant<T>, ResultImpl<T, E> {
    ok: T;
    isOk: true = true;
    isErr: false = false;

    constructor(ok: T) {
        this.ok = ok;
    }

    match<R>(ifOk: (ok: T) => R, ifErr: (err: E) => R): R {
        return ifOk(this.ok);
    }

    andThen<U>(func: (ok: T) => Result<U, E>): Result<U, E> {
        return func(this.ok);
    }

    map<U>(func: (ok: T) => U): Result<U, E> {
        return new Ok(func(this.ok));
    }

    mapErr<F>(func: (err: E) => F): Result<T, F> {
        return new Ok(this.ok);
    }

    unwrap(): T {
        return this.ok;
    }

    unwrapOr(_: T): T {
        return this.ok;
    }

    unwrapOrElse(_: () => T): T {
        return this.ok;
    }

    cast<E>(): Result<T, E> & OkVariant<T> {
        return new Ok(this.ok);
    }
}

export class Err<T, E> implements ErrVariant<E>, ResultImpl<T, E> {
    err: E;
    isOk: false = false;
    isErr: true = true;

    constructor(err: E) {
        this.err = err;
    }

    match<R>(ifOk: (ok: T) => R, ifErr: (err: E) => R): R {
        return ifErr(this.err);
    }

    andThen<U>(func: (ok: T) => Result<U, E>): Result<U, E> {
        return new Err(this.err);
    }

    map<U>(func: (ok: T) => U): Result<U, E> {
        return new Err(this.err);
    }

    mapErr<F>(func: (err: E) => F): Result<T, F> {
        return new Err(func(this.err));
    }

    unwrap(): T {
        throw new UnwrapError(this.err);
    }

    unwrapOr(default_: T): T {
        return default_;
    }

    unwrapOrElse(default_: () => T): T {
        return default_();
    }

    cast<T>(): Result<T, E> & ErrVariant<E> {
        return new Err(this.err);
    }
}

export class UnwrapError<E> extends Error {
    value: E;

    constructor(value: E) {
        super("Called `unwrap` on an `Err` with value: " + value);
        this.value = value;
    }
}
