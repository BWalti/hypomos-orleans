// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

// TODO: Seamless RxJs integration
// From RxJs: https://github.com/ReactiveX/rxjs/blob/master/src/Observer.ts
export interface Observer<T> {
    closed?: boolean;
    next: (value: T) => void;
    error?: (err: any) => void;
    complete?: () => void;
}

export class Subscription<T> {
    private subject: Subject<T>;
    private observer: Observer<T>;

    constructor(subject: Subject<T>, observer: Observer<T>) {
        this.subject = subject;
        this.observer = observer;
    }

    dispose(): void {
        const index = this.subject.observers.indexOf(this.observer);
        if (index > -1) {
            this.subject.observers.splice(index, 1);
        }

        if (this.subject.observers.length === 0) {
            this.subject.cancelCallback().catch((_) => {});
        }
    }
}

export interface Observable<T> {
    subscribe(observer: Observer<T>): Subscription<T>;
}

export class Subject<T> implements Observable<T> {
    observers: Array<Observer<T>>;
    cancelCallback: () => Promise<void>;

    constructor(cancelCallback: () => Promise<void>) {
        this.observers = [];
        this.cancelCallback = cancelCallback;
    }

    next(item: T): void {
        for (const observer of this.observers) {
            observer.next(item);
        }
    }

    error(err: any): void {
        for (const observer of this.observers) {
            if (observer.error) {
                observer.error(err);
            }
        }
    }

    complete(): void {
        for (const observer of this.observers) {
            if (observer.complete) {
                observer.complete();
            }
        }
    }

    subscribe(observer: Observer<T>): Subscription<T> {
        this.observers.push(observer);
        return new Subscription(this, observer);
    }
}