import { EventEmitter, Uri, UriHandler, Disposable } from "vscode";

export class SpotifyUriHandler implements UriHandler {
    private _disposables = new Set<Disposable>();
    private _onDidHandleUri = new EventEmitter<Uri>();
    readonly onDidHandleUri = this._onDidHandleUri.event;

    constructor() {
        this._disposables.add(this._onDidHandleUri);
    }

    dispose() {
        for (const disposable of this._disposables) {
            try {
                disposable.dispose();
            } catch (e) {
                console.error(e);
            }
        }
    }

    handleUri(uri: Uri): void {
        this._onDidHandleUri.fire(uri);
    }

    waitForUri(): Promise<Uri> {
        return new Promise(resolve => {
            const disposable = this.onDidHandleUri(uri => {
                this._disposables.delete(disposable);
                disposable.dispose();
                resolve(uri);
            });
            this._disposables.add(disposable);
        });
    }
}
