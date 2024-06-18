import { AccessToken, SpotifyApi } from "@spotify/web-api-ts-sdk";
import { authentication, AuthenticationProvider, AuthenticationProviderAuthenticationSessionsChangeEvent, AuthenticationSession, Disposable, env, Event, EventEmitter, SecretStorage, Uri, window } from "vscode";
import { SpotifyUriHandler } from "./uriHandler";

export const clientId = '18f4898a018949518ac1b17eea561af9';
const redirectUrl = 'https://vscode.dev/redirect';

const authorizationEndpoint = "https://accounts.spotify.com/authorize";
const tokenEndpoint = "https://accounts.spotify.com/api/token";

const secretStorageKey = 'tokens';

export interface SpotifyAuthenticationSession extends AuthenticationSession {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
    clientId: string;
}

export class SpotifyAuthProvider extends Disposable implements AuthenticationProvider {
    static readonly id = 'spotify';
    static readonly label = 'Spotify';

    private _disposables = new Set<Disposable>();
    private _uriHandler = new SpotifyUriHandler();

    private _onDidChangeSessions: EventEmitter<AuthenticationProviderAuthenticationSessionsChangeEvent> = new EventEmitter<AuthenticationProviderAuthenticationSessionsChangeEvent>();
    onDidChangeSessions: Event<AuthenticationProviderAuthenticationSessionsChangeEvent> = this._onDidChangeSessions.event;

    private _sessions: SpotifyAuthenticationSession[] = [];

    constructor(private readonly _secretStorage: SecretStorage) {
        super(() => this.dispose());
        this._disposables.add(this._uriHandler);
        this._disposables.add(window.registerUriHandler(this._uriHandler));
        this._disposables.add(this._onDidChangeSessions);
    }

    //#region Lifecycle functions

    dispose() {
        for (const disposable of this._disposables) {
            try {
                disposable.dispose();
            } catch (e) {
                console.error(e);
            }
        }
    }

    async initialize() {
        let sessions = await this._secretStorage.get(secretStorageKey);
        this._sessions = sessions ? JSON.parse(sessions) : [];
        await this._refreshSessions();
    }

    //#endregion

    //#region AuthenticationProvider implementation

    getSessions(scopes?: readonly string[]): Thenable<readonly AuthenticationSession[]> {
        return Promise.resolve(this._sessions
            .filter(session => !scopes || scopes.every(scope => session.scopes.includes(scope)))
            .map(s => ({
                id: s.id,
                accessToken: s.accessToken,
                scopes: s.scopes,
                account: s.account
            }))
        );
    }

    async createSession(scopes: readonly string[]): Promise<AuthenticationSession> {
        const codeVerifier = this._createCodeVerifier();
        const codeChallenge = await this._createCodeChallenge(codeVerifier);
        await this._openSpotifyAuthUri(scopes.join(' '), codeChallenge);
        const uri = await this._uriHandler.waitForUri();
        const code = new URLSearchParams(uri.query).get('code');
        if (!code) {
            throw new Error('No code found in URI');
        }
        const response = await this._exchangeCodeForToken(code, codeVerifier);
        // eslint-disable-next-line @typescript-eslint/naming-convention
        const { display_name, id } = await this._getUserInfo(response.access_token);
        const session: SpotifyAuthenticationSession = {
            id: response.access_token,
            accessToken: response.access_token,
            refreshToken: response.refresh_token,
            expiresIn: response.expires_in,
            scopes,
            clientId,
            account: {
                label: display_name,
                id
            }
        };
        this._sessions.push(session);
        await this._secretStorage.store(secretStorageKey, JSON.stringify(this._sessions));
        this._onDidChangeSessions.fire({ added: [session], removed: [], changed: [] });
        // Setup the timeout to refresh the sessions
        if (this._sessions.length === 1) {
            setTimeout(() => this._refreshSessions(), response.expires_in * 1000 * 2 / 3);
        }
        return {
            id: session.id,
            accessToken: session.accessToken,
            scopes: session.scopes,
            account: session.account
        };
    }

    async removeSession(sessionId: string): Promise<void> {
        const sessionIndex = this._sessions.findIndex(session => session.id === sessionId);
        if (sessionIndex !== -1) {
            const [session] = this._sessions.splice(sessionIndex, 1);
            await this._secretStorage.store(secretStorageKey, JSON.stringify(this._sessions));
            this._onDidChangeSessions.fire({ added: [], removed: [session], changed: [] });
        }
        return Promise.resolve();
    }

    //#endregion

    //#region create flow helpers

    private _createCodeVerifier(): string {
        const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const randomValues = globalThis.crypto.getRandomValues(new Uint8Array(64));
        const randomString = randomValues.reduce((acc, x) => acc + possible[x % possible.length], "");
        return randomString;
    }

    private async _createCodeChallenge(codeVerifier: string): Promise<string> {
        const data = new TextEncoder().encode(codeVerifier);
        const hashed = await globalThis.crypto.subtle.digest('SHA-256', data);

        const codeChallengeBase64 = btoa(String.fromCharCode(...new Uint8Array(hashed)))
            .replace(/=/g, '')
            .replace(/\+/g, '-')
            .replace(/\//g, '_');
        return codeChallengeBase64;
    }

    private async _openSpotifyAuthUri(
        scope: string,
        codeChallenge: string
    ): Promise<boolean> {
        const redirectTo = await env.asExternalUri(Uri.parse(`${env.uriScheme}://TylerLeonhardt.vscode-spotify-auth/authenticate`));
        const authUrl = new URL(authorizationEndpoint);
        authUrl.search = new URLSearchParams({
            // eslint-disable-next-line @typescript-eslint/naming-convention
            response_type: 'code',
            // eslint-disable-next-line @typescript-eslint/naming-convention
            client_id: clientId,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            code_challenge_method: 'S256',
            // eslint-disable-next-line @typescript-eslint/naming-convention
            code_challenge: codeChallenge,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            redirect_uri: redirectUrl,
            scope,
            state: redirectTo.toString(true),
        }).toString();
        return await env.openExternal(Uri.parse(authUrl.toString()));
    }

    private async _exchangeCodeForToken(code: string, codeVerifier: string): Promise<AccessToken> {
        const body = new URLSearchParams({
            code,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            grant_type: 'authorization_code',
            // eslint-disable-next-line @typescript-eslint/naming-convention
            redirect_uri: redirectUrl,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            client_id: clientId,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            code_verifier: codeVerifier,
        }).toString();
        const response = await this._safeFetchWithRetry<AccessToken>(tokenEndpoint, {
            method: 'POST',
            // eslint-disable-next-line @typescript-eslint/naming-convention
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body,
        });
        return response;
    }

    // eslint-disable-next-line @typescript-eslint/naming-convention
    private async _getUserInfo(accessToken: string): Promise<{ display_name: string, id: string }> {
        // eslint-disable-next-line @typescript-eslint/naming-convention
        const response = await this._safeFetchWithRetry<{ display_name: string, id: string }>(
            'https://api.spotify.com/v1/me',
            {
                headers: { authorization: `Bearer ${accessToken}` },
            }
        );
        return response;
    }

    //#endregion

    //#region refresh flow helpers

    private async _refreshSessions(): Promise<void> {
        if (!this._sessions.length) {
            return;
        }
        for (const session of this._sessions) {
            try {
                const newSession = await this._refreshSession(session.refreshToken);
                session.accessToken = newSession.access_token;
                session.refreshToken = newSession.refresh_token;
                session.expiresIn = newSession.expires_in;
            } catch (e: any) {
                if (e.message === 'Network failure') {
                    setTimeout(() => this._refreshSessions(), 60 * 1000);
                    return;
                }
            }
        }
        await this._secretStorage.store(secretStorageKey, JSON.stringify(this._sessions));
        this._onDidChangeSessions.fire({ added: [], removed: [], changed: this._sessions });
        setTimeout(() => this._refreshSessions(), this._sessions[0].expiresIn * 1000 * 2 / 3);
    }

    private async _refreshSession(refreshToken: string): Promise<AccessToken> {

        // eslint-disable-next-line @typescript-eslint/naming-convention
        const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: refreshToken, client_id: clientId }).toString();
        const response = await this._safeFetchWithRetry<AccessToken>(tokenEndpoint, {
            method: 'POST',
            // eslint-disable-next-line @typescript-eslint/naming-convention
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body,
        });
        return response;
    }

    //#endregion

    //#region network helpers

    private async _safeFetchWithRetry<T>(request: string | URL | Request, init?: RequestInit): Promise<T> {
        let retryCount = 0;
        const maxRetries = 3;
        const baseDelay = 1000;
        try {
            const response = await this._safeFetch(request, init);
            return response;
        } catch (error) {
            if (error instanceof NetworkError) {
                while (retryCount < maxRetries) {
                    const delay = baseDelay * Math.pow(2, retryCount);
                    await new Promise(resolve => setTimeout(resolve, delay));
                    try {
                        const response = await this._safeFetch(request, init);
                        return response;
                    } catch (error) {
                        if (error instanceof NetworkError) {
                            retryCount++;
                        } else {
                            throw error;
                        }
                    }
                }
                throw new NetworkError();
            } else {
                throw error;
            }
        }
    }

    private async _safeFetch(request: string | URL | Request, init?: RequestInit): Promise<any> {
        let response: Response;
        try {
            response = await Promise.race([
                fetch(request, init),
                new Promise<Response>((_, reject) => setTimeout(() => reject(new Error('Timeout')), 10000)),
            ]);
        } catch (error: any) {
            if (error.message === 'Timeout' || error.message === 'Network request failed') {
                throw new NetworkError();
            } else {
                throw error; // rethrow other unexpected errors
            }
        }
        if (!response.ok) {
            const text = await response.text();
            throw new ServerError(response.status, text);
        }
        try {
            const body = await response.json();
            return body;
        } catch (e) {
            throw new NetworkError();
        }
    }

    //#endregion
}

class NetworkError extends Error {
    constructor() {
        super('Network failure');
    }
}

class ServerError extends Error {
    constructor(readonly status: number, readonly reason: string) {
        super('Server failure');
    }
}
