# Spotify Authentication

Provides a VS Code Authentication Provider for Spotify 🎶

## Usage

Add this extension to your package.json:

```json
"extensionDependencies": [
    "TylerLeonhardt.vscode-spotify-auth"
],
```

Then, in your extension, you can use the built-in auth API to authenticate with Spotify:

```ts
import * as vscode from 'vscode';

const exampleScopes = ['user-read-playback-state', 'user-modify-playback-state'];
const session = await vscode.authentication.getSession('spotify', exampleScopes, options);
```

This returns an `AuthenticationSession` object which actually includes a refresh token property as well:

```ts
export interface SpotifyAuthenticationSession extends AuthenticationSession {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
}
```

You can turn this into the  `@spotify/web-api-ts-sdk`'s `AccessToken` which looks like this:
```ts
export interface AccessToken {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token: string;
    expires?: number;
}
```
