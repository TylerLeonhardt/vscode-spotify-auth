import { authentication, env, l10n, Uri, window } from "vscode";
import { SpotifyAuthenticationSession } from "./authProvider";
import { SpotifyApi } from "@spotify/web-api-ts-sdk";

export async function helloCommand() {
    const session = await authentication.getSession('spotify', ['user-read-private', 'user-read-email'], { createIfNone: true }) as SpotifyAuthenticationSession;
    const client = SpotifyApi.withAccessToken(
        session.clientId,
        {
            // eslint-disable-next-line @typescript-eslint/naming-convention
            access_token: session.accessToken,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            token_type: 'Bearer',
            // eslint-disable-next-line @typescript-eslint/naming-convention
            refresh_token: session.refreshToken,
            // eslint-disable-next-line @typescript-eslint/naming-convention
            expires_in: session.expiresIn,
        }
    );
    const profile = await client.currentUser.profile();
    const open = l10n.t('Open Profile');
    const result = await window.showInformationMessage(`Hello, ${profile.display_name}!`, open);
    if (result === open) {
        await env.openExternal(Uri.parse(profile.external_urls.spotify));
    }
}
