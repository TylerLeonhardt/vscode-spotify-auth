import { authentication, commands, Disposable, env, ExtensionContext, l10n, Uri, window } from 'vscode';
import { SpotifyAuthenticationSession, SpotifyAuthProvider } from './authProvider';
import { SpotifyApi } from '@spotify/web-api-ts-sdk';

export async function activate(context: ExtensionContext) {

	const authProvider = new SpotifyAuthProvider(context.secrets);
	await authProvider.initialize();
	context.subscriptions.push(Disposable.from(
		authProvider,
		authentication.registerAuthenticationProvider(SpotifyAuthProvider.id, SpotifyAuthProvider.label, authProvider),
		// Example usage of the authentication provider
		commands.registerCommand('spotify-auth.hello', async () => {
			const session = await authentication.getSession('spotify', ['user-read-private', 'user-read-email'], { createIfNone: true}) as SpotifyAuthenticationSession;
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
		})
	));
}

export function deactivate() {}
