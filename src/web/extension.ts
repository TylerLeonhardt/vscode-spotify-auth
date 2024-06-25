import { authentication, commands, Disposable, env, ExtensionContext, l10n, Uri, window } from 'vscode';
import { SpotifyAuthProvider } from './authProvider';
import { helloCommand } from './commands';

export async function activate(context: ExtensionContext) {

	const authProvider = new SpotifyAuthProvider(context.secrets);
	await authProvider.initialize();
	context.subscriptions.push(Disposable.from(
		authProvider,
		authentication.registerAuthenticationProvider(SpotifyAuthProvider.id, SpotifyAuthProvider.label, authProvider),
		// Example usage of the authentication provider
		commands.registerCommand('spotify-auth.hello', helloCommand)
	));
}

export function deactivate() {}
