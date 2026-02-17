import { GatekeepServer } from './server.js';
import { initializeOAuth2Client } from './upstream/auth/client.js';
import { AuthServer } from './upstream/auth/server.js';
import type { ServerConfig } from './upstream/config/TransportConfig.js';

async function main() {
  try {
    const config: ServerConfig = {
      transport: { type: 'stdio' },
    };

    // Parse --enable-tools from args
    const args = process.argv.slice(2);
    const enableToolsIdx = args.indexOf('--enable-tools');
    if (enableToolsIdx >= 0 && args[enableToolsIdx + 1]) {
      config.enabledTools = args[enableToolsIdx + 1].split(',');
    }

    const server = new GatekeepServer(config);
    await server.initialize();
    await server.start();
  } catch (error: unknown) {
    process.stderr.write(
      `[Gatekeep] Failed to start: ${error instanceof Error ? error.message : error}\n`,
    );
    process.exit(1);
  }
}

async function runAuth(accountId?: string): Promise<void> {
  if (accountId) {
    if (!/^[a-z0-9_-]{1,64}$/.test(accountId)) {
      process.stderr.write('Invalid account ID.\n');
      process.exit(1);
    }
    process.env.GOOGLE_ACCOUNT_MODE = accountId;
  }

  try {
    const oauth2Client = await initializeOAuth2Client();
    const authServerInstance = new AuthServer(oauth2Client);
    const success = await authServerInstance.start(true);

    if (!success && !authServerInstance.authCompletedSuccessfully) {
      process.stderr.write("Authentication failed.\n");
      process.exit(1);
    } else if (authServerInstance.authCompletedSuccessfully) {
      process.stderr.write("Authentication successful.\n");
      process.exit(0);
    }

    process.stderr.write("Complete authentication in your browser...\n");

    const intervalId = setInterval(async () => {
      if (authServerInstance.authCompletedSuccessfully) {
        clearInterval(intervalId);
        await authServerInstance.stop();
        process.stderr.write("Authentication completed!\n");
        process.exit(0);
      }
    }, 1000);
  } catch (error) {
    process.stderr.write(`Authentication failed: ${error}\n`);
    process.exit(1);
  }
}

// CLI
const cliArgs = process.argv.slice(2).filter(a => !a.startsWith('--'));
const command = cliArgs[0];

switch (command) {
  case 'auth':
    runAuth(cliArgs[1]);
    break;
  case 'start':
  case undefined:
    main();
    break;
  case 'version':
    process.stdout.write('Gatekeep v0.1.0\n');
    break;
  case 'help':
    process.stdout.write(`Gatekeep v0.1.0 - Calendar Security Proxy for Claude Desktop

Usage:
  gatekeep [command]

Commands:
  auth [account-id]  Run OAuth authentication flow
  start              Start the MCP server (default)
  version            Show version
  help               Show this help
`);
    break;
  default:
    process.stderr.write(`Unknown command: ${command}\n`);
    process.exit(1);
}
