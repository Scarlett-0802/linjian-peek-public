// Run manually only when ready to configure Render. Output is a PRIVATE SECRET.
// Never redirect into the repository, commit it, or paste it into chat.
import { generateKeyPairSync, randomUUID } from 'node:crypto';
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const key = { ...privateKey.export({ format: 'jwk' }), kid: randomUUID(), alg: 'RS256', use: 'sig' };
process.stdout.write(JSON.stringify({ keys: [key] }) + '\n');
