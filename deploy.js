// Auto-deploy using Node.js ssh2
import { Client } from 'ssh2';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const VPS_IP = '103.82.193.18';
const VPS_USER = 'root';
const VPS_PASS = '2wgqsmEecBHYyQbP';
const LOCAL_FILE = 'server.js';
const REMOTE_PATH = '/root/goxprint-driver-manager';

console.log('🚀 Starting deployment...\n');

const conn = new Client();

conn.on('ready', () => {
    console.log('✅ SSH connected!\n');

    // Step 1: Upload file
    console.log('[1/3] Uploading server.js...');

    conn.sftp((err, sftp) => {
        if (err) {
            console.error('❌ SFTP error:', err.message);
            conn.end();
            return;
        }

        const localPath = path.join(__dirname, LOCAL_FILE);
        const remotePath = `${REMOTE_PATH}/${LOCAL_FILE}`;

        const readStream = fs.createReadStream(localPath);
        const writeStream = sftp.createWriteStream(remotePath);

        writeStream.on('close', () => {
            console.log('✅ Upload successful!\n');

            // Step 2: Restart service
            console.log('[2/3] Restarting service...');

            const restartCmd = `cd ${REMOTE_PATH} && pm2 restart goxprint-driver-manager 2>/dev/null || (pkill -9 node && nohup npm start > server.log 2>&1 &)`;

            conn.exec(restartCmd, (err, stream) => {
                if (err) {
                    console.error('❌ Restart error:', err.message);
                    conn.end();
                    return;
                }

                let output = '';
                stream.on('data', (data) => {
                    output += data.toString();
                });

                stream.on('close', () => {
                    console.log('✅ Service restarted!');
                    if (output) console.log('Output:', output);
                    console.log('\n[3/3] Waiting for service to start...');

                    setTimeout(() => {
                        // Step 3: Verify
                        const healthCmd = 'curl -s http://localhost:3001/api/health';

                        conn.exec(healthCmd, (err, stream) => {
                            let healthOutput = '';

                            stream.on('data', (data) => {
                                healthOutput += data.toString();
                            });

                            stream.on('close', () => {
                                try {
                                    const health = JSON.parse(healthOutput);
                                    if (health.status === 'ok') {
                                        console.log('✅ Health check passed!');
                                        console.log('   Version:', health.version || 'N/A');
                                    } else {
                                        console.log('⚠️  Unexpected health status:', healthOutput);
                                    }
                                } catch (e) {
                                    console.log('⚠️  Health check response:', healthOutput.substring(0, 100));
                                }

                                console.log('\n🎉 Deployment complete!\n');
                                conn.end();
                            });
                        });
                    }, 3000); // Wait 3 seconds for service to start
                });
            });
        });

        writeStream.on('error', (err) => {
            console.error('❌ Upload failed:', err.message);
            conn.end();
        });

        readStream.pipe(writeStream);
    });

}).on('error', (err) => {
    console.error('❌ SSH connection error:', err.message);
    console.log('\nPlease check:');
    console.log('  - VPS is reachable');
    console.log('  - Credentials are correct');
    console.log('  - Firewall allows SSH');
}).connect({
    host: VPS_IP,
    port: 22,
    username: VPS_USER,
    password: VPS_PASS
});
