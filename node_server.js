const http = require('http');

const PORT = 3000; // Your Rust LB should point to this port

const server = http.createServer((req, res) => {
    let body = '';

    // Collect the payload (body)
    req.on('data', chunk => {
        body += chunk.toString();
    });

    req.on('end', () => {
        console.log('--- NEW REQUEST RECEIVED ---');
        console.log(`[Time]: ${new Date().toISOString()}`);
        console.log(`[Method]: ${req.method}`);
        console.log(`[URL]: ${req.url}`);

        // Print all headers
        console.log('[Headers]:');
        console.table(req.headers);

        // Print payload if it exists
        if (body) {
            console.log(`[Payload]: ${body}`);
        } else {
            console.log('[Payload]: (Empty)');
        }

        console.log('--- END OF REQUEST ---\n');

        // Send a response back to Phalanx
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: "success",
            message: `Hello from Node.js! You requested ${req.url}`,
            received_headers: req.headers
        }));
    });
});

server.listen(PORT, () => {
    console.log(`Backend server is running on http://localhost:${PORT}`);
    console.log(`Configure Phalanx to use "localhost:${PORT}" as the upstream.`);
});