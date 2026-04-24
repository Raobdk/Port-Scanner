const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const net = require('net');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());

// Serve static frontend files
app.use(express.static(__dirname));

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Utility to scan a single port
function scanPort(port, host, timeout) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let status = 'closed';
    let banner = '';
    
    socket.setTimeout(timeout);

    socket.on('connect', () => {
      status = 'open';
      // If connected, try to grab a banner
      socket.write("HEAD / HTTP/1.0\r\n\r\n");
    });

    socket.on('data', (data) => {
      banner += data.toString();
      // Only keep the first 100 characters of banner
      if(banner.length > 100) banner = banner.substring(0, 100) + '...';
      socket.destroy();
    });

    socket.on('timeout', () => {
      if(status !== 'open') status = 'filtered';
      socket.destroy();
    });

    socket.on('error', (err) => {
      if (err.code === 'ECONNREFUSED') status = 'closed';
      else status = 'filtered';
    });

    socket.on('close', () => {
      resolve({ port, status, banner: banner.trim().replace(/\n/g, ' ') });
    });

    socket.connect(port, host);
  });
}

io.on('connection', (socket) => {
  console.log('Frontend connected:', socket.id);

  socket.on('start_scan', async (data) => {
    const { target, ports, timeout = 2000 } = data;
    
    console.log(`Starting scan on ${target} for ${ports.length} ports...`);
    
    socket.emit('scan_started', { target, total: ports.length });

    let scanned = 0;
    
    // Scan in chunks to avoid opening too many sockets at once
    const concurrency = 50; 
    
    for (let i = 0; i < ports.length; i += concurrency) {
      const chunk = ports.slice(i, i + concurrency);
      
      // We wait for the chunk to finish
      const promises = chunk.map(port => scanPort(port, target, timeout).then(result => {
        scanned++;
        socket.emit('port_result', {
          ...result,
          scanned,
          total: ports.length
        });
      }));
      
      await Promise.all(promises);
    }
    
    console.log('Scan complete for', target);
    socket.emit('scan_complete', { target });
  });
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`Nexus Scanner Live on port ${PORT}`);
});
