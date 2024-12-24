const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const WebSocket = require('ws');
const http = require('http');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = 3000;

// Serve static files from public and views directories
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(path.join(__dirname, 'views')));

// Serve the map page
app.get('/map', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'map.html'));
});

// Serve the topology page
app.get('/topology', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'topology.html'));
});

// API to fetch scan data
app.get('/api/scan-results', (req, res) => {
  const dbPath = path.join(__dirname, 'data', 'scan_results.db');
  console.log('Attempting to connect to database at:', dbPath);
  
  const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
      console.error('Database connection error:', err);
      return res.status(500).json({ error: 'Database connection failed' });
    }
    console.log('Successfully connected to database');
  });

  db.all('SELECT * FROM scan_results', [], (err, rows) => {
    if (err) {
      console.error('Query error:', err);
      res.status(500).json({ error: err.message });
    } else {
      console.log('Query successful, found rows:', rows?.length);
      res.json(rows);
    }
    db.close((err) => {
      if (err) {
        console.error('Error closing database:', err);
      }
    });
  });
});

// API to fetch topology data with filtering support
app.get('/api/topology', (req, res) => {
  const { ip, service, port, protocol } = req.query;
  const dbPath = path.join(__dirname, 'data', 'scan_results.db');
  const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
      console.error('Database connection error:', err);
      return res.status(500).json({ error: 'Database connection failed' });
    }
  });

  let query = `
    SELECT DISTINCT 
      ip_address,
      GROUP_CONCAT(port || ':' || protocol || ':' || service || ':' || scan_status) as ports,
      os,
      hostname,
      country,
      city,
      isp,
      latitude,
      longitude
    FROM scan_results 
    GROUP BY ip_address
  `;

  const params = [];
  const conditions = [];

  if (ip) {
    conditions.push('ip_address LIKE ?');
    params.push(`%${ip}%`);
  }
  if (service) {
    conditions.push('service LIKE ?');
    params.push(`%${service}%`);
  }
  if (port) {
    conditions.push('port = ?');
    params.push(port);
  }
  if (protocol) {
    conditions.push('protocol = ?');
    params.push(protocol);
  }

  if (conditions.length > 0) {
    query = query.replace('GROUP BY ip_address', `WHERE ${conditions.join(' AND ')} GROUP BY ip_address`);
  }

  db.all(query, params, (err, rows) => {
    if (err) {
      console.error('Query error:', err);
      res.status(500).json({ error: err.message });
      return;
    }

    // Transform data for topology visualization
    const nodes = rows.map(row => ({
      id: row.ip_address,
      label: row.hostname !== 'Unknown' ? `${row.hostname}\n${row.ip_address}` : row.ip_address,
      ports: row.ports.split(',').map(port => {
        const [number, protocol, service, status] = port.split(':');
        return { number, protocol, service, status };
      }),
      os: row.os,
      country: row.country,
      city: row.city,
      isp: row.isp,
      position: {
        latitude: row.latitude,
        longitude: row.longitude
      }
    }));

    // Create edges between nodes in the same network
    const edges = [];
    nodes.forEach((node, i) => {
      const nodeNetwork = node.id.split('.').slice(0, 3).join('.');
      nodes.slice(i + 1).forEach(otherNode => {
        const otherNetwork = otherNode.id.split('.').slice(0, 3).join('.');
        if (nodeNetwork === otherNetwork) {
          edges.push({
            id: `${node.id}-${otherNode.id}`,
            source: node.id,
            target: otherNode.id
          });
        }
      });
    });

    res.json({ nodes, edges });
    db.close((err) => {
      if (err) {
        console.error('Error closing database:', err);
      }
    });
  });
});

// WebSocket connection handling
wss.on('connection', (ws) => {
  console.log('New WebSocket connection established');

  // Send initial connection message
  ws.send(JSON.stringify({ type: 'connection', message: 'Connected to topology server' }));

  // Handle incoming messages
  ws.on('message', (message) => {
    const data = JSON.parse(message);
    
    // Broadcast updates to all connected clients
    if (data.type === 'update') {
      wss.clients.forEach((client) => {
        if (client !== ws && client.readyState === WebSocket.OPEN) {
          client.send(JSON.stringify(data));
        }
      });
    }
  });
});

// Start the server
server.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
  console.log('WebSocket server is running');
});
