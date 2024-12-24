document.addEventListener('DOMContentLoaded', () => {
  // Initialize dark mode from localStorage
  const darkMode = localStorage.getItem('darkMode') === 'true';
  if (darkMode) {
    document.documentElement.setAttribute('data-theme', 'dark');
  }

  // Dark mode toggle
  document.getElementById('toggle-dark-mode').addEventListener('click', () => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    document.documentElement.setAttribute('data-theme', isDark ? 'light' : 'dark');
    localStorage.setItem('darkMode', !isDark);
    updateCytoscapeStyles();
  });

  // Initialize WebSocket connection
  const ws = new WebSocket(`ws://${window.location.host}`);
  
  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    if (data.type === 'update') {
      updateTopology(data.nodes, data.edges);
    }
  };

  // Add modal elements to the DOM
  const modalHtml = `
    <div class="backdrop"></div>
    <div class="node-modal">
      <span class="node-modal-close">&times;</span>
      <h2>Node Details</h2>
      <div class="node-modal-content"></div>
    </div>
  `;
  document.body.insertAdjacentHTML('beforeend', modalHtml);

  // Modal elements
  const modal = document.querySelector('.node-modal');
  const backdrop = document.querySelector('.backdrop');
  const modalContent = document.querySelector('.node-modal-content');
  const closeBtn = document.querySelector('.node-modal-close');
  const contextMenu = document.querySelector('.context-menu');

  // Close modal function
  const closeModal = () => {
    modal.style.display = 'none';
    backdrop.style.display = 'none';
  };

  // Event listeners for modal
  closeBtn.addEventListener('click', closeModal);
  backdrop.addEventListener('click', closeModal);

  // Cytoscape styles based on theme
  const getCytoscapeStyles = () => {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    return [
      {
        selector: 'node',
        style: {
          'background-color': isDark ? '#2980b9' : '#2ecc71',
          'label': 'data(label)',
          'color': '#fff',
          'text-valign': 'center',
          'text-halign': 'center',
          'text-outline-width': 2,
          'text-outline-color': isDark ? '#2c3e50' : '#27ae60',
          'font-size': '14px',
          'text-wrap': 'wrap',
          'text-max-width': '100px',
          'width': 60,
          'height': 60,
          'border-width': 3,
          'border-color': isDark ? '#2c3e50' : '#27ae60'
        }
      },
      {
        selector: 'node:selected',
        style: {
          'background-color': isDark ? '#3498db' : '#3498db',
          'border-color': isDark ? '#2980b9' : '#2980b9',
          'text-outline-color': isDark ? '#2980b9' : '#2980b9'
        }
      },
      {
        selector: 'edge',
        style: {
          'width': 3,
          'line-color': isDark ? '#7f8c8d' : '#95a5a6',
          'target-arrow-color': isDark ? '#7f8c8d' : '#95a5a6',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'opacity': 0.7
        }
      },
      {
        selector: '.highlighted',
        style: {
          'border-color': isDark ? '#d35400' : '#f39c12',
          'border-width': 4
        }
      },
      {
        selector: '.isolated',
        style: {
          'opacity': 0.3
        }
      }
    ];
  };

  // Function to update Cytoscape styles
  const updateCytoscapeStyles = () => {
    const newStyles = getCytoscapeStyles();
    cy.style(newStyles);
  };

  // Initialize the topology map
  const cy = cytoscape({
    container: document.getElementById('cy'),
    style: getCytoscapeStyles()
  });

  // Context menu handling
  let selectedNode = null;

  cy.on('cxttap', 'node', (event) => {
    event.preventDefault();
    selectedNode = event.target;
    
    const position = event.renderedPosition;
    contextMenu.style.left = position.x + 'px';
    contextMenu.style.top = position.y + 'px';
    contextMenu.style.display = 'block';
  });

  document.addEventListener('click', () => {
    contextMenu.style.display = 'none';
  });

  // Context menu actions
  document.getElementById('highlight-connections').addEventListener('click', () => {
    if (!selectedNode) return;
    
    cy.elements().removeClass('highlighted');
    const connectedEdges = selectedNode.connectedEdges();
    const connectedNodes = selectedNode.neighborhood('node');
    
    connectedEdges.addClass('highlighted');
    connectedNodes.addClass('highlighted');
    selectedNode.addClass('highlighted');
  });

  document.getElementById('isolate-node').addEventListener('click', () => {
    if (!selectedNode) return;
    
    cy.elements().addClass('isolated');
    const connectedEdges = selectedNode.connectedEdges();
    const connectedNodes = selectedNode.neighborhood('node');
    
    selectedNode.removeClass('isolated');
    connectedEdges.removeClass('isolated');
    connectedNodes.removeClass('isolated');
  });

  document.getElementById('reset-view').addEventListener('click', () => {
    cy.elements().removeClass('highlighted isolated');
    cy.fit();
  });

  // Clustering toggle
  let isClustered = false;
  document.getElementById('toggle-clustering').addEventListener('click', () => {
    if (isClustered) {
      cy.layout({ name: 'concentric', minNodeSpacing: 100 }).run();
    } else {
      cy.layout({ 
        name: 'cose',
        idealEdgeLength: 100,
        nodeOverlap: 20,
        refresh: 20,
        fit: true,
        padding: 30,
        randomize: false,
        componentSpacing: 100,
        nodeRepulsion: 400000,
        edgeElasticity: 100,
        nestingFactor: 5,
        gravity: 80,
        numIter: 1000,
        initialTemp: 200,
        coolingFactor: 0.95,
        minTemp: 1.0
      }).run();
    }
    isClustered = !isClustered;
  });

  // Export functionality
  document.getElementById('export-image').addEventListener('click', () => {
    const png64 = cy.png();
    const link = document.createElement('a');
    link.download = 'topology.png';
    link.href = png64;
    link.click();
  });

  document.getElementById('export-json').addEventListener('click', () => {
    const json = cy.json();
    const blob = new Blob([JSON.stringify(json, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.download = 'topology.json';
    link.href = url;
    link.click();
    URL.revokeObjectURL(url);
  });

  // Filtering functionality
  const applyFilters = () => {
    const ip = document.getElementById('ip-filter').value;
    const service = document.getElementById('service-filter').value;
    const port = document.getElementById('port-filter').value;
    const protocol = document.getElementById('protocol-filter').value;

    const params = new URLSearchParams();
    if (ip) params.append('ip', ip);
    if (service) params.append('service', service);
    if (port) params.append('port', port);
    if (protocol) params.append('protocol', protocol);

    fetch(`/api/topology?${params.toString()}`)
      .then(response => response.json())
      .then(data => updateTopology(data.nodes, data.edges));
  };

  document.getElementById('apply-filters').addEventListener('click', applyFilters);
  document.getElementById('reset-filters').addEventListener('click', () => {
    document.getElementById('ip-filter').value = '';
    document.getElementById('service-filter').value = '';
    document.getElementById('port-filter').value = '';
    document.getElementById('protocol-filter').value = '';
    applyFilters();
  });

  // Dynamic node styling based on port states
  const updateNodeStyles = () => {
    cy.nodes().forEach(node => {
      const ports = node.data('ports');
      if (!ports) return;

      const hasOpenPorts = ports.some(port => port.status.toLowerCase() === 'open');
      const hasClosedPorts = ports.some(port => port.status.toLowerCase() === 'closed');
      
      const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
      if (hasOpenPorts && hasClosedPorts) {
        node.style({
          'background-color': isDark ? '#d35400' : '#f1c40f',
          'border-color': isDark ? '#e67e22' : '#f39c12'
        });
      } else if (hasOpenPorts) {
        node.style({
          'background-color': isDark ? '#27ae60' : '#2ecc71',
          'border-color': isDark ? '#2ecc71' : '#27ae60'
        });
      } else {
        node.style({
          'background-color': isDark ? '#c0392b' : '#e74c3c',
          'border-color': isDark ? '#e74c3c' : '#c0392b'
        });
      }
    });
  };

  // Function to update topology
  const updateTopology = (nodes, edges) => {
    cy.elements().remove();
    
    const elements = nodes.map(node => ({
      group: 'nodes',
      data: {
        id: node.id,
        label: node.label,
        ports: node.ports,
        os: node.os,
        country: node.country,
        city: node.city,
        isp: node.isp,
        position: node.position
      }
    }));

    elements.push(...edges.map(edge => ({
      group: 'edges',
      data: edge
    })));

    cy.add(elements);
    cy.layout({ name: 'concentric', minNodeSpacing: 100 }).run();
    updateNodeStyles();
  };

  // Initial data fetch
  fetch('/api/topology')
    .then(response => response.json())
    .then(data => {
      updateTopology(data.nodes, data.edges);

      // Click event on nodes
      cy.on('tap', 'node', event => {
        const node = event.target;
        const data = node.data();
        
        let portsHtml = '<div class="ports-list">';
        data.ports.forEach(port => {
          portsHtml += `
            <div class="port-item">
              <span class="port-number">${port.number}</span>
              <span class="port-protocol">${port.protocol}</span>
              <span class="port-service">${port.service}</span>
              <span class="port-status ${port.status.toLowerCase()}">${port.status}</span>
            </div>
          `;
        });
        portsHtml += '</div>';
        
        modalContent.innerHTML = `
          <div class="node-details">
            <div class="detail-section">
              <h3>Network Information</h3>
              <p><strong>IP Address:</strong> ${data.id}</p>
              <p><strong>Operating System:</strong> ${data.os}</p>
              <p><strong>ISP:</strong> ${data.isp}</p>
            </div>
            
            <div class="detail-section">
              <h3>Location</h3>
              <p><strong>Country:</strong> ${data.country}</p>
              <p><strong>City:</strong> ${data.city}</p>
              <p><strong>Coordinates:</strong> ${data.position.latitude}, ${data.position.longitude}</p>
            </div>
            
            <div class="detail-section">
              <h3>Open Ports</h3>
              ${portsHtml}
            </div>
          </div>
        `;

        modal.style.display = 'block';
        backdrop.style.display = 'block';
      });

      // Double click to zoom to a node
      cy.on('dbltap', 'node', event => {
        const node = event.target;
        cy.animate({
          fit: {
            eles: node,
            padding: 50
          },
          duration: 500
        });
      });
    })
    .catch(err => console.error('Error fetching topology data:', err));
});
