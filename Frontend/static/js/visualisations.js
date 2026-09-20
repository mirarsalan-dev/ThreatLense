// visualisations.js
// Handles Threat DNA (Radar) and Threat Graph (Node Network)

window.renderThreatDNA = function(data) {
    const ctx = document.getElementById('threatDnaChart').getContext('2d');
    
    // Destroy previous chart if exists
    if (window.threatDnaChartInstance) {
        window.threatDnaChartInstance.destroy();
    }
    
    // Extract real values from scan features, normalized to 0-100 scale
    // If features are unavailable, default to 0 rather than random (Real Data Only policy)
    let features = data.ml_analysis && data.ml_analysis.features ? data.ml_analysis.features : {};
    
    // Normalize string lengths and counts into roughly 0-100 scales based on heuristic max values
    let structure = Math.min((features.url_length || 0) + (features.path_length || 0), 100);
    let domain = Math.min((features.hostname_length || 0) * 2 + (features.subdomain_count || 0) * 10, 100);
    let obfuscation = Math.min((features.special_chars_count || 0) * 5 + (features.entropy || 0) * 10, 100);
    let content = data.risk_score || 0; 
    let reputation = data.verdict === 'phishing' || data.verdict === 'MALICIOUS' ? 90 : 10;
    let network = data.osint && data.osint.modules && data.osint.modules.dns && data.osint.modules.dns.records && data.osint.modules.dns.records.A ? 50 : 0;

    const chartData = {
        labels: ['URL STRUCTURE', 'DOMAIN', 'OBFUSCATION', 'CONTENT', 'REPUTATION', 'NETWORK'],
        datasets: [{
            label: 'Threat Signature',
            data: [structure, domain, obfuscation, content, reputation, network],
            backgroundColor: 'rgba(88, 166, 255, 0.2)', // Accent Cyan with opacity
            borderColor: '#58a6ff',
            pointBackgroundColor: '#58a6ff',
            pointBorderColor: '#fff',
            pointHoverBackgroundColor: '#fff',
            pointHoverBorderColor: '#58a6ff'
        }]
    };

    const config = {
        type: 'radar',
        data: chartData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                r: {
                    angleLines: { color: 'rgba(255,255,255,0.1)' },
                    grid: { color: 'rgba(255,255,255,0.1)' },
                    pointLabels: {
                        color: '#8b949e',
                        font: { family: "'JetBrains Mono', monospace", size: 10 }
                    },
                    ticks: { display: false, min: 0, max: 100 }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    };

    window.threatDnaChartInstance = new Chart(ctx, config);
};


window.renderThreatGraph = function(data) {
    const container = document.getElementById('threat-network-graph');
    
    let hostname = "UNKNOWN";
    try { hostname = new URL(data.url).hostname; } catch(e) {}
    
    // Create base nodes
    const nodesArray = [
        { id: 1, label: 'TARGET\n' + data.url.substring(0,25) + (data.url.length > 25 ? '...' : ''), group: 'target', font: { color: '#fff' } },
        { id: 2, label: 'DOMAIN\n' + hostname, group: 'domain' }
    ];
    
    const edgesArray = [
        { from: 1, to: 2 }
    ];
    
    let nextNodeId = 3;
    
    // Dynamically add real DNS A records
    if(data.osint && data.osint.modules && data.osint.modules.dns && data.osint.modules.dns.records && data.osint.modules.dns.records.A) {
        data.osint.modules.dns.records.A.forEach(ip => {
            let id = nextNodeId++;
            nodesArray.push({ id: id, label: 'IP\n' + ip, group: 'ip' });
            edgesArray.push({ from: 2, to: id });
        });
    }

    // Dynamically add real SSL info
    if(data.osint && data.osint.modules && data.osint.modules.ssl && data.osint.modules.ssl.details && data.osint.modules.ssl.details.issuer) {
        let issuer = data.osint.modules.ssl.details.issuer;
        let id = nextNodeId++;
        nodesArray.push({ id: id, label: 'SSL\n' + issuer.substring(0, 15), group: 'ssl' });
        edgesArray.push({ from: 2, to: id });
    }

    if(data.verdict === 'phishing' || data.verdict === 'MALICIOUS') {
        let id = nextNodeId++;
        nodesArray.push({ id: id, label: 'IOC\nMALICIOUS PATTERN', group: 'threat' });
        edgesArray.push({ from: 1, to: id, color: { color: '#f85149' }, dashes: true });
    }

    const nodes = new vis.DataSet(nodesArray);
    const edges = new vis.DataSet(edgesArray);

    const graphData = { nodes: nodes, edges: edges };

    const options = {
        nodes: {
            shape: 'dot',
            size: 20,
            font: { face: "'JetBrains Mono', monospace", size: 12, color: '#c9d1d9' },
            borderWidth: 2
        },
        edges: {
            width: 1.5,
            color: { color: '#30363d' },
            smooth: { type: 'continuous' }
        },
        groups: {
            target: { color: { background: '#161b22', border: '#58a6ff' } },
            domain: { color: { background: '#161b22', border: '#d29922' } },
            ip: { color: { background: '#161b22', border: '#8b949e' } },
            dns: { color: { background: '#161b22', border: '#8b949e' } },
            ssl: { color: { background: '#161b22', border: '#3fb950' } },
            geo: { color: { background: '#161b22', border: '#8b949e' } },
            threat: { color: { background: '#200505', border: '#f85149' } }
        },
        physics: {
            barnesHut: { gravitationalConstant: -3000, centralGravity: 0.3, springLength: 95 },
            stabilization: { iterations: 150 }
        },
        interaction: { hover: true, tooltipDelay: 200 }
    };

    new vis.Network(container, graphData, options);
};
