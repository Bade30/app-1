// server.js - Express server for the threat detection dashboard
const express = require('express');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve static files from 'public' directory

// In-memory database to store logs and alerts (in a real app, you'd use a proper database)
let logs = [];
let alerts = [];
let threatLevel = 'medium';
let stats = {
    threatsDetected: 42,
    activeAlerts: 16,
    securityScore: 98.5,
    criticalIssues: 3
};
let topThreats = [
    { name: 'Brute Force Login Attempts', count: 24, severity: 'error' },
    { name: 'SQL Injection Attempts', count: 16, severity: 'error' },
    { name: 'Unauthorized Port Scanning', count: 12, severity: 'warning' },
    { name: 'Unusual Data Exfiltration', count: 8, severity: 'warning' },
    { name: 'Unpatched System Vulnerabilities', count: 5, severity: 'normal' }
];

// Generate initial simulated data
generateInitialData();

// API Routes
app.get('/api/threat-level', (req, res) => {
    res.json({ 
        level: threatLevel, 
        lastUpdated: new Date().toISOString() 
    });
});

app.get('/api/alerts', (req, res) => {
    res.json(alerts);
});

app.get('/api/logs', (req, res) => {
    res.json(logs);
});

app.get('/api/stats', (req, res) => {
    res.json(stats);
});

app.get('/api/top-threats', (req, res) => {
    res.json(topThreats);
});

app.get('/api/dashboard-data', (req, res) => {
    // Endpoint that returns all data in one request
    res.json({
        threatLevel: { 
            level: threatLevel, 
            lastUpdated: new Date().toISOString() 
        },
        alerts: alerts,
        logs: logs,
        stats: stats,
        topThreats: topThreats
    });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    
    // Set up periodic log generation (simulate real-time logs)
    setInterval(generateNewLog, 5000); // Generate a new log every 5 seconds
    setInterval(updateThreatLevel, 30000); // Update threat level every 30 seconds
});

// Helper functions to generate simulated data
function generateInitialData() {
    // Generate initial logs
    const logTypes = [
        { message: "User authentication successful - username: {user}@example.com", severity: "normal" },
        { message: "Failed login attempt #{count} - username: {user}@example.com, IP: 192.168.1.{ip}", severity: "error" },
        { message: "HTTP 403 Forbidden - /admin/config.php accessed from IP: 192.168.1.{ip}", severity: "warning" },
        { message: "File download: {file} by user {user}@example.com", severity: "normal" },
        { message: "System scan completed - {count} critical issues, {count2} warnings", severity: "normal" },
        { message: "New device connected to network - MAC: 14:b3:1f:{mac}, IP: 192.168.1.{ip}", severity: "warning" },
        { message: "SQL Error: syntax error at line 1 near \"{sql}\" - Request blocked", severity: "error" },
        { message: "User session timeout - username: {user}@example.com", severity: "normal" },
        { message: "Firewall blocked outbound connection to suspicious IP: 78.{ip}.{ip2}.{ip3}", severity: "warning" }
    ];
    
    const users = ['admin', 'john', 'sarah', 'mike', 'jessica', 'robert', 'emily'];
    const files = ['quarterly_report.pdf', 'employee_data.xlsx', 'config.json', 'invoice_march.docx', 'project_plan.pptx'];
    const sqlTerms = ['DROP TABLE', 'UNION SELECT', 'OR 1=1', 'exec(', 'INTO OUTFILE'];
    
    // Generate 20 initial logs
    for (let i = 0; i < 20; i++) {
        const timestamp = new Date(Date.now() - (i * 3 * 60000)); // Spread logs over the last hour
        const logType = logTypes[Math.floor(Math.random() * logTypes.length)];
        
        let message = logType.message
            .replace('{user}', users[Math.floor(Math.random() * users.length)])
            .replace('{ip}', Math.floor(Math.random() * 254) + 1)
            .replace('{ip2}', Math.floor(Math.random() * 254) + 1)
            .replace('{ip3}', Math.floor(Math.random() * 254) + 1)
            .replace('{file}', files[Math.floor(Math.random() * files.length)])
            .replace('{count}', Math.floor(Math.random() * 10) + 1)
            .replace('{count2}', Math.floor(Math.random() * 20) + 1)
            .replace('{mac}', Math.floor(Math.random() * 999).toString().padStart(3, '0'))
            .replace('{sql}', sqlTerms[Math.floor(Math.random() * sqlTerms.length)]);
        
        const log = {
            id: Date.now() - i,
            timestamp: timestamp.toISOString(),
            message: message,
            severity: logType.severity
        };
        
        logs.push(log);
        
        // Add some logs as alerts (higher severity logs)
        if (logType.severity === 'error' || (logType.severity === 'warning' && Math.random() > 0.5)) {
            alerts.push(log);
        }
    }
    
    // Sort logs by timestamp (newest first)
    logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    alerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    // Keep only the 10 most recent alerts
    alerts = alerts.slice(0, 10);
}

function generateNewLog() {
    const logTypes = [
        { message: "User authentication successful - username: {user}@example.com", severity: "normal", probability: 0.3 },
        { message: "Failed login attempt - username: {user}@example.com, IP: 192.168.1.{ip}", severity: "error", probability: 0.1 },
        { message: "HTTP 403 Forbidden - /admin/config.php accessed from IP: 192.168.1.{ip}", severity: "warning", probability: 0.1 },
        { message: "File download: {file} by user {user}@example.com", severity: "normal", probability: 0.2 },
        { message: "New device connected to network - MAC: 14:b3:1f:{mac}, IP: 192.168.1.{ip}", severity: "warning", probability: 0.05 },
        { message: "SQL Error: syntax error at line 1 near \"{sql}\" - Request blocked", severity: "error", probability: 0.05 },
        { message: "User session timeout - username: {user}@example.com", severity: "normal", probability: 0.15 },
        { message: "Firewall blocked outbound connection to suspicious IP: 78.{ip}.{ip2}.{ip3}", severity: "warning", probability: 0.05 }
    ];
    
    // Weighted random selection of log type
    let random = Math.random();
    let cumulativeProbability = 0;
    let selectedLogType;
    
    for (const logType of logTypes) {
        cumulativeProbability += logType.probability;
        if (random <= cumulativeProbability) {
            selectedLogType = logType;
            break;
        }
    }
    
    // If somehow we didn't select a log type, use the first one
    if (!selectedLogType) {
        selectedLogType = logTypes[0];
    }
    
    const users = ['admin', 'john', 'sarah', 'mike', 'jessica', 'robert', 'emily'];
    const files = ['quarterly_report.pdf', 'employee_data.xlsx', 'config.json', 'invoice_march.docx', 'project_plan.pptx'];
    const sqlTerms = ['DROP TABLE', 'UNION SELECT', 'OR 1=1', 'exec(', 'INTO OUTFILE'];
    
    let message = selectedLogType.message
        .replace('{user}', users[Math.floor(Math.random() * users.length)])
        .replace('{ip}', Math.floor(Math.random() * 254) + 1)
        .replace('{ip2}', Math.floor(Math.random() * 254) + 1)
        .replace('{ip3}', Math.floor(Math.random() * 254) + 1)
        .replace('{file}', files[Math.floor(Math.random() * files.length)])
        .replace('{count}', Math.floor(Math.random() * 10) + 1)
        .replace('{count2}', Math.floor(Math.random() * 20) + 1)
        .replace('{mac}', Math.floor(Math.random() * 999).toString().padStart(3, '0'))
        .replace('{sql}', sqlTerms[Math.floor(Math.random() * sqlTerms.length)]);
    
    const newLog = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        message: message,
        severity: selectedLogType.severity
    };
    
    // Add to logs
    logs.unshift(newLog);
    
    // Limit logs to 100 entries
    if (logs.length > 100) {
        logs = logs.slice(0, 100);
    }
    
    // Add to alerts if it's a warning or error
    if (selectedLogType.severity === 'error' || selectedLogType.severity === 'warning') {
        alerts.unshift(newLog);
        
        // Update stats
        stats.activeAlerts++;
        if (selectedLogType.severity === 'error') {
            stats.threatsDetected++;
            
            // Randomly update top threats
            if (Math.random() > 0.7) {
                const threatIndex = Math.floor(Math.random() * topThreats.length);
                topThreats[threatIndex].count++;
            }
        }
        
        // Limit alerts to 20 entries
        if (alerts.length > 20) {
            alerts = alerts.slice(0, 20);
        }
    }
    
    // Randomly update security score occasionally
    if (Math.random() > 0.9) {
        const change = (Math.random() - 0.5) * 0.5; // Small random change
        stats.securityScore = Math.max(0, Math.min(100, stats.securityScore + change)).toFixed(1);
    }
}

function updateThreatLevel() {
    const levels = ['low', 'medium', 'high', 'critical'];
    const weights = [0.4, 0.3, 0.2, 0.1]; // Higher probability for lower threat levels
    
    let random = Math.random();
    let cumulativeProbability = 0;
    
    for (let i = 0; i < levels.length; i++) {
        cumulativeProbability += weights[i];
        if (random <= cumulativeProbability) {
            threatLevel = levels[i];
            
            // Update critical issues count based on threat level
            if (threatLevel === 'critical') {
                stats.criticalIssues = Math.floor(Math.random() * 5) + 5; // 5-10
            } else if (threatLevel === 'high') {
                stats.criticalIssues = Math.floor(Math.random() * 4) + 1; // 1-5
            } else {
                stats.criticalIssues = Math.floor(Math.random() * 3); // 0-3
            }
            
            break;
        }
    }
}