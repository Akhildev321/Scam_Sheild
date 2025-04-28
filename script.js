// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/scamshield', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Models
const Report = require('./models/report');
const Blacklist = require('./models/blacklist');
const ScamType = require('./models/scamType');

// Sample scam keywords and patterns (would be in database in production)
const scamKeywords = ['urgent', 'account suspended', 'verify', 'free gift', 'click here', 'you have won'];
const scamPatterns = [
    { pattern: 'http://', description: 'Unsecure HTTP link' },
    { pattern: 'bit.ly', description: 'URL shortener used' }
];

// API Routes
// Text analysis endpoint
app.post('/api/analyze', (req, res) => {
    const { text } = req.body;
    
    if (!text) {
        return res.status(400).json({ error: 'Text is required' });
    }
    
    const indicators = [];
    let scamScore = 0;
    
    // Check for keywords
    const foundKeywords = scamKeywords.filter(keyword => 
        text.toLowerCase().includes(keyword.toLowerCase())
    );
    
    if (foundKeywords.length > 0) {
        scamScore += foundKeywords.length * 5;
        indicators.push({
            type: 'keywords',
            items: foundKeywords,
            description: `Found ${foundKeywords.length} scam-related keywords`
        });
    }
    
    // Check for patterns
    const foundPatterns = scamPatterns.filter(({ pattern }) => 
        text.includes(pattern)
    );
    
    if (foundPatterns.length > 0) {
        scamScore += foundPatterns.length * 10;
        indicators.push({
            type: 'patterns',
            items: foundPatterns.map(p => p.description),
            description: `Found ${foundPatterns.length} suspicious patterns`
        });
    }
    
    // Determine scam level
    let level;
    if (scamScore > 50) level = 'High';
    else if (scamScore > 20) level = 'Medium';
    else level = 'Low';
    
    res.json({
        score: Math.min(scamScore, 100),
        level,
        indicators,
        suggestions: getSuggestions(level)
    });
});

// Email verification endpoint
app.post('/api/verify/email', async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ error: 'Email is required' });
    }
    
    try {
        const isBlacklisted = await Blacklist.findOne({ type: 'email', value: email.toLowerCase() });
        const domain = email.split('@')[1] || '';
        
        res.json({
            email,
            isBlacklisted: !!isBlacklisted,
            domain
        });
    } catch (err) {
        console.error('Email verification error:', err);
        res.status(500).json({ error: 'Server error during email verification' });
    }
});

// Phone verification endpoint
app.post('/api/verify/phone', async (req, res) => {
    const { phone } = req.body;
    
    if (!phone) {
        return res.status(400).json({ error: 'Phone number is required' });
    }
    
    try {
        const isBlacklisted = await Blacklist.findOne({ type: 'phone', value: phone });
        const isInternational = !phone.startsWith('+1') && !phone.startsWith('1');
        
        res.json({
            phone,
            isBlacklisted: !!isBlacklisted,
            isInternational
        });
    } catch (err) {
        console.error('Phone verification error:', err);
        res.status(500).json({ error: 'Server error during phone verification' });
    }
});

// Report submission endpoint
app.post('/api/reports', async (req, res) => {
    const { type, description, contactInfo, date } = req.body;
    
    if (!type || !description) {
        return res.status(400).json({ error: 'Scam type and description are required' });
    }
    
    try {
        const report = new Report({
            type,
            description,
            contactInfo,
            date: date || new Date(),
            status: 'new',
            ipAddress: req.ip
        });
        
        await report.save();
        
        // Check if contact info should be blacklisted
        if (contactInfo) {
            await checkAndBlacklist(contactInfo);
        }
        
        res.status(201).json({ message: 'Report submitted successfully', report });
    } catch (err) {
        console.error('Report submission error:', err);
        res.status(500).json({ error: 'Server error during report submission' });
    }
});

// Get scam types for dropdown
app.get('/api/scam-types', async (req, res) => {
    try {
        const types = await ScamType.find({ active: true }).sort({ name: 1 });
        res.json(types);
    } catch (err) {
        console.error('Error fetching scam types:', err);
        res.status(500).json({ error: 'Server error fetching scam types' });
    }
});

// Helper functions
function getSuggestions(level) {
    const suggestions = {
        High: [
            'This message is highly suspicious and likely a scam.',
            'Do not click any links or provide any personal information.',
            'Delete the message and block the sender if possible.'
        ],
        Medium: [
            'This message shows several scam indicators.',
            'Be very cautious about any requests in the message.',
            'Verify the sender through official channels before responding.'
        ],
        Low: [
            'No obvious scam indicators found, but remain cautious.',
            'Always verify unexpected messages with the supposed sender.',
            'Be wary of any requests for personal information.'
        ]
    };
    
    return suggestions[level] || suggestions.Low;
}

async function checkAndBlacklist(contactInfo) {
    // Simple check for multiple reports of the same contact info
    const reportCount = await Report.countDocuments({ contactInfo });
    
    if (reportCount > 2) { // Threshold for auto-blacklisting
        const existing = await Blacklist.findOne({ value: contactInfo });
        
        if (!existing) {
            const type = contactInfo.includes('@') ? 'email' : 
                        /^[\d\+]+$/.test(contactInfo) ? 'phone' : 'other';
            
            const blacklistEntry = new Blacklist({
                type,
                value: contactInfo,
                source: 'auto',
                reports: reportCount
            });
            
            await blacklistEntry.save();
            console.log(`Auto-blacklisted ${type}: ${contactInfo}`);
        }
    }
}

// Serve frontend in production
if (process.env.NODE_ENV === 'production') {
    app.get('*', (req, res) => {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    });
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// models/report.js
const mongoose = require('mongoose');

const reportSchema = new mongoose.Schema({
    type: { type: String, required: true },
    description: { type: String, required: true },
    contactInfo: String,
    date: { type: Date, default: Date.now },
    status: { type: String, default: 'new', enum: ['new', 'reviewed', 'actioned'] },
    ipAddress: String,
    screenshots: [String]
}, { timestamps: true });

module.exports = mongoose.model('Report', reportSchema);

// models/blacklist.js
const mongoose = require('mongoose');

const blacklistSchema = new mongoose.Schema({
    type: { type: String, required: true, enum: ['email', 'phone', 'url', 'other'] },
    value: { type: String, required: true, unique: true },
    source: { type: String, enum: ['manual', 'auto', 'import'], default: 'manual' },
    reports: Number,
    notes: String
}, { timestamps: true });

module.exports = mongoose.model('Blacklist', blacklistSchema);

// models/scamType.js
const mongoose = require('mongoose');

const scamTypeSchema = new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    description: String,
    active: { type: Boolean, default: true },
    examples: [String],
    preventionTips: [String]
}, { timestamps: true });

module.exports = mongoose.model('ScamType', scamTypeSchema);