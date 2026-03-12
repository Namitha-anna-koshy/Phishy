// ============ INITIALIZATION ============
const canvas = document.getElementById('bg-canvas');
const ctx = canvas.getContext('2d');

let canvasWidth = 0;
let canvasHeight = 0;
let particles = [];
let animationId = null;

const PARTICLE_COUNT = 70;
const CONNECTION_DIST = 130;
const MIN_RADIUS = 0.5;

// ============ CANVAS SETUP ============
function initCanvas() {
    canvasWidth = window.innerWidth;
    canvasHeight = window.innerHeight;
    canvas.width = canvasWidth;
    canvas.height = canvasHeight;
}

// ============ PARTICLE CLASS ============
class Particle {
    constructor() {
        this.x = Math.random() * canvasWidth;
        this.y = Math.random() * canvasHeight;
        this.vx = (Math.random() - 0.5) * 0.4;
        this.vy = (Math.random() - 0.5) * 0.4;
        this.radius = Math.max(MIN_RADIUS, Math.random() * 2 + 0.8);
        this.alpha = Math.random() * 0.4 + 0.15;
    }

    update() {
        this.x += this.vx;
        this.y += this.vy;

        if (this.x < 0) { this.x = 0; this.vx *= -1; }
        if (this.x > canvasWidth) { this.x = canvasWidth; this.vx *= -1; }
        if (this.y < 0) { this.y = 0; this.vy *= -1; }
        if (this.y > canvasHeight) { this.y = canvasHeight; this.vy *= -1; }
    }

    draw() {
        const r = Math.max(MIN_RADIUS, this.radius);
        ctx.beginPath();
        ctx.arc(this.x, this.y, r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0, 229, 255, ${this.alpha})`;
        ctx.fill();
    }
}

// ============ PARTICLE SYSTEM ============
function initParticles() {
    particles = [];
    for (let i = 0; i < PARTICLE_COUNT; i++) {
        particles.push(new Particle());
    }
}

function drawConnections() {
    for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
            const dx = particles[i].x - particles[j].x;
            const dy = particles[i].y - particles[j].y;
            const dist = Math.sqrt(dx * dx + dy * dy);

            if (dist < CONNECTION_DIST) {
                const alpha = (1 - dist / CONNECTION_DIST) * 0.12;
                ctx.beginPath();
                ctx.moveTo(particles[i].x, particles[i].y);
                ctx.lineTo(particles[j].x, particles[j].y);
                ctx.strokeStyle = `rgba(0, 229, 255, ${alpha})`;
                ctx.lineWidth = 1;
                ctx.stroke();
            }
        }
    }
}

function animate() {
    ctx.clearRect(0, 0, canvasWidth, canvasHeight);

    particles.forEach(p => {
        p.update();
        p.draw();
    });

    drawConnections();
    animationId = requestAnimationFrame(animate);
}

// ============ PAGE NAVIGATION ============
const pages = {
    hero: document.getElementById('heroPage'),
    input: document.getElementById('inputPage'),
    loading: document.getElementById('loadingPage'),
    results: document.getElementById('resultsPage')
};

const backBtn = document.getElementById('backBtn');
const startBtn = document.getElementById('startBtn');
const analyzeBtn = document.getElementById('analyzeBtn');
const scanAgainBtn = document.getElementById('scanAgainBtn');
const urlInput = document.getElementById('urlInput');

let currentPage = 'hero';
let history = ['hero'];

function showPage(pageName) {
    Object.values(pages).forEach(p => {
        p.classList.add('hidden');
        p.classList.remove('exit');
    });

    pages[pageName].classList.remove('hidden');

    backBtn.classList.toggle('hidden', pageName === 'hero');

    if (pageName !== currentPage) {
        history.push(pageName);
    }
    currentPage = pageName;
}

function goBack() {
    if (history.length > 1) {
        history.pop();
        const prevPage = history[history.length - 1];

        pages[currentPage].classList.add('exit');

        setTimeout(() => {
            showPage(prevPage);
            history = [prevPage];
        }, 300);
    }
}

// ============ RESULTS GENERATION ============
function generateResults(analysisData) {
    const riskScoreEl = document.getElementById('riskScore');
    const meterFill = document.getElementById('meterFill');
    const statusBadge = document.getElementById('statusBadge');
    const meterBar = meterFill.parentElement;
    
    // Use the final intensity returned by the backend; this value already
    // incorporates any boosting or hybrid adjustments. vt_score is only a
    // fallback for very old responses that might lack malicious_intensity.
    let risk = 0;
    if (analysisData.malicious_intensity) {
        const num = parseFloat(analysisData.malicious_intensity);
        if (!isNaN(num)) risk = num;
    } else {
        const vt = analysisData.hybrid_report?.global_threat_intel || {};
        if (vt.vt_score != null) {
            risk = parseFloat(vt.vt_score) || 0;
        }
    }
    const verdict = analysisData.final_verdict;

    // determine badge/level based strictly on the backend verdict so the UI
    // mirrors exactly what the engine returned (clean/model/hybrid logic).
    let level, levelClass, badgeText, iconPath;
    switch (verdict) {
        case 'MALICIOUS':
            level = 'critical';
            levelClass = 'critical';
            badgeText = 'Malicious';
            iconPath = '<path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>';
            break;
        case 'SUSPICIOUS':
            level = 'moderate';
            levelClass = 'moderate';
            badgeText = 'Suspicious';
            iconPath = '<path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>';
            break;
        default:
            // CLEAN or any unknown
            level = 'low';
            levelClass = 'secure';
            badgeText = 'Secure';
            iconPath = '<path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>';
    }

    // previous risk-based fallback logic removed
    
    // Reset and animate
    meterFill.style.width = '0%';
    meterFill.className = 'meter-fill ' + level;

    const colors = {
        low: '#00e676',
        moderate: '#ffc400',
        high: '#ff6d00',
        critical: '#ff5252'
    };

    statusBadge.innerHTML = `
        <span class="badge ${levelClass}">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                ${iconPath}
            </svg>
            ${badgeText}
        </span>
    `;

    // show which engine/source determined the verdict (provided by backend)
    const sourceEl = document.getElementById('sourceInfo');
    if (sourceEl) {
        sourceEl.textContent = `Determined by: ${analysisData.source || 'Hybrid'}`;
    }

    riskScoreEl.style.color = colors[level];

    // Animate score counter
    let current = 0;
    const duration = 1500;
    const startTime = performance.now();

    function animateScore(timestamp) {
        const elapsed = timestamp - startTime;
        const progress = Math.min(elapsed / duration, 1);

        current = Math.round(progress * risk);
        riskScoreEl.textContent = current + '%';
        meterFill.style.width = current + '%';
        meterBar.setAttribute('aria-valuenow', current);

        if (progress < 1) {
            requestAnimationFrame(animateScore);
        }
    }

    requestAnimationFrame(animateScore);
    
    // Populate findings from analysis data
    populateFindings(analysisData);

    // Show SHAP feature contributions if available
    showShapContributions(
        analysisData.hybrid_report.local_ml_engine.feature_impacts
    );
}

// ---------- SHAP DISPLAY HELPERS ----------
function showShapContributions(contributions) {
    const shapSection = document.getElementById('shapSection');
    const shapList = document.getElementById('shapList');
    shapList.innerHTML = '';
    if (contributions && Object.keys(contributions).length) {
        Object.entries(contributions).forEach(([feature, value]) => {
            const li = document.createElement('li');
            li.textContent = `${feature}: ${value}`;
            shapList.appendChild(li);
        });
        shapSection.classList.remove('hidden');
    } else {
        shapSection.classList.add('hidden');
    }
}

// ============ POPULATE FINDINGS ============
function populateFindings(analysisData) {
    const vt = analysisData.hybrid_report.global_threat_intel || {};
    const ml = analysisData.hybrid_report.local_ml_engine || {};

    // remove previous result items
    const existing = document.querySelectorAll('#resultsPage .result-item');
    existing.forEach(el => el.remove());

    const container = document.querySelector('#resultsPage .w-full.max-w-lg');
    if (!container) return;
    const h3 = container.querySelector('h3');
    if (!h3) return;

    // build new entries
    let html = '';

    // entry for global threat intel
    html += `
        <div class="result-item mb-3">
            <div class="flex items-start gap-4">
                <div class="w-2.5 h-2.5 rounded-full mt-1.5" style="background: #00e676; flex-shrink:0;"></div>
                <div>
                    <h4 class="font-semibold mb-1" style="color: var(--fg);">Global Intelligence: ${vt.verdict || 'N/A'}</h4>
                    <p class="text-sm" style="color: var(--muted);">
                        engines=${vt.total_engines||0}, malicious=${vt.malicious_count||0}, suspicious=${vt.suspicious_count||0}
                    </p>
                </div>
            </div>
        </div>
    `;

    // entry for local ML engine
    html += `
        <div class="result-item mb-3">
            <div class="flex items-start gap-4">
                <div class="w-2.5 h-2.5 rounded-full mt-1.5" style="background: #ffc400; flex-shrink:0;"></div>
                <div>
                    <h4 class="font-semibold mb-1" style="color: var(--fg);">ML Engine: ${ml.verdict || 'N/A'}</h4>
                    <p class="text-sm" style="color: var(--muted);">confidence: ${ml.confidence_score != null ? ml.confidence_score : '—'}</p>
                </div>
            </div>
        </div>
    `;

    h3.insertAdjacentHTML('afterend', html);
}

// ============ API CALL FUNCTION ============
async function analyzeURL(url) {
    const backendURL = 'http://localhost:8000/analyze';
    
    try {
        const response = await fetch(backendURL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });
        
        if (!response.ok) {
            throw new Error(`Backend error: ${response.status} ${response.statusText}`);
        }
        
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Analysis failed:', error);
        throw error;
    }
}

// ============ EVENT LISTENERS ============
startBtn.addEventListener('click', () => {
    pages.hero.classList.add('exit');
    setTimeout(() => showPage('input'), 300);
});

analyzeBtn.addEventListener('click', async () => {
    const url = urlInput.value.trim();
    if (url) {
        document.getElementById('loadingUrl').textContent = url;
        document.getElementById('scannedUrl').textContent = url;

        showPage('loading');
        document.getElementById('loadingShield').classList.add('scanning');

        try {
            // Call backend API
            const analysisData = await analyzeURL(url);
            
            // Simulate minimum loading time for better UX
            await new Promise(resolve => setTimeout(resolve, 2000));
            
            document.getElementById('loadingShield').classList.remove('scanning');
            showPage('results');
            generateResults(analysisData);
        } catch (error) {
            document.getElementById('loadingShield').classList.remove('scanning');
            alert('Analysis failed: ' + error.message);
            showPage('input');
        }
    } else {
        urlInput.focus();
        urlInput.style.borderColor = '#ff5252';
        setTimeout(() => {
            urlInput.style.borderColor = '';
        }, 1500);
    }
});

urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        analyzeBtn.click();
    }
});

scanAgainBtn.addEventListener('click', () => {
    urlInput.value = '';
    showPage('input');
    history = ['input'];
});

backBtn.addEventListener('click', goBack);

// ============ RESIZE HANDLER ============
function handleResize() {
    initCanvas();
    particles.forEach(p => {
        p.x = Math.min(p.x, canvasWidth);
        p.y = Math.min(p.y, canvasHeight);
    });
}

window.addEventListener('resize', handleResize);

// ============ INIT ============
function init() {
    initCanvas();
    initParticles();

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
    if (!prefersReducedMotion.matches) {
        animate();
    } else {
        // Draw static particles
        particles.forEach(p => p.draw());
        drawConnections();
    }
}

init();