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
function generateResults() {
    const risk = Math.floor(Math.random() * 100);
    const riskScoreEl = document.getElementById('riskScore');
    const meterFill = document.getElementById('meterFill');
    const statusBadge = document.getElementById('statusBadge');
    const meterBar = meterFill.parentElement;

    let level, levelClass, badgeText, iconPath;

    if (risk < 25) {
        level = 'low';
        levelClass = 'secure';
        badgeText = 'Secure';
        iconPath = '<path d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>';
    } else if (risk < 50) {
        level = 'moderate';
        levelClass = 'moderate';
        badgeText = 'Moderate Risk';
        iconPath = '<path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>';
    } else if (risk < 75) {
        level = 'high';
        levelClass = 'high';
        badgeText = 'High Risk';
        iconPath = '<path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>';
    } else {
        level = 'critical';
        levelClass = 'critical';
        badgeText = 'Critical Risk';
        iconPath = '<path d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>';
    }

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
}

// ============ EVENT LISTENERS ============
startBtn.addEventListener('click', () => {
    pages.hero.classList.add('exit');
    setTimeout(() => showPage('input'), 300);
});

analyzeBtn.addEventListener('click', () => {
    const url = urlInput.value.trim();
    if (url) {
        document.getElementById('loadingUrl').textContent = url;
        document.getElementById('scannedUrl').textContent = url;

        showPage('loading');
        document.getElementById('loadingShield').classList.add('scanning');

        const scanDuration = 2200 + Math.random() * 1500;

        setTimeout(() => {
            document.getElementById('loadingShield').classList.remove('scanning');
            showPage('results');
            generateResults();
        }, scanDuration);
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