const API_URL = 'http://localhost:8000/ingest';

// --- Utilities ---
const getRandomIP = () => Array.from({ length: 4 }, () => Math.floor(Math.random() * 256)).join('.');

const showToast = (message) => {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
};

const sendLog = async (logData) => {
    try {
        await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(logData)
        });
        console.log('Log sent:', logData.event_type);
    } catch (error) {
        console.error('Failed to send log:', error);
    }
};

// --- Store Interactions ---

// 1. Search
document.getElementById('btn-search').addEventListener('click', () => {
    const q = document.getElementById('search-input').value;
    if (!q) return;
    
    sendLog({
        event_type: 'web_access',
        src_ip: getRandomIP(),
        severity: 1,
        message: `Khách hàng tìm kiếm: ${q}`,
        source: 'nova_store_frontend',
        action: 'allow'
    });
    showToast(`Đang tìm kiếm: ${q}`);
});

// 2. Add to cart
document.querySelectorAll('.add-to-cart').forEach(btn => {
    btn.addEventListener('click', (e) => {
        const id = e.target.dataset.id;
        const name = e.target.closest('.product-card').querySelector('h3').textContent;
        const count = document.querySelector('.cart-count');
        count.textContent = parseInt(count.textContent) + 1;
        
        sendLog({
            event_type: 'web_access',
            src_ip: getRandomIP(),
            severity: 1,
            message: `Khách hàng thêm ${name} (ID: ${id}) vào giỏ hàng`,
            source: 'nova_store_frontend'
        });
        showToast(`Đã thêm ${name} vào giỏ hàng!`);
    });
});

// 3. Login Modal
document.getElementById('nav-login').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('login-modal').style.display = 'flex';
});

document.querySelector('.close-modal').addEventListener('click', () => {
    document.getElementById('login-modal').style.display = 'none';
});

document.getElementById('btn-do-login').addEventListener('click', () => {
    const user = document.getElementById('login-user').value || 'guest';
    const pass = document.getElementById('login-pass').value;
    
    if (pass === 'admin123') {
        sendLog({
            event_type: 'login_success',
            src_ip: getRandomIP(),
            severity: 1,
            message: `Người dùng ${user} đăng nhập thành công`,
            user: user,
            source: 'nova_store_auth'
        });
        showToast('Đăng nhập thành công!');
        document.getElementById('login-modal').style.display = 'none';
    } else {
        sendLog({
            event_type: 'login_failure',
            src_ip: getRandomIP(),
            severity: 3,
            message: `Đăng nhập thất bại: ${user} (Sai mật khẩu)`,
            user: user,
            source: 'nova_store_auth'
        });
        showToast('Sai tên đăng nhập hoặc mật khẩu!');
    }
});

// --- Dev Tools / Attack Simulation ---

document.getElementById('open-testing-tools').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('dev-tools').style.display = 'block';
    showToast('Đã mở chế độ kiểm thử');
});

document.getElementById('close-dev').addEventListener('click', () => {
    document.getElementById('dev-tools').style.display = 'none';
});

// Keyboard shortcut (Ctrl+Shift+D)
window.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.shiftKey && e.key === 'D') {
        const tool = document.getElementById('dev-tools');
        tool.style.display = tool.style.display === 'block' ? 'none' : 'block';
    }
});

// Attack logic
document.getElementById('sim-sqli').addEventListener('click', () => {
    const payload = "' OR 1=1 --";
    document.getElementById('search-input').value = payload;
    sendLog({
        event_type: 'ids_alert',
        src_ip: getRandomIP(),
        severity: 4,
        message: `Phát hiện SQL Injection trong chuỗi tìm kiếm: ${payload}`,
        source: 'ids'
    });
    showToast('Simulating SQL Injection...');
});

document.getElementById('sim-xss').addEventListener('click', () => {
    const payload = "<script>alert('pwned')</script>";
    document.getElementById('search-input').value = payload;
    sendLog({
        event_type: 'ids_alert',
        src_ip: getRandomIP(),
        severity: 4,
        message: `Phát hiện XSS Attack: ${payload}`,
        source: 'ids'
    });
    showToast('Simulating XSS Attack...');
});

document.getElementById('sim-portscan').addEventListener('click', () => {
    const attackerIp = getRandomIP();
    showToast('Simulating Port Scan...');
    for (let i = 0; i < 5; i++) {
        setTimeout(() => {
            sendLog({
                event_type: 'port_scan',
                src_ip: attackerIp,
                severity: 3,
                message: `Quét cổng ${80+i}`,
                source: 'firewall'
            });
        }, i * 300);
    }
});

document.getElementById('sim-dos').addEventListener('click', () => {
    const attackerIp = getRandomIP();
    showToast('Simulating DoS Attack...');
    let count = 0;
    const itv = setInterval(() => {
        sendLog({
            event_type: 'dos_attack',
            src_ip: attackerIp,
            severity: 4,
            message: 'Flood request detected',
            source: 'firewall'
        });
        count++;
        if (count > 10) clearInterval(itv);
    }, 200);
});

document.getElementById('sim-malware').addEventListener('click', () => {
    sendLog({
        event_type: 'malware_detected',
        src_ip: getRandomIP(),
        severity: 5,
        message: 'Virus detected in uploaded file: ransom.exe',
        source: 'antivirus'
    });
    showToast('Simulating Malware Detection...');
});
