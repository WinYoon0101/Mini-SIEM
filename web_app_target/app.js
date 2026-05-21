const API_URL = "http://localhost:8000/ingest";

// ======================================================
// Fixed IP Configuration
// ======================================================

// Normal user IP
const USER_IP = "192.168.1.100";

// Simulated attacker IP
const ATTACKER_IP = "185.220.101.45";

// ======================================================
// Utilities
// ======================================================

const generateEventId = () => crypto.randomUUID();

const createBaseLog = () => ({
  event_id: generateEventId(),

  timestamp: new Date().toISOString(),

  src_ip: USER_IP,

  source: "web_server",
});

const showToast = (message) => {
  const container = document.getElementById("toast-container");

  const toast = document.createElement("div");

  toast.className = "toast";
  toast.textContent = message;

  container.appendChild(toast);

  setTimeout(() => {
    toast.remove();
  }, 3000);
};

const sendLog = async (logData) => {
  try {
    await fetch(API_URL, {
      method: "POST",

      headers: {
        "Content-Type": "application/json",
      },

      body: JSON.stringify(logData),
    });

    console.log("[SIEM EVENT]", logData);
  } catch (error) {
    console.error("Failed to send log:", error);
  }
};

// ======================================================
// Store Interactions
// ======================================================

// Search
document.getElementById("btn-search").addEventListener("click", () => {
  const keyword =
    document.getElementById("search-input").value;

  if (!keyword) return;

  sendLog({
    ...createBaseLog(),

    event_type: "search_performed",
    category: "user_activity",

    severity: 1,

    action: "allowed",

    search_keyword: keyword,

    message: `User searched for keyword "${keyword}"`,
  });

  showToast(`Search results for: ${keyword}`);
});

// Add To Cart
document.querySelectorAll(".add-to-cart").forEach((btn) => {
  btn.addEventListener("click", (e) => {
    const productId = e.target.dataset.id;

    const productName = e.target
      .closest(".product-card")
      .querySelector("h3").textContent;

    const count =
      document.querySelector(".cart-count");

    count.textContent =
      parseInt(count.textContent) + 1;

    sendLog({
      ...createBaseLog(),

      event_type: "product_added_to_cart",
      category: "ecommerce",

      severity: 1,

      action: "success",

      product_id: productId,
      product_name: productName,

      message: `Product "${productName}" added to cart`,
    });

    showToast(`Product added to cart: ${productName}`);
  });
});

// ======================================================
// Authentication
// ======================================================

document.getElementById("nav-login").addEventListener("click", (e) => {
  e.preventDefault();

  document.getElementById("login-modal").style.display =
    "flex";
});

document.querySelector(".close-modal").addEventListener("click", () => {
  document.getElementById("login-modal").style.display =
    "none";
});

document.getElementById("btn-do-login").addEventListener("click", () => {
  const username =
    document.getElementById("login-user").value || "guest";

  const password =
    document.getElementById("login-pass").value;

  // SUCCESS LOGIN
  if (password === "admin123") {
    sendLog({
      event_id: generateEventId(),

      timestamp: new Date().toISOString(),

      event_type: "authentication_success",
      category: "authentication",

      severity: 1,

      src_ip: USER_IP,

      source: "web_server",
      action: "success",

      username: username,

      message: `Successful login for user "${username}"`,
    });

    showToast("Login successful!");

    document.getElementById("login-modal").style.display =
      "none";
  }

  // FAILED LOGIN
  else {
    sendLog({
      event_id: generateEventId(),

      timestamp: new Date().toISOString(),

      event_type: "authentication_failure",
      category: "authentication",

      severity: 2,

      src_ip: USER_IP,

      source: "web_server",
      action: "failed",

      username: username,

      reason: "invalid_password",

      message: `Failed login attempt for user "${username}"`,
    });

    showToast("Invalid username or password!");
  }
});

// ======================================================
// Dev / Security Testing Tools
// ======================================================

document
  .getElementById("open-testing-tools")
  .addEventListener("click", (e) => {
    e.preventDefault();

    document.getElementById("dev-tools").style.display =
      "block";

    showToast("Security testing mode enabled");
  });

document.getElementById("close-dev").addEventListener("click", () => {
  document.getElementById("dev-tools").style.display =
    "none";
});

// Keyboard shortcut: Ctrl + Shift + D
window.addEventListener("keydown", (e) => {
  if (e.ctrlKey && e.shiftKey && e.key === "D") {
    const tool = document.getElementById("dev-tools");

    tool.style.display =
      tool.style.display === "block"
        ? "none"
        : "block";
  }
});

// ======================================================
// Attack Simulations
// ======================================================

// SQL Injection
document.getElementById("sim-sqli").addEventListener("click", () => {
  const payload = "' OR 1=1 --";

  document.getElementById("search-input").value =
    payload;

  sendLog({
    event_id: generateEventId(),

    timestamp: new Date().toISOString(),

    event_type: "sql_injection_attempt",
    category: "web_attack",

    severity: 4,

    src_ip: ATTACKER_IP,

    source: "modsecurity_waf",
    action: "blocked",

    target: "/search",

    attack_type: "sqli",

    payload: payload,

    message:
      "SQL Injection payload detected in search input",
  });

  showToast("Simulating SQL Injection...");
});

// XSS
document.getElementById("sim-xss").addEventListener("click", () => {
  const payload = "<script>alert('pwned')</script>";

  document.getElementById("search-input").value =
    payload;

  sendLog({
    event_id: generateEventId(),

    timestamp: new Date().toISOString(),

    event_type: "xss_attempt",
    category: "web_attack",

    severity: 4,

    src_ip: ATTACKER_IP,

    source: "modsecurity_waf",
    action: "blocked",

    target: "/search",

    attack_type: "xss",

    payload: payload,

    message:
      "Cross-site scripting payload detected",
  });

  showToast("Simulating XSS Attack...");
});

// Port Scan
document.getElementById("sim-portscan").addEventListener("click", () => {
  showToast("Simulating Port Scan...");

  for (let i = 0; i < 5; i++) {
    const targetPort = 80 + i;

    setTimeout(() => {
      sendLog({
        event_id: generateEventId(),

        timestamp: new Date().toISOString(),

        event_type: "port_scan_detected",
        category: "network_attack",

        severity: 3,

        src_ip: ATTACKER_IP,

        source: "firewall",
        action: "detected",

        destination_port: targetPort,

        message: `Port scanning activity detected on port ${targetPort}`,
      });
    }, i * 300);
  }
});

// DoS Attack
document.getElementById("sim-dos").addEventListener("click", () => {
  showToast("Simulating DoS Attack...");

  let count = 0;

  const interval = setInterval(() => {
    sendLog({
      event_id: generateEventId(),

      timestamp: new Date().toISOString(),

      event_type: "dos_attack_detected",
      category: "network_attack",

      severity: 4,

      src_ip: ATTACKER_IP,

      source: "firewall",
      action: "blocked",

      attack_type: "dos_flood",

      request_count: count + 1,

      target: "/api/login",

      message:
        "Potential denial-of-service flood traffic detected",
    });

    count++;

    if (count >= 10) {
      clearInterval(interval);
    }
  }, 200);
});

// Malware Detection
document.getElementById("sim-malware").addEventListener("click", () => {
  sendLog({
    event_id: generateEventId(),

    timestamp: new Date().toISOString(),

    event_type: "malware_detected",
    category: "malware",

    severity: 5,

    src_ip: ATTACKER_IP,

    source: "ids",
    action: "quarantined",

    malware_name: "ransom.exe",

    infected_file: "invoice_attachment.zip",

    message:
      'Malware detected in uploaded file "ransom.exe"',
  });

  showToast("Simulating Malware Detection...");
});