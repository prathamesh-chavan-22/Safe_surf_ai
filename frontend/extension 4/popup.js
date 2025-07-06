// popup.js
let authToken = null;
let userEmail = null;

function showMessage(id, message, color = 'black') {
  const el = document.getElementById(id);
  el.textContent = message;
  el.style.color = color;
}

// Function to update UI based on login status
async function updateUI() {
  const authSection = document.getElementById('authSection');
  const loggedInSection = document.getElementById('loggedInSection');
  const loggedInEmailSpan = document.getElementById('loggedInEmail');

  const storedToken = await chrome.storage.session.get('authToken');
  const storedEmail = await chrome.storage.session.get('userEmail');

  authToken = storedToken.authToken || null;
  userEmail = storedEmail.userEmail || null;

  if (authToken && userEmail) {
    authSection.classList.add('hidden');
    loggedInSection.classList.remove('hidden');
    loggedInEmailSpan.textContent = userEmail;
    showMessage('authResult', 'You are currently logged in.', 'green');
  } else {
    authSection.classList.remove('hidden');
    loggedInSection.classList.add('hidden');
    loggedInEmailSpan.textContent = '';
    showMessage('authResult', 'Please log in or register.', 'black');
  }
}

async function sendOTP() {
  const email = document.getElementById('email').value;
  showMessage('authResult', 'Sending OTP...', 'black');
  try {
    const res = await fetch('http://127.0.0.1:8000/api/send-otp/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });

    const data = await res.json();
    if (res.ok) {
      showMessage('authResult', '✅ OTP sent to your email', 'green');
    } else {
      showMessage('authResult', '❌ ' + (data.error || JSON.stringify(data)), 'red');
    }
  } catch (error) {
    showMessage('authResult', '❌ Network error: ' + error.message, 'red');
  }
}

async function register() {
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  const otp = document.getElementById('otp').value;
  showMessage('authResult', 'Registering...', 'black');

  try {
    const res = await fetch('http://127.0.0.1:8000/api/register/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, otp })
    });

    const data = await res.json();
    if (res.ok) {
      showMessage('authResult', '✅ Registered successfully! Please log in.', 'green');
    } else {
      showMessage('authResult', '❌ ' + (data.error || JSON.stringify(data)), 'red');
    }
  } catch (error) {
    showMessage('authResult', '❌ Network error: ' + error.message, 'red');
  }
}

async function login() {
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  showMessage('authResult', 'Logging in...', 'black');

  try {
    const res = await fetch('http://127.0.0.1:8000/api/login/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();
    if (res.ok && data.token) {
      authToken = data.token;
      userEmail = email; // Store the email upon successful login
      await chrome.storage.session.set({ authToken: authToken, userEmail: userEmail });
      showMessage('authResult', '✅ Logged in successfully!', 'green');
      updateUI();
    } else {
      showMessage('authResult', '❌ ' + (data.error || JSON.stringify(data)), 'red');
    }
  } catch (error) {
    showMessage('authResult', '❌ Network error: ' + error.message, 'red');
  }
}

async function logout() {
  const storedToken = await chrome.storage.session.get('authToken');
  if (!storedToken.authToken) {
    showMessage('authResult', 'You are not logged in.', 'orange');
    return;
  }

  showMessage('authResult', 'Logging out...', 'black');
  try {
    const res = await fetch('http://127.0.0.1:8000/api/logout/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Token ' + storedToken.authToken
      }
    });

    if (res.ok) {
      authToken = null;
      userEmail = null;
      await chrome.storage.session.remove('authToken');
      await chrome.storage.session.remove('userEmail');
      showMessage('authResult', '✅ Logged out.', 'green');
      updateUI();
    } else {
      const data = await res.json();
      showMessage('authResult', '❌ Failed to log out: ' + (data.error || JSON.stringify(data)), 'red');
    }
  } catch (error) {
    showMessage('authResult', '❌ Network error: ' + error.message, 'red');
  }
}

// Add event listeners after the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('sendOtpButton').addEventListener('click', sendOTP);
  document.getElementById('registerButton').addEventListener('click', register);
  document.getElementById('loginButton').addEventListener('click', login);
  document.getElementById('logoutButton1').addEventListener('click', logout); // For the logout button in authSection
  document.getElementById('logoutButton2').addEventListener('click', logout); // For the logout button in loggedInSection

  updateUI(); // Initial UI update when popup loads
});