const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');
const secretBtn = document.getElementById('secretBtn');
if (document.cookie.includes('nf_jwt')) {
    logoutBtn.classList.remove('hidden');
    secretBtn.classList.remove('hidden');
} else {
    loginBtn.classList.remove('hidden');
}
