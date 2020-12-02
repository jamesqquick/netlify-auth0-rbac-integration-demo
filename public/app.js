const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');
const secretGuestBtn = document.getElementById('secretGuestBtn');
const secretAdminBtn = document.getElementById('secretAdminBtn');
if (document.cookie.includes('nf_jwt')) {
    logoutBtn.classList.remove('hidden');
    secretGuestBtn.classList.remove('hidden');
    secretAdminBtn.classList.remove('hidden');
} else {
    loginBtn.classList.remove('hidden');
}
