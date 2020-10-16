const authButtons = document.getElementById('authButtons');

const createAuthButton = (type) => {
    const loginButton = document.createElement('a');
    loginButton.href = `/.netlify/functions/${type}`;
    loginButton.innerText = type.charAt(0).toUpperCase() + type.slice(1);
    authButtons.append(loginButton);
};

const createSecretLink = () => {
    const secretButton = document.createElement('a');
    secretButton.href = `/admin/secret`;
    secretButton.innerText = 'View the Secret Stuff!';
    authButtons.append(secretButton);
};

if (document.cookie.includes('nf_jwt')) {
    createAuthButton('logout');
    createSecretLink();
} else {
    createAuthButton('login');
}
