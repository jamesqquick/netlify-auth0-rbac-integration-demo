const { Issuer, generators } = require('openid-client');
const jwt = require('jsonwebtoken');
const cookie = require('cookie');

const NETLIFY_JWT_EXPIRATION_SECONDS = 14 * 24 * 3600;

const isRunningLocally = () => {
    return process.env.NETLIFY_DEV === 'true';
};

const getOpenIDClient = async () => {
    const issuer = await Issuer.discover(`https://${process.env.AUTH0_DOMAIN}`);
    return new issuer.Client({
        client_id: process.env.AUTH0_CLIENT_ID,
        redirect_uris: [`${process.env.URL}/.netlify/functions/callback`],
        response_types: ['id_token'],
    });
};

const generateNetlifyJWT = async (tokenData) => {
    const iat = Math.floor(Date.now() / 1000);
    const exp = Math.floor(iat + NETLIFY_JWT_EXPIRATION_SECONDS);
    //copy over appropriate properties from the original token data
    //Refer to Netlify Documentation for token formatting - https://docs.netlify.com/visitor-access/role-based-access-control/#external-providers
    const netlifyTokenData = {
        exp,
        iat,
        updated_at: iat,
        aud: tokenData.aud,
        sub: tokenData.sub,
        app_metadata: {
            authorization: {
                roles: tokenData[`${process.env.AUTH0_TOKEN_NAMESPACE}/roles`],
            },
        },
    };
    return await jwt.sign(netlifyTokenData, process.env.TOKEN_SECRET);
};

const generateAuth0LoginCookie = (nonce, encodedStateStr) => {
    const cookieData = { nonce, state: encodedStateStr };
    return cookie.serialize('auth0_login_cookie', JSON.stringify(cookieData), {
        secure: !isRunningLocally(),
        path: '/',
        maxAge: 30 * 60 * 1000,
        httpOnly: true,
    });
};

const generateEncodedStateString = (route) => {
    const state = { route: route || '/', nonce: generators.nonce() };
    const stateBuffer = Buffer.from(JSON.stringify(state));
    return stateBuffer.toString('base64');
};

const generateAuth0LoginResetCookie = () => {
    return cookie.serialize('auth0_login_cookie', 'Auth0 Login Cookie Reset', {
        secure: !isRunningLocally(),
        httpOnly: true,
        path: '/',
        maxAge: new Date(0),
    });
};

const generateLogoutCookie = () => {
    return cookie.serialize('nf_jwt', 'Logout Cookie', {
        secure: !isRunningLocally(),
        path: '/',
        maxAge: new Date(0),
        httpOnly: true,
    });
};

const generateNetlifyCookieFromAuth0Token = async (tokenData) => {
    const netlifyToken = await generateNetlifyJWT(tokenData);

    const twoWeeks = 14 * 24 * 3600000;
    return cookie.serialize('nf_jwt', netlifyToken, {
        secure: !isRunningLocally(),
        path: '/',
        maxAge: twoWeeks,
    });
};

const getCallbackParams = (openIDClient, event) => {
    /* NOTE: method, body, and url are all required for the openIDClient to work with
    the request*/
    const req = {
        method: 'POST',
        body: event.body,
        url: event.headers.host,
    };
    //callbackParams documentation - https://github.com/panva/node-openid-client/tree/master/docs#clientcallbackparamsinput
    return openIDClient.callbackParams(req);
};

const generateAuth0LogoutUrl = () => {
    const auth0DomainLogout = `https://${process.env.AUTH0_DOMAIN}/v2/logout`;
    const urlReturnTo = `returnTo=${encodeURIComponent(process.env.URL)}`;
    const urlClientId = `client_id=${process.env.AUTH0_CLIENT_ID}`;
    return `${auth0DomainLogout}?${urlReturnTo}&${urlClientId}`;
};

const handleLogin = async (event) => {
    if (!event || !event.headers) {
        throw new Error('Malformed event');
    }
    const openIDClient = await getOpenIDClient();
    const referer = event.headers.referer;

    //authorizationUrl docs - https://github.com/panva/node-openid-client/tree/master/docs#clientauthorizationurlparameters
    const authRedirectURL = openIDClient.authorizationUrl({
        scope: 'openid email profile',
        response_mode: 'form_post',
        nonce: generators.nonce(),
        state: generateEncodedStateString(referer),
    });
    return {
        statusCode: 302,
        headers: {
            Location: authRedirectURL,
            'Cache-Control': 'no-cache',
            'Set-Cookie': generateAuth0LoginCookie(nonce, encodedStateStr),
        },
    };
};

const handleCallback = async (event) => {
    if (!event || !event.headers || !event.headers.cookie) {
        throw new Error('Invalid request');
    }
    const openIDClient = await getOpenIDClient();

    const { auth0_login_cookie: loginCookie } = cookie.parse(
        event.headers.cookie
    );
    const { nonce, state } = JSON.parse(loginCookie);

    const params = getCallbackParams(openIDClient, event);

    //callback docs - https://github.com/panva/node-openid-client/tree/master/docs#clientcallbackredirecturi-parameters-checks-extras
    const tokenSet = await openIDClient.callback(
        `${process.env.URL}/.netlify/functions/callback`,
        params,
        {
            nonce,
            state,
        }
    );
    const { id_token } = tokenSet;
    const decodedToken = jwt.decode(id_token);
    const netlifyCookie = await generateNetlifyCookieFromAuth0Token(
        decodedToken
    );

    const auth0LoginCookie = generateAuth0LoginResetCookie();

    //Get the redirect URL from the decoded state
    const buff = Buffer.from(state, 'base64');
    const decodedState = JSON.parse(buff.toString('utf8'));
    return {
        statusCode: 302,
        headers: {
            Location: decodedState.route,
            'Cache-Control': 'no-cache',
        },
        multiValueHeaders: {
            'Set-Cookie': [netlifyCookie, auth0LoginCookie],
        },
    };
};

const handleLogout = async () => {
    return {
        statusCode: 302,
        headers: {
            Location: generateAuth0LogoutUrl(),
            'Cache-Control': 'no-cache',
            'Set-Cookie': generateLogoutCookie(),
        },
    };
};

module.exports = {
    handleLogin,
    handleCallback,
    handleLogout,
};
