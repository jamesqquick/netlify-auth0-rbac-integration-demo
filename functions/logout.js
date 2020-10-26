require('dotenv').config();
const { handleLogout } = require('./AuthUtils');

exports.handler = async (event, context) => {
    try {
        return handleLogout();
    } catch (err) {
        console.error(err);
        return {
            statusCode: 302,
            headers: {
                Location: '/',
                'Cache-Control': 'no-cache',
            },
        };
    }
};
