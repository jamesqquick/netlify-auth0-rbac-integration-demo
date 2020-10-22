require('dotenv').config();
const { handleCallback } = require('./AuthUtils');

exports.handler = async (event, context) => {
    try {
        return await handleCallback(event);
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
