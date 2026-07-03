function normalizeErrorResponses(req, res, next) {
    const sendJson = res.json.bind(res);

    res.json = (body) => {
        if (body && body.success === false) {
            const message = body.message || body.error;
            if (message) {
                body = { ...body, message, error: message };
            }
        }
        return sendJson(body);
    };

    next();
}

module.exports = { normalizeErrorResponses };
