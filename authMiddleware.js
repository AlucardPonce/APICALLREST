const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'supersecreto123';

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']; // Header: "Bearer token"
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ success: false, error: 'Token no proporcionado' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, error: 'Token inválido o expirado' });
        }

        req.user = user; // Guardamos datos del usuario decodificado en req.user
        next();
    });
}

module.exports = authenticateToken;
