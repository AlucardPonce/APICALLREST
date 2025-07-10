const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const twilio = require('twilio');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./firebaseconfig'); // Aquí importas tu configuración con admin y Firestore

require('dotenv').config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Twilio
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioNumber = process.env.TWILIO_NUMBER;
const client = twilio(accountSid, authToken);

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'supersecreto123';

// Login endpoint
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const snapshot = await db.collection('users').where('email', '==', email).get();

        if (snapshot.empty) {
            return res.status(401).json({ success: false, error: 'Usuario no encontrado' });
        }

        const userDoc = snapshot.docs[0];
        const user = userDoc.data();
        const userId = userDoc.id;

        const validPassword = bcrypt.compareSync(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ success: false, error: 'Contraseña incorrecta' });
        }

        const token = jwt.sign(
            {
                id: userId,
                email: user.email,
                telefono: user.telefono || '',
            },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        delete user.password;

        res.json({ success: true, token, userData: { id: userId, ...user } });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Alerta inundación vía Twilio
app.post('/api/alerta-inundacion', async (req, res) => {
    const { phoneNumber, message } = req.body;

    try {
        await client.calls.create({
            to: phoneNumber,
            from: twilioNumber,
            twiml: `<Response><Say language="es-MX" voice="woman">${message}</Say></Response>`,
        });

        res.json({ success: true });
    } catch (error) {
        console.error('Error al llamar:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// Middleware de autenticación
const authenticateToken = require('./authMiddleware');

// Ruta protegida solo accesible con token válido
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({
        success: true,
        message: 'Acceso autorizado a ruta protegida',
        user: req.user, // Datos del token decodificado
    });
});


const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
});
