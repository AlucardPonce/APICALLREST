const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const twilio = require('twilio');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./firebaseConfig.js'); // configuración con admin y Firestore
const nodemailer = require('nodemailer');

require('dotenv').config();

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'poncealucard@gmail.com',
        pass: process.env.EMAIL_PASS || 'vwixjvyzppizaruw'
    }
});

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

// Ruta protegida
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({
        success: true,
        message: 'Acceso autorizado a ruta protegida',
        user: req.user,
    });
});

// Enviar código de verificación por correo y guardarlo en Firestore
app.post("/send-code", async (req, res) => {
    const { to, code } = req.body;

    if (!to || !code) {
        return res.status(400).json({ error: "Faltan campos" });
    }

    try {
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to,
            subject: "Tu código de verificación",
            text: `Tu código es: ${code}`,
        });

        await db.collection("verifications").add({
            email: to,
            code,
            createdAt: new Date(),
        });

        res.status(200).json({ success: true });
    } catch (error) {
        console.error("Error al enviar código:", error);
        res.status(500).json({ error: "No se pudo enviar el código" });
    }
});

// Registrar usuario con verificación de código desde Firestore
app.post("/api/verify-and-register", async (req, res) => {
    const { nombre, email, password, telefono, code } = req.body;

    if (!nombre || !email || !password || !telefono || !code) {
        return res.status(400).json({ error: "Faltan campos requeridos" });
    }

    try {
        // Verifica si el código existe y es válido
        const codeSnap = await db.collection("verifications")
            .where("email", "==", email)
            .where("code", "==", code)
            .orderBy("createdAt", "desc")
            .limit(1)
            .get();

        if (codeSnap.empty) {
            return res.status(400).json({ error: "Código inválido o no encontrado" });
        }

        const codeDoc = codeSnap.docs[0];
        const { createdAt } = codeDoc.data();

        const now = new Date();
        const createdTime = createdAt.toDate ? createdAt.toDate() : createdAt;
        const diffMinutes = (now - createdTime) / (1000 * 60);

        if (diffMinutes > 10) {
            return res.status(400).json({ error: "El código ha expirado." });
        }

        // Verifica si ya hay usuario
        const userSnap = await db.collection("users").where("email", "==", email).get();
        if (!userSnap.empty) {
            return res.status(409).json({ error: "El correo ya está en uso" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = {
            nombre,
            email,
            telefono,
            password: hashedPassword,
            createdAt: new Date(),
        };

        const newDoc = await db.collection("users").add(newUser);
        res.status(201).json({ success: true, id: newDoc.id });

    } catch (err) {
        console.error("Error en /verify-and-register:", err);
        res.status(500).json({ error: "Error al verificar y registrar" });
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
});
