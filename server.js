const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const twilio = require('twilio');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('./firebaseConfig.js'); // configuración con admin y Firestore
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const axios = require('axios');
require('dotenv').config();

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'poncealucard@gmail.com',
        pass: process.env.EMAIL_PASS || 'bvcnwrqqovqsuley'
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
app.post("/api/send-code", async (req, res) => {
    const { to, code } = req.body;

    if (!to || !code) {
        return res.status(400).json({ error: "Faltan campos" });
    }

    try {
        // ❌ Verifica si ya hay un usuario registrado con este correo
        const userSnap = await db.collection("users").where("email", "==", to).get();
        if (!userSnap.empty) {
            return res.status(409).json({ error: "El correo ya está en uso" });
        }

        // ✉️ Enviar correo
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to,
            subject: "Tu código de verificación",
            text: `Tu código es: ${code}`,
        });

        // 💾 Guardar código con ID = correo
        await db.collection("verifications").doc(to).set({
            code,
            createdAt: new Date(),
        });

        res.status(200).json({ success: true });
    } catch (error) {
        console.error("Error en /send-code:", error);
        res.status(500).json({ error: "No se pudo enviar el código" });
    }
});

app.post("/api/verify-and-register", async (req, res) => {
    const { nombre, email, password, telefono, code } = req.body;

    if (!nombre || !email || !password || !telefono || !code) {
        console.log("❌ Faltan campos:", req.body);
        return res.status(400).json({ error: "Faltan campos requeridos" });
    }

    try {
        // 🔍 Obtiene el último código guardado para este email
        const docRef = db.collection("verifications").doc(email);
        const docSnap = await docRef.get();

        if (!docSnap.exists) {
            console.log("❌ No se encontró código para:", email);
            return res.status(400).json({ error: "Código no encontrado" });
        }

        const data = docSnap.data();
        if (data.code !== code.toString()) {
            console.log("❌ Código inválido para:", email);
            return res.status(400).json({ error: "Código inválido" });
        }

        const createdTime = data.createdAt.toDate ? data.createdAt.toDate() : new Date(data.createdAt);
        const now = new Date();
        const diffMinutes = (now - createdTime) / (1000 * 60);
        if (diffMinutes > 10) {
            console.log("⚠️ Código expirado. Tiempo:", diffMinutes.toFixed(2), "min");
            return res.status(400).json({ error: "El código ha expirado." });
        }

        // Verifica si ya hay usuario registrado
        const userSnap = await db.collection("users").where("email", "==", email).get();
        if (!userSnap.empty) {
            console.log("❌ Correo ya en uso:", email);
            return res.status(409).json({ error: "El correo ya está en uso" });
        }

        // 🔐 Crea usuario con contraseña encriptada
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            nombre,
            email,
            telefono,
            password: hashedPassword,
            createdAt: new Date(),
        };

        const userDoc = await db.collection("users").add(newUser);
        console.log("✅ Usuario registrado con ID:", userDoc.id);
        res.status(201).json({ success: true, id: userDoc.id });

    } catch (err) {
        console.error("💥 Error en /verify-and-register:", err);
        res.status(500).json({ error: "Error al verificar y registrar" });
    }
});



// Genera código numérico de 6 dígitos
function generateCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

app.post("/api/send-code-reset-password", async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: "Falta el correo electrónico" });
    }

    try {
        // Verificar que el usuario exista
        const userSnap = await db.collection("users").where("email", "==", email).get();
        if (userSnap.empty) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        // Generar código de 6 dígitos
        const code = Math.floor(100000 + Math.random() * 900000).toString();

        // Guardar código y fecha en Firestore en colección "password_resets"
        await db.collection("password_resets").doc(email).set({
            code,
            createdAt: new Date(),
        });

        // Enviar correo con el código
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Código para restablecer tu contraseña",
            text: `Tu código para restablecer la contraseña es: ${code}`,
        });

        res.json({ success: true });
    } catch (error) {
        console.error("Error en /send-code-reset-password:", error);
        res.status(500).json({ error: "No se pudo enviar el código" });
    }
});

app.post("/api/reset-password", async (req, res) => {
    const { email, code, newPassword } = req.body;

    if (!email || !code || !newPassword) {
        return res.status(400).json({ success: false, error: "Faltan campos" });
    }

    try {
        const docRef = db.collection("password_resets").doc(email);
        const docSnap = await docRef.get();

        if (!docSnap.exists) {
            return res.status(400).json({ success: false, error: "Código no encontrado" });
        }

        const data = docSnap.data();

        if (data.code !== code.toString()) {
            return res.status(400).json({ success: false, error: "Código incorrecto" });
        }

        const createdAt = data.createdAt.toDate ? data.createdAt.toDate() : new Date(data.createdAt);
        const now = new Date();
        const diffMinutes = (now - createdAt) / (1000 * 60);
        if (diffMinutes > 10) {
            return res.status(400).json({ success: false, error: "El código ha expirado" });
        }

        const userSnap = await db.collection("users").where("email", "==", email).get();
        if (userSnap.empty) {
            return res.status(404).json({ success: false, error: "Usuario no encontrado" });
        }

        const userDoc = userSnap.docs[0];
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await db.collection("users").doc(userDoc.id).update({
            password: hashedPassword,
        });

        // Borrar código tras usarlo
        await docRef.delete();

        res.json({ success: true, message: "Contraseña actualizada correctamente" });
    } catch (error) {
        console.error("Error en /reset-password:", error);
        res.status(500).json({ success: false, error: "Error interno del servidor" });
    }
});
const getColorBySeverity = (severity) => {
    switch (severity) {
        case 'Severo': return '#FF0000'; // Rojo
        case 'Moderado': return '#FFA500'; // Naranja
        case 'Leve': return '#FFFF00'; // Amarillo
        default: return '#00FF00'; // Verde (bajo riesgo o desconocido)
    }
};

// Coordenadas de zonas reales de Querétaro
const ELEVACION_PROMEDIO = 1820;

const zonas = [
    {
        nombre: 'Centro Histórico',
        lat: 20.5888,
        lng: -100.38806,
        elevacion: ELEVACION_PROMEDIO,
    },
    {
        nombre: 'Col. Félix Osores',
        lat: 20.5756,
        lng: -100.3789,
        elevacion: ELEVACION_PROMEDIO,
    },
    {
        nombre: 'Col. Casa Blanca',
        lat: 20.5634,
        lng: -100.3567,
        elevacion: ELEVACION_PROMEDIO,
    },
    {
        nombre: 'Juriquilla',
        lat: 20.6130,
        lng: -100.4050,
        elevacion: ELEVACION_PROMEDIO,
    },
    {
        nombre: 'Col. Jardines de Querétaro',
        lat: 20.6012,
        lng: -100.4123,
        elevacion: ELEVACION_PROMEDIO,
    }
];

app.get('/predicciones', async (req, res) => {
    try {
        const predicciones = await Promise.all(zonas.map(async (zona) => {
            const response = await axios.post('http://127.0.0.1:8000/predecir', {
                lat: zona.lat,
                lng: zona.lng,
                elevacion: zona.elevacion,
            });

            const { riesgo, coordenadas } = response.data;

            return {
                name: zona.nombre,
                coordinate: coordenadas,
                riskLevel: riesgo,
                frequency: Math.floor(Math.random() * 5) + 1,
                radius: riesgo === 'Severo' ? 800 : riesgo === 'Moderado' ? 600 : 400,
                color: getColorBySeverity(riesgo),
            };
        }));

        res.json({
            zonas: predicciones,
            historico: [], // Aquí podrías agregar más si tienes datos anteriores
        });
    } catch (error) {
        console.error('Error al predecir zonas:', error.message);
        res.status(500).json({ error: 'Error al predecir zonas de riesgo' });
    }
});

app.post('/predicciones/personalizadas', async (req, res) => {
    //console.log('📥 /predicciones/personalizadas - body recibido:', req.body);

    const { name, lat, lng, elevation } = req.body;

    if (!name || !lat || !lng) {
       // console.warn('⚠️ /predicciones/personalizadas - Datos faltantes:', { name, lat, lng });
        return res.status(400).json({ error: 'Faltan datos obligatorios: name, lat, lng' });
    }

    try {
        // Usa la elevación enviada si viene, si no, asigna un valor fijo
        const elevacion = elevation || 1820;

        //console.log('🌍 Enviando datos a IA para predicción:', { lat, lng, elevacion });

        const response = await axios.post('http://127.0.0.1:8000/predecir', {
            lat,
            lng,
            elevacion,
        });

        //console.log('✅ Respuesta de IA recibida:', response.data);

        const { riesgo, coordenadas } = response.data;

        return res.json({
            name,
            coordinate: coordenadas,
            riskLevel: riesgo,
            frequency: Math.floor(Math.random() * 5) + 1,
        });
    } catch (err) {
        console.error('❌ Error en /predicciones/personalizada:', err);
        if (err.response) {
            console.error('Response data:', err.response.data);
            console.error('Response status:', err.response.status);
        }
        res.status(500).json({ error: 'No se pudo analizar la zona' });
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
});
