const db = require('./firebaseAdmin');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const usersCollection = db.collection('users');

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';
const TOKEN_EXPIRATION = '12h'; // Duración del token

async function registerUser({ nombre, email, password }) {
    try {
        // Validar que el email no exista
        const userSnapshot = await usersCollection.where('email', '==', email).get();
        if (!userSnapshot.empty) {
            return { success: false, error: 'El usuario ya existe' };
        }

        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync(password, salt);

        const newUser = {
            nombre,
            email,
            password: hashedPassword,
            createdAt: new Date(),
        };

        const docRef = await usersCollection.add(newUser);

        return { success: true, userId: docRef.id };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

async function loginUser({ email, password }) {
    try {
        const userSnapshot = await usersCollection.where('email', '==', email).get();

        if (userSnapshot.empty) {
            return { success: false, error: 'Usuario no encontrado' };
        }

        const userDoc = userSnapshot.docs[0];
        const userData = userDoc.data();

        const passwordMatch = bcrypt.compareSync(password, userData.password);
        if (!passwordMatch) {
            return { success: false, error: 'Contraseña incorrecta' };
        }

        // Crear token JWT con info básica del usuario (id y email)
        const token = jwt.sign(
            { userId: userDoc.id, email: userData.email, nombre: userData.nombre },
            JWT_SECRET,
            { expiresIn: TOKEN_EXPIRATION }
        );

        return {
            success: true,
            token,
            user: {
                id: userDoc.id,
                email: userData.email,
                nombre: userData.nombre,
                createdAt: userData.createdAt,
            },
        };
    } catch (error) {
        return { success: false, error: error.message };
    }
}

module.exports = { registerUser, loginUser };
