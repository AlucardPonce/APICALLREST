const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const app = express();

app.use(cors());
app.use(bodyParser.json());

// Configuración de riesgo dinámico
let currentRiskIndex = 0;
const riskLevels = ['Severo', 'Moderado', 'Leve'];
const riskColors = {
    'Severo': '#FF4444',
    'Moderado': '#FF8800',
    'Leve': '#FFAA00'
};

// Función para rotar el nivel de riesgo automáticamente
function rotateRiskLevel() {
    currentRiskIndex = (currentRiskIndex + 1) % riskLevels.length;
    return riskLevels[currentRiskIndex];
}

// Datos simulados de zonas en Querétaro
const zonasSimuladas = [
    { nombre: 'Centro Histórico', lat: 20.5888, lng: -100.38806 },
    { nombre: 'Col. Félix Osores', lat: 20.5756, lng: -100.3789 },
    { nombre: 'Col. Casa Blanca', lat: 20.5634, lng: -100.3567 },
    { nombre: 'Juriquilla', lat: 20.6130, lng: -100.4050 },
    { nombre: 'Col. Jardines', lat: 20.6012, lng: -100.4123 }
];

// Endpoint para obtener predicciones con riesgo dinámico
app.get('/predicciones', (req, res) => {
    try {
        const predicciones = zonasSimuladas.map((zona, index) => {
            // Rotar riesgo para cada zona
            const riesgo = rotateRiskLevel();
            
            return {
                name: zona.nombre,
                coordinate: { latitude: zona.lat, longitude: zona.lng },
                riskLevel: riesgo,
                frequency: riesgo === 'Severo' ? 5 : riesgo === 'Moderado' ? 3 : 1,
                radius: riesgo === 'Severo' ? 800 : riesgo === 'Moderado' ? 600 : 400,
                color: riskColors[riesgo]
            };
        });

        res.json({
            zonas: predicciones,
            historico: []
        });
    } catch (error) {
        console.error('Error en /predicciones:', error);
        res.status(500).json({ error: 'Error al obtener predicciones' });
    }
});

// Endpoint para predicciones personalizadas con riesgo dinámico
app.post('/predicciones/personalizadas', (req, res) => {
    const { name, lat, lng } = req.body;

    if (!lat || !lng) {
        return res.status(400).json({ error: 'Se requieren latitud y longitud' });
    }

    try {
        // Rotar riesgo para cada solicitud
        const riesgo = rotateRiskLevel();

        res.json({
            name: name || 'Ubicación personalizada',
            coordinate: { latitude: parseFloat(lat), longitude: parseFloat(lng) },
            riskLevel: riesgo,
            frequency: riesgo === 'Severo' ? 5 : riesgo === 'Moderado' ? 3 : 1,
            radius: 500,
            color: riskColors[riesgo],
            isCustom: true,
            timestamp: new Date().toISOString()
        });
    } catch (error) {
        console.error('Error en /predicciones/personalizadas:', error);
        res.status(500).json({ error: 'Error al procesar predicción' });
    }
});

// Endpoint para simular alertas en tiempo real
app.get('/simular-alerta', (req, res) => {
    const riesgo = rotateRiskLevel();
    const zonasAfectadas = Math.floor(Math.random() * 3) + 1;
    
    res.json({
        alerta: true,
        mensaje: `Alerta de inundación ${riesgo} detectada`,
        nivel: riesgo,
        zonas_afectadas: zonasAfectadas,
        timestamp: new Date().toISOString(),
        color: riskColors[riesgo]
    });
});

// Endpoint de estado del servidor
app.get('/status', (req, res) => {
    res.json({
        status: 'operativo',
        version: '1.0.0',
        ultima_actualizacion: new Date().toISOString(),
        configuracion: {
            niveles_riesgo: riskLevels,
            rotacion_automatica: true
        }
    });
});

// Configuración del servidor
const PORT = 3005;
app.listen(PORT, () => {
    console.log(`🚀 Servidor de pruebas corriendo en http://localhost:${PORT}`);
    console.log('Endpoints disponibles:');
    console.log(`- GET  /predicciones           - Zonas con riesgo rotatorio`);
    console.log(`- POST /predicciones/personalizadas - Predicción personalizada`);
    console.log(`- GET  /simular-alerta         - Simula alerta en tiempo real`);
    console.log(`- GET  /status                 - Estado del servidor`);
    
    // Mostrar configuración inicial
    console.log('\n🔧 Configuración:');
    console.log(`- Niveles de riesgo: ${riskLevels.join(', ')}`);
    console.log('- El riesgo rota automáticamente con cada solicitud');
});