from fastapi import FastAPI
from pydantic import BaseModel
import requests
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

OPENWEATHER_API_KEY = os.getenv("OPENWEATHER_API_KEY")

if not OPENWEATHER_API_KEY:
    raise Exception("API Key no encontrada. Verifica tu archivo .env")

class Ubicacion(BaseModel):
    lat: float
    lng: float
    elevacion: float  # Aún la necesitamos para el modelo

def obtener_datos_climaticos(lat, lon):
    url = f"https://api.openweathermap.org/data/2.5/weather?lat={lat}&lon={lon}&appid={OPENWEATHER_API_KEY}&units=metric"
    response = requests.get(url)
    data = response.json()

    humedad = data["main"]["humidity"]

    # Lluvia puede no estar presente
    lluvia = data.get("rain", {}).get("1h", 0.0)

    return lluvia, humedad

def calcular_riesgo(lluvia, humedad, elevacion):
    if lluvia > 50 and humedad > 70 and elevacion < 1800:
        return "Severo"
    elif lluvia > 30:
        return "Moderado"
    else:
        return "Leve"

@app.post("/predecir")
def predecir_inundacion(ubicacion: Ubicacion):
    try:
        lluvia, humedad = obtener_datos_climaticos(ubicacion.lat, ubicacion.lng)
        riesgo = calcular_riesgo(lluvia, humedad, ubicacion.elevacion)

        return {
            "zona": f"Lat: {ubicacion.lat}, Lng: {ubicacion.lng}",
            "riesgo": riesgo,
            "lluvia": lluvia,
            "humedad": humedad,
            "coordenadas": {
                "latitude": ubicacion.lat,
                "longitude": ubicacion.lng
            }
        }
    except Exception as e:
        return {"error": f"No se pudo obtener datos: {str(e)}"}
