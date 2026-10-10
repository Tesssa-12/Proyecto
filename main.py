import pandas as pd
import os
from google import genai
from google.genai import types
from server import app

# Configure la credencial fuera del código mediante GOOGLE_API_KEY.
def _genai_client():
    api_key = os.getenv("GOOGLE_API_KEY")
    return genai.Client(api_key=api_key) if api_key else None

# Instrucción estricta para que la IA responda de forma directa y concisa
REGLAS_AUDITORIA_PRODUCTOS = """
Eres el validador de errores del portal Peya Tools. Tu respuesta debe ser extremadamente corta, directa y sin guías paso a paso ni explicaciones de cómo usar Excel.
Indica únicamente el error detectado y qué se debe corregir en las filas específicas, siguiendo este formato de ejemplo:
"Este archivo tiene [tipo de error]. Corregir [acción] en filas: [números de fila]."
"""

def procesar_archivo_productos(ruta_archivo):
    print(f"Analizando el archivo: {ruta_archivo}...")
    
    try:
        df = pd.read_excel(ruta_archivo)
    except Exception as e:
        print(f"❌ Error al leer el archivo: {e}")
        return False

    errores_detectados = []
    
    # 1. Eliminar columnas prohibidas automáticamente
    columnas_a_eliminar = ['ID Sección', 'ID', 'GTIN', 'Stock', 'Global Catalog ID', 'Indice']
    df = df.drop(columns=[col for col in columnas_a_eliminar if col in df.columns])
    
    # 2. Validar que no existan SKU duplicados
    if 'SKU' in df.columns:
        skus_duplicados = df[df.duplicated(subset=['SKU'], keep=False) & df['SKU'].notnull()]
        if not skus_duplicados.empty:
            filas_excel = [f + 2 for f in skus_duplicados.index.tolist()]
            errores_detectados.append(f"productos con SKU duplicados. Corregir SKU duplicados en filas: {', '.join(map(str, filas_excel))}")

    # 3. Validar integridad (Nombre con Precio y SKU obligatorios)
    if 'Nombre' in df.columns:
        if 'Precio' in df.columns:
            filas_sin_precio = df[df['Nombre'].notnull() & df['Precio'].isnull()]
            if not filas_sin_precio.empty:
                filas_excel = [f + 2 for f in filas_sin_precio.index.tolist()]
                errores_detectados.append(f"productos sin precio asignado. Corregir precio en filas: {', '.join(map(str, filas_excel))}")
        
        if 'SKU' in df.columns:
            filas_sin_sku = df[df['Nombre'].notnull() & df['SKU'].isnull()]
            if not filas_sin_sku.empty:
                filas_excel = [f + 2 for f in filas_sin_sku.index.tolist()]
                errores_detectados.append(f"productos sin SKU asignado. Ingresar SKU en filas: {', '.join(map(str, filas_excel))}")

    # 4. Decisión: Si hay errores, la IA da el aviso directo; si todo está OK, exporta automático
    if errores_detectados:
        print("\n⚠️ Notificación de Inconsistencia:")
        prompt = f"Genera un mensaje de error directo y conciso para el agente basado en estos hallazgos: {errores_detectados}"
        
        config = types.GenerateContentConfig(
            system_instruction=REGLAS_AUDITORIA_PRODUCTOS,
            temperature=0.1
        )
        
        client = _genai_client()
        if not client:
            print(
                "No se puede generar el diagnóstico de IA. Configure la variable "
                "de entorno GOOGLE_API_KEY y vuelva a ejecutar la auditoría."
            )
            return False
        try:
            response = client.models.generate_content(
                model='gemini-3.6-flash',
                contents=prompt,
                config=config
            )
            print(response.text)
        except Exception:
            print("El archivo contiene inconsistencias que requieren corrección.")
        return False
        
    else:
        print("✅ Validación superada con éxito.")
        nombre_salida = 'productos_procesados.csv'
        
        # Exportar a CSV eliminando las columnas prohibidas y quitando la cabecera (header=False)
        df.to_csv(nombre_salida, index=False, header=False, encoding='utf-8')
        print(f"🚀 Archivo procesado correctamente. Columnas prohibidas eliminadas y exportado sin cabecera como: {nombre_salida}")
        return True

if __name__ == "__main__":
    # Ejecutar script con archivo de prueba únicamente al invocarlo directamente.
    procesar_archivo_productos('prueba_productos.xlsx')
