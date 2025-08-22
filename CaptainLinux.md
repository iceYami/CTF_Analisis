# CTF Captain Linux

<img src="https://m.media-amazon.com/images/I/81j7vf54EeL.jpg" width="300"/>


## Índice
1. [Información General](#información-general)
2. [Configuración Inicial](#configuración-inicial)
3. [Análisis de Preguntas y Soluciones](#análisis-de-preguntas-y-soluciones)
4. [Técnicas de Reconocimiento](#técnicas-de-reconocimiento)
5. [Escalada de Privilegios](#escalada-de-privilegios)
6. [Herramientas y Comandos Útiles](#herramientas-y-comandos-útiles)
7. [Troubleshooting](#troubleshooting)

## Descripción
- **Nombre**: Hackviser CTF
- **Tipo**: Capture The Flag - Linux System Exploration
- **Usuario inicial**: captain
- **Contraseña**: shadow
- **Puerto SSH**: 22
- **Sistema**: Debian GNU/Linux 5.10.0-27-amd64
- **Objetivo**: Resolver preguntas 8-15 mediante exploración del sistema
- **Característica especial**: Sistema sin `sudo` instalado

### Credenciales de Acceso
```bash
Usuario: captain
Contraseña: shadow
Método de conexión: SSH
IP: Variable según examen
```

### Estructura del Sistema
```bash
/home/captain/
├── .bashrc
├── .bash_logout  
├── .bash_history (vacío)
├── .profile
├── .local/
│   └── share/nano/
├── files/
│   └── .favorite_country.txt (archivo oculto)
├── favorite_movie.txt (permisos especiales 0000)
├── moment.txt (archivo de texto largo)
├── emailpass.txt (archivo grande ~3.6MB)
└── output.txt (vacío)
```

### Credenciales de Acceso
```bash
Usuario: captain
Contraseña: shadow
Método de conexión: SSH
```

## Configuración Inicial

### 1. Conexión SSH
```bash
ssh captain@<IP_DEL_EXAMEN> -p 22
# Contraseña: shadow
```

### 2. Verificación de Conexión
```bash
whoami
pwd
uname -a
id
```

### 3. Exploración Inicial del Sistema
```bash
# Ver directorio home
ls -la /home/captain

# Ver estructura general
ls -la /

# Verificar permisos del usuario
groups
sudo -l
```

## Análisis de Preguntas y Soluciones

### Pregunta 8: Buscar archivo de configuración
**Objetivo**: Localizar `database.conf` en todo el sistema

**Comando principal**:
```bash
find / -name database.conf 2>/dev/null
```

**Análisis de opciones**:
- `find /`: Busca desde la raíz del sistema
- `-name database.conf`: Busca exactamente ese nombre
- `2>/dev/null`: Suprime errores de permisos

**Alternativas**:
```bash
# Búsqueda más específica
find /etc /opt /usr /var -name database.conf 2>/dev/null

# Con wildcards
find / -name "*database.conf*" 2>/dev/null

# Búsqueda case-insensitive
find / -iname database.conf 2>/dev/null
```

### Pregunta 9: Permisos de archivo protegido
**Objetivo**: Ver permisos y acceder al contenido de `favorite_movie.txt`

**Comando principal**:
```bash
ls -l /home/captain/favorite_movie.txt
```

**Análisis de la salida real**:
```
---------- 1 captain captain 13 Mar 23  2024 /home/captain/favorite_movie.txt
```
- `----------`: **Permisos 0000** - Sin permisos para nadie (ni propietario)
- `captain captain`: El propietario es captain (el usuario actual)
- **Tamaño**: 13 bytes
- **Problema especial**: Archivo sin permisos de lectura incluso para el propietario

**SOLUCIÓN - Cambiar permisos como propietario**:
```bash
# Como eres propietario, puedes cambiar permisos
chmod 644 /home/captain/favorite_movie.txt

# Verificar el cambio
ls -l /home/captain/favorite_movie.txt

# Leer el contenido
cat /home/captain/favorite_movie.txt
```

**Métodos alternativos si chmod no funciona**:
```bash
# Método 1: Copiar archivo (bypasses permisos de lectura)
cp /home/captain/favorite_movie.txt /tmp/movie_copy.txt
cat /tmp/movie_copy.txt

# Método 2: Usar dd para bypass de bajo nivel
dd if=/home/captain/favorite_movie.txt of=/tmp/movie_dd.txt 2>/dev/null
cat /tmp/movie_dd.txt

# Método 3: Verificar información detallada
stat favorite_movie.txt
file favorite_movie.txt
```

**Análisis técnico**:
- Permisos `0000` impiden lectura incluso al propietario
- Como captain ES el propietario, puede modificar permisos
- El archivo tiene 13 bytes, sugiere contenido corto (nombre de película)
- Este es un escenario común en CTFs para enseñar gestión de permisos

### Pregunta 10: UID del usuario specter
**Objetivo**: Consultar User ID de specter

**Comando principal**:
```bash
id -u specter
```

**Análisis completo del usuario**:
```bash
# UID específico
id -u specter

# Información completa
id specter

# Verificar existencia en passwd
grep specter /etc/passwd

# Ver todos los usuarios del sistema
cut -d: -f1 /etc/passwd
```

### Preguntas 11-15: Análisis de archivos específicos

#### Archivo: `emailpass.txt`
```bash
# Ver contenido completo
cat emailpass.txt

# Última línea
tail -n 1 emailpass.txt

# Buscar email específico
grep whoami@securemail.hv emailpass.txt

# Contar líneas/palabras
wc -l emailpass.txt
```

#### Archivo: `moment.txt`
```bash
# Contar palabras
wc -w moment.txt

# Ver contenido
cat moment.txt

# Análisis detallado
wc moment.txt  # líneas, palabras, caracteres
```

#### Archivo: `files/.favorite_country.txt`
```bash
# Acceder al archivo oculto
cat files/.favorite_country.txt

# Verificar permisos
ls -la files/.favorite_country.txt
```

## Técnicas de Reconocimiento

### Exploración de Directorios
```bash
# Archivos ocultos en home
ls -la /home/captain

# Estructura de directorios
tree /home/captain 2>/dev/null

# Buscar archivos interesantes
find /home/captain -type f -name ".*" 2>/dev/null
```

### Análisis de Permisos
```bash
# Permisos detallados
ls -la

# Permisos numericos
stat -c "%a %n" *

# ACLs extendidas
getfacl *
```

### Búsqueda de Archivos
```bash
# Por nombre
find / -name "*.txt" 2>/dev/null

# Por permisos
find / -perm -4000 2>/dev/null  # SUID
find / -perm -2000 2>/dev/null  # SGID

# Por propietario
find / -user root 2>/dev/null
```

## Escalada de Privilegios

### Verificación de Privilegios Sudo
```bash
sudo -l
```

### Búsqueda de SUID/SGID
```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
```

### Análisis de Procesos
```bash
ps aux
ps -ef
pstree
```

### Variables de Entorno
```bash
env
export
echo $PATH
```

## Herramientas y Comandos Útiles

### Comandos de Búsqueda
| Comando | Función | Ejemplo |
|---------|---------|---------|
| `find` | Buscar archivos/directorios | `find / -name "*.conf"` |
| `locate` | Buscar en base de datos | `locate database.conf` |
| `which` | Localizar comando | `which hello` |
| `whereis` | Localizar binarios/manuales | `whereis ls` |

### Comandos de Análisis de Archivos
| Comando | Función | Ejemplo |
|---------|---------|---------|
| `ls -l` | Ver permisos | `ls -l archivo.txt` |
| `stat` | Información detallada | `stat archivo.txt` |
| `file` | Tipo de archivo | `file archivo.txt` |
| `wc` | Contar líneas/palabras | `wc -w archivo.txt` |

### Comandos de Usuario/Sistema
| Comando | Función | Ejemplo |
|---------|---------|---------|
| `id` | Información de usuario | `id -u specter` |
| `whoami` | Usuario actual | `whoami` |
| `groups` | Grupos del usuario | `groups` |
| `passwd` | Ver usuarios | `cat /etc/passwd` |

## Troubleshooting

### Problemas Comunes

#### Permission Denied
```bash
# Verificar permisos
ls -l archivo

# Intentar con sudo
sudo cat archivo

# Cambiar permisos (si es posible)
chmod +r archivo
```

#### Archivo No Encontrado
```bash
# Verificar ruta completa
ls -la directorio/

# Buscar archivo
find / -name "archivo" 2>/dev/null

# Verificar archivos ocultos
ls -la
```

#### Comando No Encontrado
```bash
# Verificar PATH
echo $PATH

# Localizar comando
which comando
whereis comando

# Usar ruta completa
/usr/bin/comando
```

## Casos Especiales y Soluciones Avanzadas

### Archivo con Permisos 0000 (Sin permisos para nadie)
Este es un caso especial donde el archivo no tiene permisos de lectura ni siquiera para el propietario:

```bash
# Verificar situación
ls -l archivo
# Output: ---------- 1 user user size fecha archivo

# Solución: Cambiar permisos como propietario
chmod 644 archivo
cat archivo

# Alternativa: Copiar archivo
cp archivo /tmp/copia_archivo
cat /tmp/copia_archivo
```

### Análisis de Sistema sin sudo
En sistemas donde `sudo` no está disponible:

```bash
# Verificar disponibilidad
which sudo  # No output = no disponible

# Buscar binarios SUID útiles
find / -perm -4000 -type f 2>/dev/null | grep -E "(cat|less|more|vim|nano)"

# Usar su para cambiar a root (si se conoce password)
su -
```

### Exploración de Archivos Protegidos
```bash
# Ver metadatos sin leer contenido
stat archivo_protegido
file archivo_protegido

# Buscar copias o backups
find / -name "*nombre_archivo*" 2>/dev/null
find / -name "*.bak" 2>/dev/null
find / -name "*~" 2>/dev/null

# Verificar logs que puedan contener información
grep -r "string_relevante" /var/log/ 2>/dev/null
```

## Estrategia de Resolución

### Orden Recomendado
1. **Conectar y orientarse en el sistema**
2. **Explorar estructura de directorios**
3. **Identificar archivos clave**
4. **Resolver preguntas simples primero**
5. **Abordar problemas de permisos**
6. **Documentar hallazgos**

### Notas Importantes
- Siempre usar `2>/dev/null` para suprimir errores
- Documentar todos los comandos utilizados
- Verificar permisos antes de intentar acceso
- Considerar múltiples enfoques para cada problema

## Comandos de Verificación Final - Checklist Completo
```bash
# === SECUENCIA DE COMANDOS PARA RESOLVER CTF HACKVISER ===

# 8. Buscar archivo de configuración database.conf
find / -name database.conf 2>/dev/null

# 9. Ver permisos y acceder a favorite_movie.txt (CASO ESPECIAL)
ls -l /home/captain/favorite_movie.txt
chmod 644 /home/captain/favorite_movie.txt  # Cambiar permisos como propietario
cat /home/captain/favorite_movie.txt       # Leer contenido
# Alternativa si chmod falla: cp /home/captain/favorite_movie.txt /tmp/movie.txt && cat /tmp/movie.txt

# 10. Consultar UID del usuario specter
id -u specter

# 11. Última línea de emailpass.txt
tail -n 1 /home/captain/emailpass.txt

# 12. Contar palabras de moment.txt
wc -w /home/captain/moment.txt

# 13. Ver archivo oculto favorite_country.txt
cat /home/captain/files/.favorite_country.txt

# 14. Buscar email específico en emailpass.txt
grep whoami@securemail.hv /home/captain/emailpass.txt

# 15. Localizar comando hello
which hello

# === VERIFICACIÓN ADICIONAL ===
# Verificar estructura de archivos
ls -la /home/captain/
ls -la /home/captain/files/

# Verificar permisos numéricos
stat -c "%a %n" /home/captain/*

# Información del sistema
whoami
id
uname -a
```

### Respuestas
| Pregunta | Comando | Resultado Esperado |
|----------|---------|-------------------|
| 8 | `find / -name database.conf 2>/dev/null` | Ruta completa del archivo |
| 9 | `chmod 644 favorite_movie.txt && cat favorite_movie.txt` | Nombre de película (13 caracteres) |
| 10 | `id -u specter` | Número UID |
| 11 | `tail -n 1 emailpass.txt` | Último email:password |
| 12 | `wc -w moment.txt` | Número de palabras |
| 13 | `cat files/.favorite_country.txt` | Nombre del país |
| 14 | `grep whoami@securemail.hv emailpass.txt` | Línea con password |
| 15 | `which hello` | Ruta del comando hello |
