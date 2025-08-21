# CTF Hackviser

## Índice
1. [Información General](#información-general)
2. [Configuración Inicial](#configuración-inicial)
3. [Análisis de Preguntas y Soluciones](#análisis-de-preguntas-y-soluciones)
4. [Técnicas de Reconocimiento](#técnicas-de-reconocimiento)
5. [Escalada de Privilegios](#escalada-de-privilegios)
6. [Herramientas y Comandos Útiles](#herramientas-y-comandos-útiles)
7. [Troubleshooting](#troubleshooting)

## Descripción de la CTF
- **Nombre**: Hackviser CTF
- **Tipo**: Capture The Flag - Linux Privilege Escalation
- **Usuario inicial**: captain
- **Contraseña**: shadow
- **Puerto SSH**: 22
- **Objetivo**: Resolver preguntas 8-15 mediante exploración del sistema

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
**Objetivo**: Ver permisos de `favorite_movie.txt`

**Comando principal**:
```bash
ls -l /home/captain/favorite_movie.txt
```

**Análisis de la salida**:
```
-rw-------  1 root root 25 fecha favorite_movie.txt
```
- `-rw-------`: Solo el propietario (root) puede leer/escribir
- `root root`: Propietario y grupo root
- **Resultado**: Permission denied para usuario captain

**Métodos alternativos para intentar acceso**:
```bash
# Verificar con diferentes comandos
stat favorite_movie.txt
file favorite_movie.txt
getfacl favorite_movie.txt

# Intentar lectura directa
cat favorite_movie.txt
head favorite_movie.txt
tail favorite_movie.txt
```

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

### Notas Importantes
- Siempre usar `2>/dev/null` para suprimir errores
- Documentar todos los comandos utilizados
- Verificar permisos antes de intentar acceso
- Considerar múltiples enfoques para cada problema

## Comandos de Verificación
```bash
# Verificar todas las respuestas
find / -name database.conf 2>/dev/null
ls -l favorite_movie.txt
id -u specter
tail -n 1 emailpass.txt
wc -w moment.txt
cat files/.favorite_country.txt
grep whoami@securemail.hv emailpass.txt
which hello
```
