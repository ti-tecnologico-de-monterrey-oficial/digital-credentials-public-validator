# Validador de 1EdTech del Tec de Monterrey

Este repositorio parte de
[1EdTech/digital-credentials-public-validator](https://github.com/1EdTech/digital-credentials-public-validator)
(versión 1.14.1, commit `cee66b0`), el validador de Open Badges 3.0 que 1EdTech publica en
https://vc.1ed.tech (licencia Apache 2.0, en `LICENSE`). Los cambios del Tec se hacen aquí. Para
traer una versión nueva de 1EdTech se crea una rama desde su `main`, se aplican encima los cambios
del Tec y se abre un pull request; esta descripción dice en qué versión se basa.

`dcc-services` lo usa como verificador `1edtech`: le manda cada credencial a
`POST /api/validate?validatorId=OB30Inspector` y traduce el reporte de probes a sus checks.

## Por qué alojarlo

El validador descarga la lista de estado (`credentialStatus.statusListCredential`) de cada
credencial. Las del Tec viven en `dcc-services`, dentro del ambiente interno de Container Apps, y
https://vc.1ed.tech no las alcanza: la corrida termina en excepción y `dcc-services` no puede dar
por comprobada la firma ni la expiración. Alojado dentro del mismo ambiente las lee como el
sidecar de VerifierPlus, y las credenciales no salen de Azure.

## Cambios respecto al original

- `StatusListUrlRewriter` (`inspector-vc`): reescribe la URL de la que se descarga la lista de
  estado según `STATUS_LIST_URL_REWRITES`. El FQDN de `dcc-services` no resuelve dentro del
  ambiente interno, así que el sidecar descarga la lista del propio `dcc-services` en
  `http://127.0.0.1:3000`. La credencial conserva su URL firmada y la firma de la lista se sigue
  verificando. Una regla mal escrita impide que la aplicación arranque. Nunca reescribe una URL
  con una barra o una diagonal invertida codificadas (`%2F`, `%5C`) en la ruta.
- `BitstringStatusListProbe`:
  - Resume el resultado de la lista en un solo hallazgo propio con la URL declarada: una
    excepción si no se pudo descargar o leer, y un error si la lista no es válida. El reporte
    original anidaba los probes de la lista (`CredentialParseProbe`, `EmbeddedProofProbe`…), que
    `dcc-services` leía como hallazgos de la credencial, y mostraba la URL interna.
  - Descarga la lista una sola vez por validación (`DownloadedResource`) y la valida en memoria.
    El original le pasaba al inspector un `UriResource`, que abre una conexión en cada
    `exists()`, `getType()` y `asByteSource()`: unas 10 peticiones por lista. El tipo (JSON o JWT)
    se detecta con las mismas reglas de `Content-Type` y de extensión, y se manda el mismo
    `Accept`. Solo descarga URL `http` o `https`, no se conecta a direcciones internas salvo por
    una regla de reescritura, valida cada redirección (ver «Seguridad»), solo acepta respuestas
    2xx y corta las de más de 2 MiB; cualquiera de esos casos es la excepción de lista ilegible.
  - Una lista válida con avisos (`WARNING`) se usa; antes se saltaba la comprobación del bit.
  - La lista se expande leyendo un flujo y guardando solo el byte del índice, así que la memoria no
    crece con el tamaño de la lista; la expansión se limita a 16 MiB. Una entrada sin
    `statusPurpose` es un error. `statusListIndex` y `statusSize` se leen como enteros
    decimales no negativos (número o texto); otra cosa (texto, decimal, negativo, un `statusSize`
    de 0) es un error y se rechaza sin descargar la lista. Un índice que queda fuera de la lista
    también es un error, igual que una lista sin `credentialSubject.statusPurpose` o
    `encodedList`. Un `encodedList` que no se puede decodificar o que pasa de 16 MiB al
    expandirse es un fallo fatal (`Error expanding bitstring: …`); su mensaje no dice «revoked»,
    así que `dcc-services` no lo toma por una revocación. Ya no imprime trazas de depuración.
- `OB30Inspector`: la credencial de `refreshService` se descarga con `DownloadedResource`, con las
  mismas reglas que la lista de estado (solo direcciones públicas, redirecciones validadas, 2 MiB,
  timeouts). El original la descargaba con un `UriResource` a cualquier dirección, incluido
  `127.0.0.1`, que el sidecar comparte con `dcc-services`. Si no se puede descargar, la
  validación sigue con la credencial original, como antes.
- Logging: un solo backend, Logback (el de `spring-boot-starter`). Se excluyen
  `spring-boot-starter-log4j2`, que llegaba con `inspector-web-public`, y `commons-logging`; las
  librerías que usan la API de Log4j o de Commons Logging escriben a través de `log4j-to-slf4j` y
  `spring-jcl`.
- `Dockerfile` en la raíz: compila dentro de la imagen sin compilar pruebas, separa las capas
  (`inspector-vc-web/src/layers.xml` pone los módulos propios en la capa `application`, así que un
  cambio de código no vuelve a publicar las librerías), corre en una JRE 25 sin root, con `tini`,
  caché AOT de Java 25, timeouts de red, heap al 70 % del límite del contenedor, subidas limitadas
  a 5 MB y healthcheck por `/actuator/health`. No necesita BuildKit (`az acr build`, `docker
  build` y `DOCKER_BUILDKIT=0` dan la misma imagen): las dependencias de Maven se descargan en una
  capa que solo cambia con los POM, y los `*.md` no entran al contexto.
- Dependencias al último parche o menor de su rama: Spring Boot 3.5, Tomcat 10.1, Thymeleaf 3.1,
  Jackson 2.23, Netty 4.1, Log4j API 2.26, BouncyCastle 1.87, OkHttp 4.12, web3j 4.14, Guava,
  JUnit 5.14 y los plugins de Maven. Los BOM de Log4j, Jackson y Netty se importan antes que el de
  Spring Boot en `inspector-vc-web/pom.xml`; si no, el de Spring Boot impone versiones más viejas.
  Excepción: `java-jwt` pasó de 3.19 a 4.6 (versión mayor) y `jwks-rsa` de 0.21 a 0.24; los usa
  `ExternalProofProbe` y sus pruebas pasan.
- Compilación con `<release>17</release>`; las pruebas y la imagen usan Java 25.

### Vulnerabilidades (Trivy, HIGH y CRITICAL)

| Imagen | Hallazgos |
|---|---|
| Dockerfile original de 1EdTech (Java 17, Spring Boot 3.4) | 67 |
| `Dockerfile` de este repositorio | 0 (2 aceptadas en `.trivyignore`) |

Las dos aceptadas están en `spring-webmvc` 6.2 y solo se corrigen en Spring 7 (Spring Boot 4):

- CVE-2026-47884 requiere vistas `XsltView`.
- CVE-2026-47890 requiere Server-Sent Events con fragmentos de vista.

La aplicación no usa ninguna de las dos (sus vistas son Thymeleaf). Pasar a Spring Boot 4 depende
de que 1EdTech publique `inspector-web-*` para Spring 7.

### Dependencias que no se actualizaron

Su API cambió o son la base de la verificación de firmas, y el código no está adaptado ni probado
con las versiones nuevas:

- `verifiable-credentials-java` (danubetech) 1.18 → 1.31: se probó y 14 pruebas de verificación
  de firmas dejan de dar `VALID` (OB 3.0, endorsements y listas de estado). Se queda en 1.18.
- Versión menor disponible sin aplicar: `uni-resolver-client` 0.5 → 0.51, `copper-multibase`
  1.0 → 1.1 y `Saxon-HE` 9.6 → 9.9.
- Versión mayor: `titanium-rdfc` 3, `json-schema-validator` 2+, `okhttp` 5, `web3j` 5+ y
  `Saxon-HE` 10+.

## Seguridad

El validador descarga lo que la credencial declara: listas de estado y de revocación, contextos
JSON-LD, documentos de DID y llaves, esquemas y la URL del emisor. Como corre dentro de la red
interna, una credencial armada a propósito puede hacer que el sidecar haga peticiones GET a
servicios internos. La reescritura no amplía ese alcance, porque una credencial ya puede declarar
esas URLs directamente; el riesgo viene de alojar el validador dentro del ambiente, igual que con
VerifierPlus. Conviene restringir la salida de red del contenedor a lo que necesita.

La lista de estado y la credencial de `refreshService` sí están acotadas (`DownloadedResource`).
Si la URL no la reescribió una regla de `STATUS_LIST_URL_REWRITES`, el host debe resolver solo a
direcciones públicas: se rechazan loopback, privadas, link-local (incluida la de metadatos
169.254.169.254), `0.0.0.0/8`, compartidas (`100.64.0.0/10`, que usa Container Apps), de pruebas
(`198.18.0.0/15`), reservadas (`240.0.0.0/4` y broadcast), multicast, IPv6 de ámbito único local
(`fc00::/7`), 168.63.129.16 (la dirección de plataforma de Azure) y las formas IPv6 que llevan una
IPv4 interna dentro (NAT64 `64:ff9b::/96`, 6to4 `2002::/16` e IPv4-compatible `::/96`). Las
redirecciones se siguen a mano, hasta 5, y cada salto se valida igual; un salto desde la dirección
reescrita conserva la confianza solo si queda en el mismo esquema, host y puerto. La dirección se
comprueba antes de conectar y `HttpURLConnection` vuelve a resolver el host al conectar, pero las
dos consultas pasan por la caché DNS de la JVM, que guarda una respuesta positiva 30 s, así que
reciben las mismas direcciones. No hay que fijar `networkaddress.cache.ttl` ni
`sun.net.inetaddr.ttl` en 0: eso abriría la puerta a que un DNS cambie su respuesta entre ambas
consultas (DNS rebinding). Las demás descargas (contextos JSON-LD, documentos de DID, llaves,
listas de revocación 1EdTech, esquemas) no tienen esta restricción.

`DownloadedResource` fija en cada conexión 10 s para conectar y 20 s para leer, y la respuesta
completa debe llegar en 30 s. Las demás descargas que hacen `HttpURLConnection` (listas de
revocación, contextos, llaves y documentos de `did:web`) usan los mismos timeouts por omisión
(`sun.net.client.defaultConnectTimeout` y `defaultReadTimeout` en el `ENTRYPOINT`), pero sin plazo
total: un servidor que manda pocos bytes cada vez retiene el hilo más tiempo. No los tienen las
que usan otros clientes HTTP: `ExternalProofProbe` (credenciales JWT con llave remota) usa el
cliente de Apache y el resolvedor universal de DID el suyo. Solo `DownloadedResource` tiene tope de
tamaño (2 MiB); en las demás descargas una URL que devuelve un documento enorme puede agotar el
heap, y con `ExitOnOutOfMemoryError` el contenedor se reinicia. `SERVER_TOMCAT_THREADS_MAX=20`
acota cuántas validaciones corren a la vez.

Una subida mayor a 5 MB se rechaza con HTTP 500 (la librería web no distingue el 413). Un cliente
que manda `Expect: 100-continue`, como `curl -F` con archivos grandes, puede quedarse esperando
hasta su propio timeout. `dcc-services` no manda nada mayor a 5 MB, porque su `BODY_LIMIT` también
es de 5 MB.

## Compilar y probar

Sin Java local, con Docker desde Git Bash:

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W):/src" -v dcpv-m2:/root/.m2 -w /src maven:3.9.16-eclipse-temurin-25 mvn -B -ntp verify
docker build -t dcc-1edtech .
docker run --rm -p 8080:8080 dcc-1edtech
curl -F "file=@inspector-vc/src/test/resources/ob30/simple.json;type=application/json" "http://localhost:8080/api/validate?validatorId=OB30Inspector"
```

El build descarga las librerías `inspector-*` de `nexus.1edtech.net` y las de danubetech de
`repo.danubetech.com`. Algunas pruebas leen recursos de internet, así que pueden fallar sin red.

## Configuración

Variables que la imagen ya fija y que se pueden sobrescribir:

| Variable | Valor en la imagen |
|---|---|
| `SERVER_PORT` | `8080` (el healthcheck la sigue) |
| `SERVER_TOMCAT_THREADS_MAX` | `20` (validaciones simultáneas) |
| `SPRING_SERVLET_MULTIPART_MAX_FILE_SIZE` / `_MAX_REQUEST_SIZE` | `5MB` |
| `JAVA_TOOL_OPTIONS` | `-XX:MaxRAMPercentage=70 -XX:+ExitOnOutOfMemoryError` |
| `STATUS_LIST_URL_REWRITES` | sin valor |

La caché AOT y los timeouts de red van en el `ENTRYPOINT`, así que sobrescribir
`JAVA_TOOL_OPTIONS` no los quita. Los logs van solo a la consola.

`STATUS_LIST_URL_REWRITES` lleva pares `prefijo|reemplazo` separados por comas. Los dos deben
ser URL absolutas `http` o `https` con host, sin usuario, query ni fragmento, con puerto válido y
ruta terminada en `/`; un host con guion bajo no es válido. Una URL coincide si su esquema y su
host (sin distinguir mayúsculas), su puerto efectivo y el inicio de su ruta son los del prefijo; el
resto de la ruta y la query se agregan al reemplazo. Nunca se reescriben URL con usuario ni con
segmentos `.` o `..`, aunque vengan codificados. Gana la primera regla que coincide.

Con 0.5 vCPU y 1 GiB, la aplicación arranca en unos 4-5 s gracias a la caché AOT (unos 8-11 s sin
ella) y usa unos 170-300 MB en reposo. En la primera validación, Java 25 avisa que JNA usa métodos
restringidos para cargar libsodium; dar el permiso con `--enable-native-access` desactivaría la
caché AOT, así que se deja el aviso.

`did:key` y `did:jwk` se resuelven sin salir del proceso; las credenciales del Tec usan
`did:key`. `did:web` descarga el `did.json` del dominio por HTTPS, `did:velocity` consulta la red
de Velocity y los demás métodos van al resolvedor universal `dev.uniresolver.io`, según
`inspector-vc-web/src/main/resources/validators.json`. Los contextos JSON-LD habituales vienen incluidos en
`inspector-vc`; los demás se descargan, así que el contenedor necesita salida a internet.

## Despliegue

Está pensado para correr como sidecar de `dcc-services`, igual que VerifierPlus. Hoy no está
desplegado en ningún ambiente; esta es la configuración con la que se probó:

| Ambiente | Container App | Contenedor | Puerto |
|---|---|---|---|
| devl | `dcc-services-devl` | `dcc-1edtech-devl` | 3002 |
| pprd | `dcc-services-pprd` | `dcc-1edtech-pprd` | 3002 |

Cada sidecar tiene 0.5 vCPU y 1 GiB, sondas HTTP a `/actuator/health` y
`STATUS_LIST_URL_REWRITES=https://<fqdn de dcc-services>/status-credential/|http://127.0.0.1:3000/status-credential/`.
`dcc-services` lo usa con `ONEEDTECH_URL=http://127.0.0.1:3002`. La imagen es
`azrdevlcredentials.azurecr.io/dcc-1edtech:<versión>` y sirve para ambos ambientes.

Workflows:

- `.github/workflows/ci.yml`: en cada pull request hacia `develop`, `release` y `main` corre las
  pruebas, construye la imagen, la prueba con una credencial y la revisa con Trivy.
- `.github/workflows/deploy.yml`: al llegar a `develop` construye la imagen `dcc-1edtech:<sha>`
  en ACR, comprueba que el contenedor `dcc-1edtech-devl` ya existe, actualiza solo ese contenedor
  y espera a que la revisión quede sana; al llegar a `release`, lo mismo con `dcc-1edtech-pprd`.
  Un cambio que solo toca archivos `*.md` no despliega. Producción todavía no tiene el sidecar.
  - Las ramas `develop` y `release` hay que crearlas en este repositorio (hoy solo existe `main`).
  - El lanzamiento a mano (`workflow_dispatch`) solo aparece cuando el workflow ya está en `main`,
    la rama por omisión.
  - El sidecar se crea una sola vez a mano, con la configuración de la tabla de arriba: si no
    existe, el workflow falla en lugar de crearlo sin variables ni sondas.

El despliegue necesita en cada environment de GitHub (`Dev`, `Pprd`) las mismas variables que
tec-credentials: `vars.AZURE_CONTAINER_REGISTRY`, `vars.RESOURCE_GROUP` y
`secrets.AZURE_CREDENTIALS`. Como `dcc-services` se despliega desde tec-credentials, sus
workflows no comparten grupo de concurrencia con este: si los dos actualizan la misma Container
App al mismo tiempo, uno puede fallar y hay que relanzarlo.
