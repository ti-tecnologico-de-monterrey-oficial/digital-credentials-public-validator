# Imagen del validador de Open Badges 3.0 de 1EdTech (módulo inspector-vc-web).
# dcc-services lo consulta en POST /api/validate?validatorId=OB30Inspector.
#
# El contexto de build es esta carpeta: el JAR web empaqueta los módulos
# inspector-vc, inspector-clr, inspector-tcp-vc e inspector-trusted. Cada módulo
# del pom raíz necesita su COPY de abajo, o falla la descarga de dependencias.
# Las pruebas corren en el CI (mvn verify), no aquí, así que ni siquiera se
# compilan.
#
# No usa funciones exclusivas de BuildKit: se construye igual con az acr build,
# con docker build y con DOCKER_BUILDKIT=0.

FROM maven:3.9.16-eclipse-temurin-25 AS build

WORKDIR /src

# Las dependencias se descargan en una capa que solo depende de los POM: un
# cambio de código reutiliza esa capa en lugar de volver a descargarlas.
COPY pom.xml ./
COPY inspector-vc/pom.xml inspector-vc/
COPY inspector-clr/pom.xml inspector-clr/
COPY inspector-tcp-vc/pom.xml inspector-tcp-vc/
COPY inspector-trusted/pom.xml inspector-trusted/
COPY inspector-vc-web/pom.xml inspector-vc-web/
RUN mvn -B -ntp -DexcludeReactor=true dependency:go-offline

COPY . .

RUN mvn -B -ntp -Dmaven.test.skip=true package

# Extrae el JAR en la aplicación más sus dependencias, separadas por capas:
# arranca más rápido que el fat jar, es la forma que admite la caché AOT de
# abajo, y un cambio de código no vuelve a publicar las dependencias.
RUN java -Djarmode=tools -jar inspector-vc-web/target/inspector-vc-web.jar \
      extract --layers --destination /layers

FROM eclipse-temurin:25-jre-noble AS runtime

# libsodium: el proveedor Ed25519 de danubetech la carga por JNA para verificar
# las firmas Ed25519Signature2020; sin ella cada prueba embebida falla.
# tini como PID 1 reenvía SIGTERM a la JVM cuando Container Apps retira una
# revisión y recoge procesos huérfanos.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends libsodium23 tini \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin validator

WORKDIR /app

# El código queda a nombre de root y el proceso corre como validator: la
# aplicación no puede reescribir sus propios archivos.
# Los RUN true entre los COPY --from evitan que el builder clásico de Docker que
# usa az acr build falle al exportar la imagen («failed to get layer ... layer
# does not exist») con varios COPY --from seguidos.
COPY --from=build /layers/dependencies/ ./
RUN true
COPY --from=build /layers/spring-boot-loader/ ./
RUN true
COPY --from=build /layers/application/ ./

# Caché AOT (JEP 483/514): una corrida de entrenamiento que se detiene al
# terminar de levantar el contexto de Spring deja precargadas y enlazadas las
# clases, lo que recorta el arranque de cada réplica nueva.
RUN java -XX:AOTCacheOutput=/app/app.aot -Dspring.context.exit=onRefresh \
      -jar /app/inspector-vc-web.jar \
    && rm -rf /tmp/*

# Ajustables al desplegar (JAVA_TOOL_OPTIONS se puede sobrescribir):
# - MaxRAMPercentage: el heap usa el 70 % del límite del contenedor; el resto
#   queda para metaspace, hilos, code cache y los ~75 MB mapeados de la caché
#   AOT.
# - ExitOnOutOfMemoryError: sin memoria, el proceso termina y Container Apps lo
#   reinicia, en lugar de quedar vivo respondiendo errores.
# - Las subidas se limitan a 5 MB, como el BODY_LIMIT de dcc-services; la
#   aplicación acepta hasta 200 MB por omisión.
# - SERVER_TOMCAT_THREADS_MAX acota cuántas validaciones corren a la vez (200
#   por omisión): cada una puede descargar y verificar una lista de estado de
#   hasta 2 MiB, y sin tope unas decenas simultáneas agotarían el heap.
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70 -XX:+ExitOnOutOfMemoryError" \
    SERVER_PORT=8080 \
    SERVER_TOMCAT_THREADS_MAX=20 \
    APP_TEMP_STORAGE_LOCATION=/tmp \
    SPRING_SERVLET_MULTIPART_MAX_FILE_SIZE=5MB \
    SPRING_SERVLET_MULTIPART_MAX_REQUEST_SIZE=5MB

USER validator

EXPOSE 8080

# Para Docker Compose; en Container Apps las sondas apuntan a la misma ruta. La
# imagen no trae curl: bash abre el socket y busca "UP" en la respuesta.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/${SERVER_PORT:-8080} && printf 'GET /actuator/health HTTP/1.0\\r\\n\\r\\n' >&3 && grep -q '\"UP\"' <&3"]

# Fijos, para que sobrescribir JAVA_TOOL_OPTIONS no los quite:
# - AOTCache: la caché entrenada arriba. No se agrega --enable-native-access
#   para el JNA de libsodium: desactiva el grafo de módulos archivado y la JVM
#   deja de usar la caché; el costo es un aviso en la primera validación.
# - Timeouts de HttpURLConnection, que el validador usa para descargar listas
#   de estado, contextos y llaves: sin ellos una URL que no responde, declarada
#   en una credencial, retiene un hilo indefinidamente.
ENTRYPOINT ["/usr/bin/tini", "--", "java", \
    "-XX:AOTCache=/app/app.aot", \
    "-Dsun.net.client.defaultConnectTimeout=10000", \
    "-Dsun.net.client.defaultReadTimeout=20000", \
    "-jar", "/app/inspector-vc-web.jar"]
