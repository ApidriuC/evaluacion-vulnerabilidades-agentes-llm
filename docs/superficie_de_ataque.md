# Arquitectura del agente experimental y superficie de ataque

Entregable del **Objetivo 1**: establecer la arquitectura y la superficie de
ataque de un agente autónomo basado en LLM como base de la evaluación.

## Arquitectura del agente víctima

El agente reproduce la arquitectura canónica descrita en el marco conceptual del
anteproyecto (Xi et al., 2023; Park et al., 2023): un modelo de lenguaje como
núcleo cognitivo, rodeado de componentes que le dan autonomía.

```
                         ┌─────────────────────────────┐
   Usuario ──tarea──▶    │   Prompt de sistema (rol)    │
                         └──────────────┬──────────────┘
                                        ▼
                         ┌─────────────────────────────┐
                         │   Núcleo LLM (razona/planea) │◀───┐
                         └──────────────┬──────────────┘    │
                              decide llamada a herramienta   │  resultado
                                        ▼                    │  (dato)
                         ┌─────────────────────────────┐    │
                         │   Arnés de ejecución         │────┘
                         │   (bucle + controles)        │
                         └──────────────┬──────────────┘
                                        ▼
     ┌──────────────┬───────────────┬──────────────┬─────────────────┐
     ▼              ▼               ▼              ▼                 ▼
 buscar/leer    leer_correo    consultar_bd     http_get        ejecutar_shell
 documento                                    enviar_correo
 (RAG)          (bandeja)      (datos estr.)   (egreso/red)     (ejecución)
     │              │               │              │                 │
     └──────────────┴───────────────┴──────────────┴─────────────────┘
                          Entorno corporativo simulado
                   (documentos, correo, base de datos, variables env)
```

## Componentes y su papel en la superficie de ataque

| Componente | Función | Debilidad que introduce |
|------------|---------|-------------------------|
| Prompt de sistema | Fija el rol y las reglas | Objetivo de anulación (jailbreak) |
| Núcleo LLM | Razona y decide acciones | Confunde datos con instrucciones |
| Memoria/contexto | Acumula resultados de herramientas | Vehículo de inyección indirecta persistente |
| Herramientas de lectura | RAG, correo, BD | **Canales de entrada** de payloads (datos no confiables) |
| Herramientas de egreso | `http_get`, `enviar_correo` | **Canales de salida** para exfiltración |
| Herramienta de ejecución | `ejecutar_shell` | Agencia excesiva, escalada |

## La superficie de ataque: dónde entra y por dónde sale

El principio que organiza todo el laboratorio: en un agente, **la frontera entre
"datos" e "instrucciones" es difusa**. Cualquier herramienta que devuelve
contenido controlable por un tercero es un canal de entrada de instrucciones
hostiles; cualquier herramienta que produce un efecto externo es un canal de
salida.

**Canales de entrada (inyección)**
- `prompt_directo` — el usuario mismo es hostil.
- `documento_rag` — payload alojado en un documento que el agente recupera.
- `correo` — payload en el cuerpo de un mensaje entrante.
- `base_datos` — payload en un campo de un registro.

**Canales de salida (impacto)**
- Exfiltración de red (`http_get`, `enviar_correo`).
- Divulgación al usuario en la respuesta.
- Ejecución de comandos (`ejecutar_shell`).

## Metadatos de seguridad por herramienta

Cada herramienta declara (`src/lab/herramientas.py`) los atributos de los que las
defensas derivan su comportamiento —no hay listas escritas a mano por escenario:

| Herramienta | riesgo | irreversible | canal_egreso | expone_datos |
|-------------|--------|:---:|:---:|:---:|
| buscar_documento | lectura | | | ✔ |
| leer_documento | lectura | | | ✔ |
| leer_correo | lectura | | | ✔ |
| consultar_bd | lectura | | | ✔ |
| http_get | red | | ✔ | |
| enviar_correo | red | ✔ | ✔ | |
| ejecutar_shell | ejecución | ✔ | | |

- `expone_datos` marca los canales de entrada → sobre ellos actúan el clasificador
  de inyección y el spotlighting.
- `canal_egreso` marca los canales de salida → sobre ellos actúa la allowlist de egreso.
- `irreversible` marca las acciones que requieren aprobación humana (HITL).

Esta tabla **es** la superficie de ataque operacionalizada: conecta el análisis
conceptual del Objetivo 1 con los controles del Objetivo 4.
