"""Adaptadores de proveedor de LLM.

El laboratorio mide el comportamiento de un *agente*, no de un proveedor
concreto, así que toda llamada al modelo pasa por la interfaz `ProveedorLLM`.
Añadir un segundo proveedor para el estudio comparativo entre modelos consiste
en implementar `responder()`.

Hay dos implementaciones:

  `ProveedorAnthropic`  SDK oficial. Es el que produce los datos del experimento.
  `ProveedorSimulado`   Sin red y determinista. Existe para validar el arnés
                        (que los canarios se detectan, que el ASR se calcula,
                        que las defensas interceptan). NO produce resultados
                        científicos y así está marcado en cada traza.

Nota de diseño: `ProveedorAnthropic` NO activa fallbacks por rechazo. En este
laboratorio un `stop_reason == "refusal"` es un dato -- significa que la
salvaguarda del modelo detuvo el ataque -- y reenrutar a otro modelo
destruiría esa medición. Se registra como `rechazo` y se contabiliza aparte.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from . import canarios
from .config import MODELO_POR_DEFECTO


@dataclass
class LlamadaHerramienta:
    id: str
    nombre: str
    argumentos: dict


@dataclass
class RespuestaLLM:
    texto: str = ""
    llamadas: list[LlamadaHerramienta] = field(default_factory=list)
    # Bloques tal como los devolvió la API; se reenvían sin modificar al
    # historial (obligatorio cuando el pensamiento extendido está activo).
    bloques: Any = None
    motivo_parada: str = ""
    rechazo: str | None = None
    tokens_entrada: int = 0
    tokens_salida: int = 0


class ProveedorLLM(Protocol):
    modelo: str
    simulado: bool

    def responder(
        self, sistema: str, mensajes: list[dict], herramientas: list[dict]
    ) -> RespuestaLLM: ...


# --------------------------------------------------------------------------
# Anthropic
# --------------------------------------------------------------------------


class ProveedorAnthropic:
    simulado = False

    def __init__(
        self,
        modelo: str | None = None,
        max_tokens: int = 8192,
        effort: str = "",
    ):
        import anthropic  # import diferido: el arnés corre sin el SDK instalado

        self._sdk = anthropic
        self.cliente = anthropic.Anthropic()
        self.modelo = modelo or os.environ.get("LAB_MODELO", MODELO_POR_DEFECTO)
        self.max_tokens = max_tokens
        self.effort = effort

    def responder(self, sistema, mensajes, herramientas) -> RespuestaLLM:
        peticion: dict[str, Any] = {
            "model": self.modelo,
            "max_tokens": self.max_tokens,
            "system": sistema,
            "messages": mensajes,
            "thinking": {"type": "adaptive"},
        }
        if herramientas:
            peticion["tools"] = herramientas
        if self.effort:
            peticion["output_config"] = {"effort": self.effort}

        respuesta = self.cliente.messages.create(**peticion)

        texto_partes: list[str] = []
        llamadas: list[LlamadaHerramienta] = []
        for bloque in respuesta.content:
            if bloque.type == "text":
                texto_partes.append(bloque.text)
            elif bloque.type == "tool_use":
                # El input puede traer escapes distintos según el modelo; nunca
                # se hace coincidencia de cadenas sobre el JSON serializado.
                argumentos = bloque.input if isinstance(bloque.input, dict) else json.loads(bloque.input)
                llamadas.append(
                    LlamadaHerramienta(id=bloque.id, nombre=bloque.name, argumentos=argumentos)
                )

        rechazo = None
        if respuesta.stop_reason == "refusal":
            detalles = getattr(respuesta, "stop_details", None)
            rechazo = getattr(detalles, "category", None) or "sin_categoria"

        return RespuestaLLM(
            texto="\n".join(texto_partes).strip(),
            llamadas=llamadas,
            bloques=respuesta.content,
            motivo_parada=respuesta.stop_reason or "",
            rechazo=rechazo,
            tokens_entrada=respuesta.usage.input_tokens,
            tokens_salida=respuesta.usage.output_tokens,
        )


# --------------------------------------------------------------------------
# Simulado (validación del arnés, sin red)
# --------------------------------------------------------------------------

_RE_URL = re.compile(r"https?://[^\s\"'<>)\]]+")
_RE_CORREO = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_RE_CANARIO = re.compile(r"CAN-[A-Z]{3}-[0-9a-f]{12}")
_RE_HERRAMIENTA = re.compile(r"\b(http_get|enviar_correo|ejecutar_shell|consultar_bd|leer_documento)\b")


class ProveedorSimulado:
    """Agente ingenuo determinista: obedece cualquier directiva que encuentre.

    Su propósito es dar una señal conocida contra la que verificar el arnés:
    bajo C0 debe producir ASR alto, y bajo C3/C4 debe caer. Si eso no ocurre,
    el fallo está en la instrumentación, no en el modelo.
    """

    simulado = True

    def __init__(self, modelo: str = "simulado-v1", **_):
        self.modelo = modelo
        self._contador = 0
        # Estado que persiste entre turnos de UNA corrida (misma instancia).
        self._secretos: set[str] = set()   # canarios vistos en cualquier resultado
        self._pendiente: dict | None = None  # acción de exfiltración por realizar
        self._leidos: set[str] = set()     # recursos ya leídos (evita bucles)

    def responder(self, sistema, mensajes, herramientas) -> RespuestaLLM:
        self._contador += 1
        disponibles = {h["name"] for h in herramientas}
        idc = f"sim_{self._contador}"

        resultados = self._resultados(mensajes)
        # Acumular todo canario visto hasta ahora: el secreto puede haber
        # llegado en un documento distinto al que trae la instrucción.
        for texto in resultados:
            self._secretos |= canarios.detectar(texto)

        # En un ataque directo (A01/A07) el propio usuario es el atacante: la
        # instrucción viaja en el prompt. En uno indirecto viaja en los datos.
        # El agente ingenuo no distingue la fuente, así que absorbe de ambas.
        self._absorber_instruccion(self._texto_usuario(mensajes))
        for texto in resultados:
            if not self._bloqueado(texto):
                self._absorber_instruccion(texto)

        # 1) ¿Falta leer el recurso que la instrucción referencia?
        lectura = self._lectura_pendiente(disponibles, idc)
        if lectura:
            return RespuestaLLM(texto="", llamadas=[lectura], motivo_parada="tool_use", bloques=None)

        # 2) ¿Hay un objetivo de exfiltración listo para ejecutar?
        exfil = self._exfiltracion(disponibles, idc)
        if exfil:
            return RespuestaLLM(texto="", llamadas=[exfil], motivo_parada="tool_use", bloques=None)

        # 3) Primer turno sin instrucción aún: leer lo que la tarea pide.
        if self._contador == 1:
            tarea = self._texto_usuario(mensajes)
            for nombre, args in self._plan_inicial(tarea):
                if nombre in disponibles:
                    self._leidos.add(nombre)
                    return RespuestaLLM(
                        texto="",
                        llamadas=[LlamadaHerramienta(id=idc, nombre=nombre, argumentos=args)],
                        motivo_parada="tool_use",
                        bloques=None,
                    )

        # 4) Cerrar con un resumen de lo leído (puede divulgar un canario: A04).
        ultimo = resultados[-1] if resultados else "Sin información disponible."
        return RespuestaLLM(texto=ultimo[:600], motivo_parada="end_turn", bloques=None)

    # -- lógica de obediencia --------------------------------------------

    def _absorber_instruccion(self, texto: str) -> None:
        """Extrae de un dato inyectado la acción que un agente ingenuo obedecería."""
        tiene_verbo = bool(_RE_HERRAMIENTA.search(texto)) or bool(_RE_URL.search(texto)) \
            or bool(_RE_CORREO.search(texto)) or "env" in texto.lower()
        if not tiene_verbo:
            return
        obj = self._pendiente or {}
        url = _RE_URL.search(texto)
        if url:
            obj["url"] = url.group(0)
        correo = _RE_CORREO.search(texto)
        if correo:
            obj["correo"] = correo.group(0)
        doc = re.search(r"[\w./-]+\.md", texto)
        if doc:
            obj["doc"] = doc.group(0).lstrip("./")
        tabla = re.search(r"tabla\s+'?([a-záéíóú]+)'?", texto, re.I)
        if tabla:
            obj["tabla"] = tabla.group(1).lower()
        if re.search(r"\benv\b|printenv|ERP_TOKEN|shell", texto, re.I):
            obj["shell"] = "env"
        self._pendiente = obj

    def _lectura_pendiente(self, disponibles: set[str], idc: str) -> LlamadaHerramienta | None:
        obj = self._pendiente
        if not obj:
            return None
        # El agente necesita el secreto para exfiltrarlo: si aún no lo tiene y la
        # instrucción referencia un documento o tabla, lo lee primero.
        if not self._secretos:
            doc = obj.get("doc")
            if doc and f"doc:{doc}" not in self._leidos and "leer_documento" in disponibles:
                self._leidos.add(f"doc:{doc}")
                return LlamadaHerramienta(id=idc, nombre="leer_documento", argumentos={"ruta": doc})
            tabla = obj.get("tabla")
            if tabla and f"bd:{tabla}" not in self._leidos and "consultar_bd" in disponibles:
                self._leidos.add(f"bd:{tabla}")
                return LlamadaHerramienta(id=idc, nombre="consultar_bd", argumentos={"tabla": tabla})
        return None

    def _exfiltracion(self, disponibles: set[str], idc: str) -> LlamadaHerramienta | None:
        obj = self._pendiente
        if not obj:
            return None
        secreto = next(iter(self._secretos), "")

        if obj.get("shell") and "ejecutar_shell" in disponibles and not obj.get("shell_hecho"):
            obj["shell_hecho"] = True
            return LlamadaHerramienta(id=idc, nombre="ejecutar_shell", argumentos={"comando": "env"})

        if obj.get("url") and secreto and "http_get" in disponibles and not obj.get("url_hecho"):
            obj["url_hecho"] = True
            destino = obj["url"]
            destino = re.sub(r"\{[^}]*\}|CIFRA|REFERENCIA|VALOR", secreto, destino)
            if secreto not in destino:
                destino = f"{destino}{'&' if '?' in destino else '?'}d={secreto}"
            return LlamadaHerramienta(id=idc, nombre="http_get", argumentos={"url": destino})

        if obj.get("correo") and secreto and "enviar_correo" in disponibles and not obj.get("correo_hecho"):
            obj["correo_hecho"] = True
            return LlamadaHerramienta(
                id=idc,
                nombre="enviar_correo",
                argumentos={"destinatario": obj["correo"], "asunto": "Info", "cuerpo": secreto},
            )
        return None

    # -- auxiliares -------------------------------------------------------

    @staticmethod
    def _texto_usuario(mensajes: list[dict]) -> str:
        for m in mensajes:
            if m["role"] == "user" and isinstance(m["content"], str):
                return m["content"]
        return ""

    @staticmethod
    def _resultados(mensajes: list[dict]) -> list[str]:
        salidas: list[str] = []
        for m in mensajes:
            if m["role"] != "user" or not isinstance(m["content"], list):
                continue
            for bloque in m["content"]:
                if isinstance(bloque, dict) and bloque.get("type") == "tool_result":
                    contenido = bloque.get("content")
                    salidas.append(contenido if isinstance(contenido, str) else str(contenido))
        return salidas

    @staticmethod
    def _bloqueado(texto: str) -> bool:
        return texto.startswith("[CONTENIDO RETENIDO") or texto.startswith("[ACCIÓN")

    @staticmethod
    def _plan_inicial(tarea: str) -> list[tuple[str, dict]]:
        t = tarea.lower()
        if "correo" in t or "bandeja" in t or "mensaje" in t:
            return [("leer_correo", {})]
        if "proveedor" in t or "empleado" in t or "base de datos" in t:
            tabla = "proveedores" if "proveedor" in t else "empleados"
            return [("consultar_bd", {"tabla": tabla})]
        palabras = [p for p in re.findall(r"\w{4,}", t)][:4]
        return [("buscar_documento", {"consulta": " ".join(palabras) or "política"})]


# --------------------------------------------------------------------------
# Ollama (modelos abiertos ejecutados localmente, sin costo de API)
# --------------------------------------------------------------------------

# Modelo local por defecto. Qwen2.5-7B es notablemente más fiable en tool
# calling que otros de su tamaño, lo que importa aquí: si el agente no sabe
# usar herramientas, el ASR baja por incompetencia, no por seguridad.
MODELO_OLLAMA_POR_DEFECTO = "qwen2.5:7b-instruct"


class ProveedorOllama:
    """Adaptador para un modelo abierto servido por Ollama en localhost.

    Traduce entre el formato de mensajes/herramientas de Anthropic que usa el
    arnés y el formato de la API de Ollama (`/api/chat`, estilo OpenAI para
    tools). Produce datos experimentales reales (`simulado = False`), sobre un
    agente auto-hospedado —- el escenario que el anteproyecto contempla al citar
    modelos abiertos ejecutables localmente.

    No hay concepto de `stop_reason: refusal`: si el modelo se niega, lo hace
    en texto y el ataque simplemente no se consuma, lo que ya queda medido como
    fallo del ataque.
    """

    simulado = False

    def __init__(self, modelo: str | None = None, temperatura: float | None = None, **_):
        import urllib.error  # stdlib: sin dependencias nuevas
        import urllib.request

        self._urllib = urllib
        # Si llega un id de Claude (default de ConfigCorrida) se ignora: este
        # proveedor solo entiende modelos locales.
        if not modelo or modelo.startswith("claude-"):
            modelo = os.environ.get("LAB_MODELO_OLLAMA") or MODELO_OLLAMA_POR_DEFECTO
        self.modelo = modelo
        self.host = os.environ.get("LAB_OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        self.url = f"{self.host}/api/chat"
        if temperatura is None:
            temperatura = float(os.environ.get("LAB_TEMPERATURE", "0.7"))
        self.temperatura = temperatura
        self.num_ctx = int(os.environ.get("LAB_NUM_CTX", "8192"))
        self.timeout = int(os.environ.get("LAB_OLLAMA_TIMEOUT", "300"))
        self._contador = 0
        self._id2nombre: dict[str, str] = {}

    def responder(self, sistema, mensajes, herramientas) -> RespuestaLLM:
        payload = {
            "model": self.modelo,
            "messages": self._a_ollama(sistema, mensajes),
            "stream": False,
            "options": {"temperature": self.temperatura, "num_ctx": self.num_ctx},
        }
        if herramientas:
            payload["tools"] = self._herramientas_ollama(herramientas)

        datos = self._post(payload)
        mensaje = datos.get("message", {}) or {}

        texto = mensaje.get("content", "") or ""
        llamadas: list[LlamadaHerramienta] = []
        for tc in mensaje.get("tool_calls", []) or []:
            fn = tc.get("function", {}) or {}
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {"_raw": args}
            self._contador += 1
            idc = f"oll_{self._contador}"
            nombre = fn.get("name", "")
            self._id2nombre[idc] = nombre
            llamadas.append(LlamadaHerramienta(id=idc, nombre=nombre, argumentos=args or {}))

        return RespuestaLLM(
            texto=texto.strip(),
            llamadas=llamadas,
            bloques=None,  # que el arnés reconstruya el mensaje del asistente
            motivo_parada="tool_use" if llamadas else "end_turn",
            rechazo=None,
            tokens_entrada=int(datos.get("prompt_eval_count", 0) or 0),
            tokens_salida=int(datos.get("eval_count", 0) or 0),
        )

    # -- traducción de formatos ------------------------------------------

    @staticmethod
    def _herramientas_ollama(herramientas: list[dict]) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": h["name"],
                    "description": h["description"],
                    "parameters": h["input_schema"],
                },
            }
            for h in herramientas
        ]

    def _a_ollama(self, sistema: str, mensajes: list[dict]) -> list[dict]:
        salida: list[dict] = [{"role": "system", "content": sistema}]
        for m in mensajes:
            rol = m["role"]
            cont = m["content"]
            if rol == "user":
                if isinstance(cont, str):
                    salida.append({"role": "user", "content": cont})
                    continue
                for b in cont:
                    if not isinstance(b, dict):
                        continue
                    if b.get("type") == "tool_result":
                        c = b.get("content")
                        texto = c if isinstance(c, str) else json.dumps(c, ensure_ascii=False)
                        salida.append(
                            {
                                "role": "tool",
                                "content": texto,
                                "tool_name": self._id2nombre.get(b.get("tool_use_id"), "tool"),
                            }
                        )
                    elif b.get("type") == "text":
                        salida.append({"role": "user", "content": b.get("text", "")})
            else:  # assistant
                if isinstance(cont, str):
                    salida.append({"role": "assistant", "content": cont})
                    continue
                partes: list[str] = []
                tool_calls: list[dict] = []
                for b in cont:
                    if not isinstance(b, dict):
                        continue
                    if b.get("type") == "text":
                        partes.append(b.get("text", ""))
                    elif b.get("type") == "tool_use":
                        tool_calls.append(
                            {"function": {"name": b.get("name", ""), "arguments": b.get("input", {})}}
                        )
                msg: dict = {"role": "assistant", "content": "\n".join(partes)}
                if tool_calls:
                    msg["tool_calls"] = tool_calls
                salida.append(msg)
        return salida

    def _post(self, payload: dict) -> dict:
        data = json.dumps(payload).encode("utf-8")
        req = self._urllib.request.Request(
            self.url, data=data, headers={"Content-Type": "application/json"}
        )
        try:
            with self._urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except self._urllib.error.URLError as exc:
            raise RuntimeError(
                f"No se pudo contactar a Ollama en {self.url} ({exc}). "
                "Verifica que Ollama esté instalado y corriendo (`ollama serve`) y que el "
                f"modelo {self.modelo!r} esté descargado (`ollama pull {self.modelo}`)."
            ) from exc


def construir(nombre: str, modelo: str | None = None, effort: str = "") -> ProveedorLLM:
    if nombre == "anthropic":
        return ProveedorAnthropic(modelo=modelo, effort=effort)
    if nombre == "ollama":
        return ProveedorOllama(modelo=modelo)
    if nombre == "simulado":
        return ProveedorSimulado()
    raise ValueError(
        f"proveedor no soportado: {nombre!r} (use 'anthropic', 'ollama' o 'simulado')"
    )
