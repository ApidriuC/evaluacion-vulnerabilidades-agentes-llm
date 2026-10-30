"""Ejecutor de campañas experimentales.

Una campaña = (conjunto de escenarios) x (una política) x (N repeticiones).

Las repeticiones no son opcionales. Un agente basado en LLM es estocástico: el
mismo ataque puede tener éxito en una corrida y fallar en la siguiente. Reportar
"el ataque funcionó" tras una sola ejecución no es un resultado, es una anécdota.
N>=30 permite estimar el ASR con un intervalo de confianza utilizable.

Cada corrida parte de un entorno reconstruido desde cero, para que no haya
contaminación entre repeticiones.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from pathlib import Path

from . import entorno as mod_entorno
from . import escenarios as mod_escenarios
from . import herramientas as mod_herramientas
from . import defensas, proveedores
from .agente import Agente
from .config import ConfigCorrida
from .escenarios import Escenario


def _una_corrida(escenario: Escenario, config: ConfigCorrida, repeticion: int) -> dict:
    ent = mod_entorno.reconstruir(config.semilla)
    escenario.preparar(ent)

    disponibles = mod_herramientas.seleccionar(None)
    expuestas = defensas.filtrar_herramientas(
        config.politica, disponibles, escenario.herramientas_requeridas
    )

    proveedor = proveedores.construir(config.proveedor, config.modelo, config.effort)
    agente = Agente(proveedor, expuestas, config.politica, ent)
    res = agente.ejecutar(escenario.tarea)

    exito, evidencia = mod_escenarios.evaluar(escenario, res)

    return {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "escenario": escenario.id,
        "escenario_nombre": escenario.nombre,
        "tipo": escenario.tipo,
        "categoria_owasp": escenario.categoria_owasp,
        "tecnica_atlas": escenario.tecnica_atlas,
        "canal": escenario.canal,
        "politica": config.politica.nombre,
        "modelo": proveedor.modelo,
        "proveedor": config.proveedor,
        "simulado": proveedor.simulado,
        "effort": config.effort or "default",
        "temperatura": getattr(proveedor, "temperatura", None),
        "repeticion": repeticion,
        "exito": exito,
        "evidencia": evidencia,
        "rechazo": res.rechazo,
        "error": res.error,
        "iteraciones": res.iteraciones,
        "herramientas_expuestas": sorted(h.nombre for h in expuestas),
        "llamadas": res.llamadas,
        "bloqueos": res.bloqueos,
        "tokens_entrada": res.tokens_entrada,
        "tokens_salida": res.tokens_salida,
        "segundos": res.segundos,
        "respuesta_final": (res.respuesta_final or "")[:3000],
    }


def ejecutar_campana(
    escenarios: list[Escenario],
    config: ConfigCorrida,
    salida: Path,
    verboso: bool = True,
) -> Path:
    salida.parent.mkdir(parents=True, exist_ok=True)
    total = len(escenarios) * config.repeticiones
    hecho = 0
    fallos = 0

    with salida.open("a", encoding="utf-8") as fh:
        for escenario in escenarios:
            exitos = 0
            for repeticion in range(1, config.repeticiones + 1):
                registro = _una_corrida(escenario, config, repeticion)
                fh.write(json.dumps(registro, ensure_ascii=False) + "\n")
                fh.flush()  # una campaña larga no debe perderse por una caída
                hecho += 1
                exitos += bool(registro["exito"])
                fallos += bool(registro["error"])
            if verboso:
                asr = exitos / config.repeticiones
                marca = "!" if escenario.tipo == "ataque" and asr > 0 else " "
                print(
                    f"{marca} [{hecho:>4}/{total}] {escenario.id:<12} {config.politica.nombre}  "
                    f"{'ASR' if escenario.tipo == 'ataque' else 'OK '}={asr:6.1%}  ({exitos}/{config.repeticiones})"
                )

    if fallos and verboso:
        print(f"\nAviso: {fallos} corrida(s) terminaron con error de ejecución; revísalas en {salida.name}.")
    return salida
