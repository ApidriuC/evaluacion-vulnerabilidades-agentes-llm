"""Pruebas del arnés experimental.

Verifican que la instrumentación mide lo que dice medir, usando el proveedor
simulado (sin red). Si estas pruebas pasan, un cambio en el ASR bajo el
proveedor real es atribuible al modelo o a la defensa, no a un bug del arnés.
"""

import sys
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "src"))

from lab import canarios, escenarios as mod_esc, metricas, runner  # noqa: E402
from lab.config import CONFIGURACIONES, ConfigCorrida  # noqa: E402
from lab import entorno as mod_entorno  # noqa: E402

DIR_ESC = RAIZ / "escenarios"


def test_canario_forma_y_deteccion():
    v = canarios.generar("CRD", "token_erp")
    assert canarios.PATRON.fullmatch(v)
    assert canarios.detectar(f"basura {v} mas basura") == {v}
    assert canarios.detectar_en({"url": f"http://x/?k={v}"}) == {v}


def test_canario_determinista():
    assert canarios.generar("FIN", "ebitda_q3", 20260901) == canarios.generar("FIN", "ebitda_q3", 20260901)


def test_entorno_reconstruye_identico():
    a = mod_entorno.reconstruir()
    b = mod_entorno.reconstruir()
    assert a.valores_canario == b.valores_canario
    assert a.canario("token_erp").startswith("CAN-CRD-")


def test_todos_los_escenarios_validan():
    escs = mod_esc.cargar_directorio(DIR_ESC)
    assert len(escs) >= 10
    ids = [e.id for e in escs]
    assert len(ids) == len(set(ids)), "hay IDs de escenario duplicados"


def test_fisher_casos_conocidos():
    # Independencia total -> p alto.
    assert metricas.fisher_exacto(15, 15, 15, 15) > 0.9
    # Separación total -> p bajo.
    assert metricas.fisher_exacto(30, 0, 0, 30) < 0.001


def test_wilson_acotado():
    lo, hi = metricas.wilson(0, 30)
    assert lo == 0.0 and 0 < hi < 0.2
    lo, hi = metricas.wilson(30, 30)
    assert hi == 1.0 and 0.8 < lo < 1.0


def _asr_global(salida, politica):
    registros = [r for r in metricas.cargar([salida]) if r["politica"] == politica]
    celdas = metricas.agregar(registros)
    fila = next(f for f in metricas.resumen_por_politica(celdas) if f["politica"] == politica)
    return fila["asr"]


def test_defensa_reduce_asr_simulado(tmp_path):
    escs = mod_esc.cargar_directorio(DIR_ESC)
    salida = tmp_path / "humo.jsonl"
    for nombre in ("C0", "C4"):
        cfg = ConfigCorrida(politica=CONFIGURACIONES[nombre], proveedor="simulado", repeticiones=3)
        runner.ejecutar_campana(escs, cfg, salida, verboso=False)
    asr_base = _asr_global(salida, "C0")
    asr_duro = _asr_global(salida, "C4")
    assert asr_base > 0, "el agente ingenuo debería caer en algún ataque bajo C0"
    assert asr_duro < asr_base, "la defensa completa debería reducir el ASR simulado"


def test_utilidad_se_conserva_bajo_defensa(tmp_path):
    escs = [e for e in mod_esc.cargar_directorio(DIR_ESC) if e.tipo == "utilidad"]
    salida = tmp_path / "util.jsonl"
    cfg = ConfigCorrida(politica=CONFIGURACIONES["C4"], proveedor="simulado", repeticiones=3)
    runner.ejecutar_campana(escs, cfg, salida, verboso=False)
    registros = metricas.cargar([salida])
    exitos = sum(bool(r["exito"]) for r in registros)
    assert exitos >= 1, "al menos una tarea legítima debe resolverse bajo C4"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
