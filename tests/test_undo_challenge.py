import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "local-engine"))
import undo_challenge as undo


def main():
    result = undo.analyze("Undo\npicoCTF", "Stage 1: encoded with ROT13\nStage 2: reversed using rev")
    assert result["ok"] and result["analyzer"] == "undo", result
    assert [s["operation"] for s in result["inverse_steps"]] == ["rev", "rot13"], result
    assert result["inverse_steps"][0]["inverse_command"] == "rev", result
    assert result["inverse_steps"][1]["inverse_command"] == "tr 'A-Za-z' 'N-ZA-Mn-za-m'", result

    mapped = undo.analyze("Undo", "The original string was translated using tr 'abc' 'xyz'")
    assert mapped["inverse_steps"][0]["inverse_command"] == "tr 'xyz' 'abc'", mapped
    lossy = undo.analyze("Undo", "The string was translated using tr 'aabc' 'xyzz'")
    assert "غير قابل للعكس" in lossy["inverse_steps"][0]["inverse_command"], lossy

    empty = undo.analyze("Undo", "  ")
    assert not empty["ok"]
    print("Undo challenge explanation tests passed")


if __name__ == "__main__":
    main()
