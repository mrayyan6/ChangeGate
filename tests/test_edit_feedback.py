from pathlib import Path

from changegate.workspace import _apply_edit


def test_ambiguous_match_reports_line_numbers(tmp_path: Path):
    (tmp_path / "a.tf").write_text("x = 1\ny = 2\nx = 1\n", encoding="utf-8")
    res = _apply_edit(tmp_path, "a.tf", "x = 1", "x = 2", tolerant=True)
    assert not res.ok and "line 1" in res.message and "line 3" in res.message


def test_not_found_shows_surrounding_file_text(tmp_path: Path):
    (tmp_path / "a.tf").write_text('a = 1\n  size = "big"\nb = 2\n', encoding="utf-8")
    res = _apply_edit(tmp_path, "a.tf", '  size = "bigg"', "  size = 1", tolerant=True)
    assert not res.ok and "File text around line 2" in res.message and 'size = "big"' in res.message
