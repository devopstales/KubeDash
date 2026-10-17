def test_dockerfile_runs_use_no_user_and_fixed_args():
    import pathlib
    import re
    df = pathlib.Path(__file__).resolve().parents[1] / "Dockerfile"
    text = df.read_text()
    assert re.search(r"^USER 10001", text, re.M), "must run non-root"
    # threat matrix: no unquoted command-substitution from ARGs in RUN lines
    for line in text.splitlines():
        if line.strip().startswith("RUN"):
            assert "$(" not in line or "${" in line, f"unquoted $() in RUN: {line}"
