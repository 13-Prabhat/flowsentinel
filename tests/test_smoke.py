import flowsentinel


def test_version_is_a_non_empty_string():
    assert isinstance(flowsentinel.__version__, str)
    assert flowsentinel.__version__