from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def data_path():
    return Path(__file__).parent / "data"


@pytest.fixture(scope="module")
def pccs_url():
    return "https://pccs.mse.cosmian.com"
