import sys
from pathlib import Path
import numpy as np

# Resolve monorepo root so `ml` package is importable from the backend
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ml.features.extractor import URLFeatureExtractor  # noqa: E402
from app.models.scan import URLFeatures

_extractor = URLFeatureExtractor()


def extract(url: str) -> tuple[URLFeatures, np.ndarray]:
    raw = _extractor.extract(url)
    features = URLFeatures(**raw)
    vector = _extractor.to_vector(raw)
    return features, vector
