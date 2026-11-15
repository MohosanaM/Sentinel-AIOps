import pandas as pd
import pytest

import schema


def test_every_family_is_known():
    assert set(schema.ATTACK_FAMILY.values()) <= set(schema.FAMILIES)
    assert set(schema.FAMILIES) == set(schema.ATTACK_FAMILY.values())


def test_feature_lists():
    assert len(schema.FEATURES) == 41
    assert 'label' not in schema.FEATURES
    assert 'difficulty' not in schema.FEATURES
    assert set(schema.CATEGORICAL) <= set(schema.FEATURES)
    assert set(schema.NUMERIC) | set(schema.CATEGORICAL) == set(schema.FEATURES)


def _row(label):
    row = {c: 0 for c in schema.COLUMN_NAMES}
    row.update(protocol_type='tcp', service='http', flag='SF', label=label)
    return row


def _write(tmp_path, labels):
    path = tmp_path / 'data.txt'
    pd.DataFrame([_row(lab) for lab in labels])[schema.COLUMN_NAMES].to_csv(
        path, header=False, index=False)
    return path


def test_load_adds_family(tmp_path):
    df = schema.load_nsl_kdd(_write(tmp_path, ['normal', 'neptune', 'nmap']))
    assert list(df['family']) == ['Normal', 'DoS', 'Probe']


def test_unknown_label_is_rejected_not_guessed(tmp_path):
    with pytest.raises(ValueError, match='totally_new_attack'):
        schema.load_nsl_kdd(_write(tmp_path, ['normal', 'totally_new_attack']))
