"""
Shared NSL-KDD schema for Sentinel AIOps.

Single source of truth for column names, feature lists and the attack-name
to attack-family mapping. Imported by train.py and by the API server.

Dataset: Tavallaee, Bagheri, Lu, Ghorbani (2009), "A Detailed Analysis of the
KDD CUP 99 Data Set", IEEE CISDA. Hosted by the University of New Brunswick.
"""
import pandas as pd

COLUMN_NAMES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files',
    'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count',
    'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]
CATEGORICAL = ['protocol_type', 'service', 'flag']
FEATURES = [c for c in COLUMN_NAMES if c not in ('label', 'difficulty')]
NUMERIC = [c for c in FEATURES if c not in CATEGORICAL]

FAMILIES = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R']

# Standard NSL-KDD grouping of attack names into 4 families (+ Normal).
ATTACK_FAMILY = {'normal': 'Normal'}
for _name in ['back', 'land', 'neptune', 'pod', 'smurf', 'teardrop',
              'mailbomb', 'apache2', 'processtable', 'udpstorm', 'worm']:
    ATTACK_FAMILY[_name] = 'DoS'
for _name in ['ipsweep', 'nmap', 'portsweep', 'satan', 'mscan', 'saint']:
    ATTACK_FAMILY[_name] = 'Probe'
for _name in ['ftp_write', 'guess_passwd', 'imap', 'multihop', 'phf', 'spy',
              'warezclient', 'warezmaster', 'sendmail', 'named',
              'snmpgetattack', 'snmpguess', 'xlock', 'xsnoop', 'httptunnel']:
    ATTACK_FAMILY[_name] = 'R2L'
for _name in ['buffer_overflow', 'loadmodule', 'perl', 'rootkit', 'ps',
              'sqlattack', 'xterm']:
    ATTACK_FAMILY[_name] = 'U2R'


def load_nsl_kdd(path):
    """Read one NSL-KDD file and add a 'family' column.

    Raises if a label is missing from ATTACK_FAMILY instead of silently
    guessing, so a bad mapping can never skew the metrics unnoticed.
    """
    df = pd.read_csv(path, names=COLUMN_NAMES)
    df['family'] = df['label'].map(ATTACK_FAMILY)
    unmapped = sorted(df.loc[df['family'].isna(), 'label'].unique())
    if unmapped:
        raise ValueError(f"Attack labels missing from ATTACK_FAMILY: {unmapped}")
    return df