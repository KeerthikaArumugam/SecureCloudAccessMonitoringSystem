# Dataset audit and external dataset adapter

## Dataset audit

This project currently uses the local synthetic authentication dataset stored in `dataset/logon.csv` and the processed matrix saved in `dataset/final_training_dataset.csv`.

### Current dataset snapshot
- Rows: 854,859
- Columns: `id`, `date`, `user`, `pc`, `activity`
- Duplicate rows: 0 in the raw source
- Missing values: none in the raw file
- Class balance in the processed training matrix: 81,768 normal vs 37,175 suspicious samples, or about 4.35% suspicious

### Important limitation
This dataset is synthetic and is not a real-world malicious-login dataset. The target labels were generated using time-based rules such as off-hours and weekend heuristics. That makes the dataset useful for local engineering testing but not scientifically defensible as ground-truth attack data.

### Current production consideration
The model should not treat off-hours or weekend heuristics as the final ground-truth suspicious label. These values may remain as behavioural signals, but they must not be used as a direct target definition in the final production pipeline.

## External dataset adapter

The project includes `training/datasets/dataset_adapter.py`, which normalizes an external authentication or login dataset into the common schema:

- user
- timestamp
- ip_address
- device
- browser
- activity
- authentication_result
- target

This adapter is designed for real security-authentication datasets such as login attempts, successful/failed authentications, or session event logs.

### How to use it
1. Place a real labelled security/authentication dataset in a local folder, for example:
   - `data/security_auth_events.csv`
   - `datasets/auth_events.csv`
2. Read the dataset with pandas.
3. Call `normalize_security_dataset(df)`.
4. Save the normalized output to a project-local CSV if needed.

### Important note
No public dataset is bundled or downloaded automatically in this repository. If a dataset is not available locally, the adapter is still provided as a real integration point, but the project must clearly report that no real labelled security dataset is currently in use.
