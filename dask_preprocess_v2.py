#!/usr/bin/env python3
"""Preprocessing for Gen-C-DDD-2022 style captures (Section 6.13): column mapping, feature extraction,
protocol-stratified train/val/test split with fixed seeds. Column names differ between dataset releases,
so they are mapped in configs/v2/dataset_columns_v2.yaml instead of being hard-coded."""
import argparse, json, os, yaml
import numpy as np, pandas as pd
def load(path, cols, use_dask):
    if use_dask:
        import dask.dataframe as dd; return dd.read_csv(path, assume_missing=True)
    return pd.read_csv(path)
def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--input", required=True); ap.add_argument("--out", default="data/v2/processed"); ap.add_argument("--columns", default="configs/v2/dataset_columns_v2.yaml")
    ap.add_argument("--seed", type=int, default=11); ap.add_argument("--dask", action="store_true"); a = ap.parse_args()
    cfg = yaml.safe_load(open(a.columns)); os.makedirs(a.out, exist_ok=True)
    df = load(a.input, cfg["columns"], a.dask)
    if a.dask: df = df.compute()
    m = cfg["columns"]; X = pd.DataFrame({k: df[v] for k, v in m.items() if v in df.columns})
    X["label"] = df[cfg["label_column"]].map(cfg["label_map"]).astype(int)
    X["proto"] = df[cfg["protocol_column"]].map(cfg["protocol_map"])
    r = np.random.default_rng(a.seed); parts = {"train": [], "val": [], "test": []}
    for (p, y), g in X.groupby(["proto", "label"]):
        idx = r.permutation(len(g)); n1, n2 = int(.6 * len(g)), int(.8 * len(g))
        parts["train"].append(g.iloc[idx[:n1]]); parts["val"].append(g.iloc[idx[n1:n2]]); parts["test"].append(g.iloc[idx[n2:]])
    counts = {}
    for k, v in parts.items():
        d = pd.concat(v); d.to_parquet(os.path.join(a.out, f"{k}.parquet")) if hasattr(d, "to_parquet") else d.to_csv(os.path.join(a.out, f"{k}.csv"), index=False)
        counts[k] = d.groupby(["proto", "label"]).size().rename("n").reset_index().to_dict("records")
    json.dump(dict(seed=a.seed, counts=counts), open(os.path.join(a.out, "split_manifest.json"), "w"), indent=2); print("wrote", a.out)
if __name__ == "__main__": main()
