# -*- coding: utf-8 -*-
import json
from datetime import timezone
from typing import Dict

import pandas as pd
from cloudproof_anonymization import Hasher, NoiseGenerator, NumberScaler
from cloudproof_fpe import Alphabet  # , Float, Integer
from dateutil import parser as date_parser

DURATION_IN_SECONDS = {
    "Second": 1,
    "Minute": 60,
    "Hour": 3600,
    "Day": 86400,
    "Month": 2_628_000,
    "Year": 31_536_000,
}


def parse_noise_options(opts):
    # TODO: rename method to distribution and optionType to a better name
    if opts["optionType"] == "params":
        if "mean" in opts and "stdDev" in opts:
            return NoiseGenerator.new_with_parameters(
                opts["method"], opts["mean"], opts["stdDev"]
            )
        else:
            raise ValueError("Missing noise mean or standard deviation.")
    elif opts["optionType"] == "bounds":
        if "minBound" in opts and "maxBound" in opts:
            return NoiseGenerator.new_with_bounds(
                opts["method"], opts["minBound"], opts["maxBound"]
            )
        else:
            raise ValueError("Missing noise bounds.")
    else:
        raise ValueError("Invalid noise parameter: {}.", opts["optionType"])


def parse_date_noise_options(data_type: str, opts):
    opt_std_dev = opts["stdDev"]
    std_dev = opt_std_dev["precision"] * DURATION_IN_SECONDS[opt_std_dev["unit"]]
    noise_generator = parse_noise_options(
        {
            "optionType": opts["optionType"],
            "method": opts["method"],
            "mean": opts["mean"],
            "stdDev": std_dev,
        }
    )

    if data_type == "Date":

        def date_to_isoformat(date_str: str) -> str:
            dt = date_parser.parse(date_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()

        return lambda date_str: noise_generator.apply_on_date(
            date_to_isoformat(date_str)
        )
    else:
        raise ValueError(f"Invalid type '{data_type}' for method Date Noise.")


def parse_fpe_string_options(data_type: str, opts: Dict):
    if data_type == "Text":
        # TODO: what about key and tweak?
        return lambda val: Alphabet(opts["alphabet"]).encrypt(
            b"A" * 32, bytes([10]), val
        )
    else:
        raise ValueError(f"Invalid type '{data_type}' for method FPE string.")


def parse_hash_options(data_type: str, opts: Dict, encoding="utf-8"):
    hasher = None
    if "saltValue" in opts:
        salt = opts["saltValue"].encode("utf-8")
        hasher = Hasher(opts["hashType"], salt)
    else:
        hasher = Hasher(opts["hashType"])

    if data_type == "Text":
        return lambda val: hasher.apply(val.encode(encoding))
    else:
        raise ValueError(f"Invalid type '{data_type}' for method Hash.")


def parse_rescaling_options(data_type: str, opts: Dict):
    scaler = NumberScaler(
        opts["mean"], opts["stdDev"], opts["scale"], opts["translation"]
    )
    if data_type == "Integer":
        return scaler.apply_on_int
    elif data_type == "Float":
        return scaler.apply_on_float
    else:
        raise ValueError(f"Invalid type '{data_type}' for method Rescaling.")


def create_transformation_function(method_name: str, data_type: str, method_opts: Dict):
    if method_name == "Fpe_string":
        return parse_fpe_string_options(data_type, method_opts)
    elif method_name == "Date_noise":
        return parse_date_noise_options(data_type, method_opts)
    elif method_name == "Hash":
        return parse_hash_options(data_type, method_opts)
    elif method_name == "Rescaling":
        return parse_rescaling_options(data_type, method_opts)

    else:
        raise ValueError(f"Unknown method named: {method_name}.")


def anonymize_dataframe(df: pd.DataFrame, config: Dict):
    anonymized_df = pd.DataFrame()

    for column_metadata in conf["metadata"]:
        col_name = column_metadata["name"]
        col_type = column_metadata["type"]
        method_name = column_metadata["technique"]
        method_opts = column_metadata["techniqueOptions"]

        transform_func = create_transformation_function(
            method_name, col_type, method_opts
        )
        anonymized_df[col_name] = df[col_name].apply(transform_func)

    return anonymized_df


if __name__ == "__main__":
    df = pd.read_csv("./tests/data/anonymization/data.csv", sep=";")
    with open("./tests/data/anonymization/config.json", "r") as f:
        conf = json.load(f)

    print(anonymize_dataframe(df, conf))
