# -*- coding: utf-8 -*-
import json
from datetime import timezone
from typing import Callable, Dict, Optional

import pandas as pd
from cloudproof_anonymization import (
    DateAggregator,
    Hasher,
    NoiseGenerator,
    NumberAggregator,
    NumberScaler,
    WordMasker,
    WordPatternMasker,
    WordTokenizer,
)
from cloudproof_fpe import Alphabet, Integer
from dateutil import parser as date_parser
from humps import decamelize

DURATION_IN_SECONDS = {
    "Second": 1,
    "Minute": 60,
    "Hour": 3600,
    "Day": 86400,
    "Month": 2_628_000,
    "Year": 31_536_000,
}


def parse_noise_options(
    distribution: str,
    mean: Optional[float] = None,
    std_dev: Optional[float] = None,
    lower_boundary: Optional[float] = None,
    upper_boundary: Optional[float] = None,
):
    """
    Returns a `NoiseGenerator` object based on the specified options.

    Args:
        method (str): The distribution to use for generating noise.
        option_type (str): Whether the noise options are specified as parameters or bounds.
        mean (float, optional): The mean value to use for generating noise if `option_type` is `params`.
        std_dev (float, optional): The standard deviation value to use for generating noise if `option_type` is `params`.
        min_bound (float, optional): The minimum value to use for generating noise if `option_type` is `bounds`.
        max_bound (float, optional): The maximum value to use for generating noise if `option_type` is `bounds`.
    """
    if mean is not None and std_dev is not None:
        return NoiseGenerator.new_with_parameters(distribution, mean, std_dev)
    elif lower_boundary is not None and upper_boundary is not None:
        return NoiseGenerator.new_with_bounds(
            distribution, lower_boundary, upper_boundary
        )
    else:
        raise ValueError("Missing noise options.")


def parse_date_noise_options(
    distribution: str,
    mean: Optional[Dict] = None,
    std_dev: Optional[Dict] = None,
    lower_boundary: Optional[Dict] = None,
    upper_boundary: Optional[Dict] = None,
) -> Callable[[str], str]:
    """
    Returns a lambda function that takes a date string and returns a noisy version of that date.

    Args:
        distribution (str): A string indicating the distribution to use for generating noise.
        mean (float, optional): The mean value to use for generating noise.
        std_dev (Dict, optional): A dictionary with the following keys:
            - precision (float): The precision value for the noise generator.
            - unit (str): A string indicating the unit of time for the noise generator.
        min_bound (Dict, optional):
            - precision (float): The precision value for the minimum bound.
            - unit (str): A string indicating the unit of time for the minimum bound.
        max_bound (Dict, optional):
            - precision (float): The precision value for the maximum bound.
            - unit (str): A string indicating the unit of time for the maximum bound.
    """

    mean_secs: Optional[float] = None
    std_dev_secs: Optional[float] = None
    if mean is not None and std_dev is not None:
        # Convert mean and standard deviation to seconds
        mean_secs = mean["precision"] * DURATION_IN_SECONDS[mean["unit"]]
        std_dev_secs = std_dev["precision"] * DURATION_IN_SECONDS[std_dev["unit"]]

    lower_boundary_secs: Optional[float] = None
    upper_boundary_secs: Optional[float] = None
    if lower_boundary is not None and upper_boundary is not None:
        # Convert range to seconds
        lower_boundary_secs = (
            lower_boundary["precision"] * DURATION_IN_SECONDS[lower_boundary["unit"]]
        )
        upper_boundary_secs = (
            upper_boundary["precision"] * DURATION_IN_SECONDS[upper_boundary["unit"]]
        )

    noise_generator = parse_noise_options(
        distribution,
        mean=mean_secs,
        std_dev=std_dev_secs,
        lower_boundary=lower_boundary_secs,
        upper_boundary=upper_boundary_secs,
    )

    def date_to_isoformat(date_str: str) -> str:
        # Convert the date string to ISO format with timezone.
        dt = date_parser.parse(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    # Define a lambda function that applies the noise generator to the ISO-formatted date
    return lambda date_str: noise_generator.apply_on_date(date_to_isoformat(date_str))


def parse_fpe_string_options(alphabet: str) -> Callable[[str], str]:
    # TODO: what about key and tweak?
    return lambda val: Alphabet(alphabet).encrypt(b"A" * 32, bytes([10]), val)


def parse_fpe_integer_options(radix: int, digit: int) -> Callable[[int], int]:
    # TODO: what about key and tweak?
    return lambda val: Integer(radix, digit).encrypt(b"A" * 32, bytes([10]), val)


def parse_hash_options(
    hash_type: str, salt_value: Optional[str] = None, encoding="utf-8"
) -> Callable[[str], str]:
    """
    Returns a function that takes a string and applies a hash function to it.

    Args:
        hash_type (str): The name of the hash function to use.
        salt_value (Optional[str]): An optional salt to use for hashing.
        encoding (str): The encoding to use when converting the input string to bytes.
    """
    salt = None
    if salt_value:
        salt = salt_value.encode("utf-8")
    hasher = Hasher(hash_type, salt)

    return lambda val: hasher.apply(val.encode(encoding))


def create_transformation_function(method_name: str, method_opts: Dict) -> Callable:
    """
    Given a method name and options, returns a callable that applies the desired transformation.
    """
    parsing_functions: Dict[str, Callable] = {
        "FpeString": parse_fpe_string_options,
        "FpeInteger": parse_fpe_integer_options,
        "TokenizeWords": lambda **kwargs: WordTokenizer(**kwargs).apply,
        "MaskWords": lambda **kwargs: WordMasker(**kwargs).apply,
        "Regex": lambda **kwargs: WordPatternMasker(**kwargs).apply,
        "Hash": parse_hash_options,
        "NoiseDate": parse_date_noise_options,
        "NoiseInteger": lambda **kwargs: parse_noise_options(**kwargs).apply_on_int,
        "NoiseFloat": lambda **kwargs: parse_noise_options(**kwargs).apply_on_float,
        "AggregationDate": lambda **kwargs: DateAggregator(**kwargs).apply_on_date,
        "AggregationInteger": lambda **kwargs: NumberAggregator(**kwargs).apply_on_int,
        "AggregationFloat": lambda **kwargs: NumberAggregator(**kwargs).apply_on_float,
        "RescalingInteger": lambda **kwargs: NumberScaler(**kwargs).apply_on_int,
        "RescalingFloat": lambda **kwargs: NumberScaler(**kwargs).apply_on_float,
    }
    parsing_function = parsing_functions.get(method_name)
    if parsing_function is None:
        raise ValueError(f"Unknown method named: {method_name}.")
    return parsing_function(**method_opts)


def anonymize_dataframe(
    df: pd.DataFrame, config: Dict, inplace: bool = False
) -> pd.DataFrame:
    """
    Anonymizes a Pandas DataFrame by applying the specified techniques to selected columns.

    Args:
        df: The input DataFrame to anonymize.
        config: A dictionary containing the metadata for each column to anonymize.
        inplace: If True, applies the anonymization directly to the input DataFrame.
            If False, creates a new DataFrame with the anonymized data.
    """
    anonymized_df = df
    if not inplace:
        anonymized_df = pd.DataFrame()

    # Iterate over each column to anonymize.
    for column_metadata in config["metadata"]:
        col_name: str = column_metadata["name"]
        method_name: str = column_metadata["method"]
        method_opts: Dict = column_metadata["method_options"]

        # Create a transformation function based on the selected technique.
        transform_func = create_transformation_function(method_name, method_opts)
        anonymized_df[col_name] = df[col_name].apply(transform_func)

    return anonymized_df


def anonymize(config_path: str, data_path: str, output_path: str) -> None:
    """
    Reads the configuration file and data file, anonymizes the data according to the configuration,
    and writes the anonymized data to a new file.

    Args:
        config_path (str): The path to the configuration file.
        data_path (str): The path to the data file.
        output_path (str): The path to the output file.
    """

    # Read the configuration file and convert keys to snake_case.
    with open(config_path, "r") as f:
        conf = decamelize(json.load(f))

    # TODO: get separator from JSON
    df = pd.read_csv(data_path, sep=";")

    # Anonymize the data according to the configuration.
    anonymized_df = anonymize_dataframe(df, conf)

    # Write the anonymized data to the output file.
    anonymized_df.to_csv(output_path, sep=";", index=False)
    print(f"Anonymized data written to {output_path}.")


if __name__ == "__main__":
    anonymize(
        "./tests/data/anonymization/config3.json",
        "./tests/data/anonymization/data.csv",
        "./tests/data/anonymization/out.csv",
    )
