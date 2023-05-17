# -*- coding: utf-8 -*-
import json
from datetime import timezone
from typing import Callable, Dict, List, Optional

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
from cloudproof_fpe import Alphabet, Float, Integer
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


def create_noise_generator(
    distribution: str,
    mean: Optional[float] = None,
    std_dev: Optional[float] = None,
    lower_boundary: Optional[float] = None,
    upper_boundary: Optional[float] = None,
) -> NoiseGenerator:
    """
    Returns a `NoiseGenerator` object based on the specified options.

    Args:
        method (str): The distribution to use for generating noise: "Uniform", "Gaussian", or "Laplace".
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


def create_date_noise_generator(
    distribution: str,
    mean: Optional[Dict] = None,
    std_dev: Optional[Dict] = None,
    lower_boundary: Optional[Dict] = None,
    upper_boundary: Optional[Dict] = None,
) -> NoiseGenerator:
    """
    Returns a `NoiseGenerator` object based on the specified options.

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

    return create_noise_generator(
        distribution,
        mean=mean_secs,
        std_dev=std_dev_secs,
        lower_boundary=lower_boundary_secs,
        upper_boundary=upper_boundary_secs,
    )


class NoiseCorrelationTask:
    """
    Class representing a noise correlation task.
    """

    def __init__(self, method: str, opts: Dict):
        """
        Initialize a NoiseCorrelationTask.

        Args:
            method (str): The noise distribution.
            opts (Dict): Options for the noise generation.
        """
        self.method = method
        # The `correlation` keyword is not used to create the generator
        self.options = {
            key: value for key, value in opts.items() if key != "correlation"
        }
        self.column_names: List[str] = []

    def add_column(self, column_name: str):
        """
        Add a column name to the list of column names.

        Args:
            column_name (str): The column name to add.
        """
        self.column_names.append(column_name)

    def generate_transformation(self) -> Callable[[List], List]:
        """
        Generate and return the transformation function for applying correlated noise.

        Returns:
            Callable[[List], List]: The transformation function.
        """
        # Mapping of noise method to noise generator functions
        noise_func_mapping: Dict[str, Callable] = {
            "NoiseDate": lambda **kwargs: create_date_noise_generator(
                **kwargs
            ).apply_correlated_noise_on_dates,
            "NoiseInteger": lambda **kwargs: create_noise_generator(
                **kwargs
            ).apply_correlated_noise_on_ints,
            "NoiseFloat": lambda **kwargs: create_noise_generator(
                **kwargs
            ).apply_correlated_noise_on_floats,
        }
        # Get the noise generator function based on the specified method
        noise_generator_func = noise_func_mapping.get(self.method)
        if noise_generator_func is None:
            raise ValueError(f"Cannot apply correlation for method: {self.method}.")

        # Scale noise by 1 for now
        correlation_factors = [1] * len(self.column_names)
        # Create a noise generator instance with the specified options
        noise_generator = noise_generator_func(**self.options)
        # Return a lambda function that applies the noise generator to the data vector
        return lambda data_vec: noise_generator(data_vec, correlation_factors)


def parse_noise_correlation_config(config: Dict) -> Dict[str, NoiseCorrelationTask]:
    """
    Parse the noise correlation configuration and return the dictionary of correlation tasks.

    Args:
        config (Dict): The noise correlation configuration.

    Returns:
        Dict[str, NoiseCorrelationTask]: The dictionary of correlation tasks.
    """
    tasks: Dict[str, NoiseCorrelationTask] = {}

    # Iterate over each column metadata in the configuration
    for column_metadata in config["metadata"]:
        col_name: str = column_metadata["name"]

        # Check if method and method_options are present
        if "method" not in column_metadata or "method_options" not in column_metadata:
            continue

        method_name: str = column_metadata["method"]
        method_opts = column_metadata["method_options"]

        # Check if correlation option is present
        if "correlation" not in method_opts:
            continue

        correlation_uid = method_opts["correlation"]

        # Create or retrieve the correlation task based on correlation_uid
        if correlation_uid not in tasks:
            tasks[correlation_uid] = NoiseCorrelationTask(method_name, method_opts)

        # Add the current column to the correlation task
        tasks[correlation_uid].add_column(col_name)

    return tasks


def date_to_rfc3339(date_str: str) -> str:
    """
    Converts a date string to ISO format with timezone (RFC 3339).

    Args:
        date_str (str): The input date string.

    Returns:
        str: The date string in RFC3339 format.
    """
    dt = date_parser.parse(date_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def parse_date_noise_options(**kwargs) -> Callable[[str], str]:
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
    return lambda date_str: create_date_noise_generator(**kwargs).apply_on_date(
        date_to_rfc3339(date_str)
    )


def parse_date_aggregation_options(time_unit: str) -> Callable[[str], str]:
    """
    Parses the date aggregation options and returns a function that applies the aggregation.

    Args:
        time_unit (str): The time unit for rounding.
    """
    return lambda date_str: DateAggregator(time_unit).apply_on_date(
        date_to_rfc3339(date_str)
    )


def parse_fpe_string_options(alphabet: str) -> Callable[[str], str]:
    # TODO: what about key and tweak?
    return lambda val: Alphabet(alphabet).encrypt(b"A" * 32, bytes([10]), val)


def parse_fpe_integer_options(radix: int, digit: int) -> Callable[[int], int]:
    # TODO: what about key and tweak?
    return lambda val: Integer(radix, digit).encrypt(b"A" * 32, bytes([10]), val)


def parse_fpe_float_options() -> Callable[[float], float]:
    # TODO: what about key and tweak?
    return lambda val: Float().encrypt(b"A" * 32, bytes([10]), val)


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

    return lambda val: hasher.apply(str(val).encode(encoding))


def create_transformation_function(method_name: str, method_opts: Dict) -> Callable:
    """
    Given a method name and options, returns a callable that applies the desired transformation.
    """
    parsing_functions: Dict[str, Callable] = {
        "FpeString": parse_fpe_string_options,
        "FpeInteger": parse_fpe_integer_options,
        "FpeFloat": parse_fpe_float_options,
        "TokenizeWords": lambda **kwargs: WordTokenizer(**kwargs).apply,
        "MaskWords": lambda **kwargs: WordMasker(**kwargs).apply,
        "Regex": lambda **kwargs: WordPatternMasker(**kwargs).apply,
        "Hash": parse_hash_options,
        "NoiseDate": parse_date_noise_options,
        "NoiseInteger": lambda **kwargs: create_noise_generator(**kwargs).apply_on_int,
        "NoiseFloat": lambda **kwargs: create_noise_generator(**kwargs).apply_on_float,
        "AggregationDate": parse_date_aggregation_options,
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
        if col_name not in df:
            # Column missing from the dataset
            raise ValueError(f"Missing column from data: {col_name}.")

        if "method" not in column_metadata:
            # No method to apply for this column
            anonymized_df[col_name] = df[col_name]
            continue
        method_name: str = column_metadata["method"]
        method_opts: Dict = (
            column_metadata["method_options"]
            if "method_options" in column_metadata
            else {}
        )
        if "correlation" in method_opts:
            # Skip correlation for now
            continue
        # Create a transformation function based on the selected technique.
        transform_func = create_transformation_function(method_name, method_opts)
        anonymized_df[col_name] = df[col_name].map(transform_func)

    # Noise correlation

    # Read through the config to find all correlation tasks
    noise_corr_tasks = parse_noise_correlation_config(config)
    # Apply correlation on each groups
    for correlation_task in noise_corr_tasks.values():
        transform_func = correlation_task.generate_transformation()
        anonymized_df[correlation_task.column_names] = df[
            correlation_task.column_names
        ].apply(transform_func, axis=1, raw=True)
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

    df = pd.read_csv(data_path, sep=conf["configuration_info"]["delimiter"])

    # Anonymize the data according to the configuration.
    anonymized_df = anonymize_dataframe(df, conf)

    # Write the anonymized data to the output file.
    anonymized_df.to_csv(output_path, sep=";", index=False)
    print(f"Anonymized data written to {output_path}.")


if __name__ == "__main__":
    anonymize(
        "./tests/data/anonymization/config-sep.json",
        "./tests/data/anonymization/data-correlated.csv",
        "./tests/data/anonymization/out.csv",
    )
