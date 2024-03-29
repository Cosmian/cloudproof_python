# -*- coding: utf-8 -*-
# Copy py interface files from PyO3 libs inside our projects
# Theses files are used by sphinx auto-api to generate the docs of the PyO3 libs
import pkgutil

if __name__ == "__main__":
    SRC_DIR = "src/cloudproof_py"
    PKGs_dir = {
        "cloudproof_cover_crypt": f"{SRC_DIR}/cover_crypt",
        "cloudproof_findex": f"{SRC_DIR}/findex",
        "cloudproof_fpe": f"{SRC_DIR}/fpe",
        "cloudproof_anonymization": f"{SRC_DIR}/anonymization",
        "cosmian_kms": f"{SRC_DIR}/kms",
    }

    print(
        "LOG extract_lib_types: copying function signatures from", ", ".join(PKGs_dir)
    )

    for pkg_name, dest_dir in PKGs_dir.items():
        try:
            data = pkgutil.get_data(pkg_name, "__init__.pyi")
            if data:
                with open(f"{dest_dir}/__init__.docpy", "w", encoding="utf-8") as f:
                    f.write(f"# file automatically copied from {pkg_name}\n")
                    f.write(data.decode("utf-8"))
            else:
                raise FileNotFoundError
        except FileNotFoundError:
            print(f"WARNING: No typing information found for {pkg_name}")
