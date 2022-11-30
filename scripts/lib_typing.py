# -*- coding: utf-8 -*-
import pkgutil

if __name__ == "__main__":
    SRC_DIR = "src/cloudproof_py"
    PKGs = ["cosmian_cover_crypt", "cosmian_findex"]

    # Marker file for PEP 561
    with open(f"{SRC_DIR}/py.typed", "w") as f:
        pass
    with open(f"{SRC_DIR}/__init__.pyi", "w") as f:
        pass

    for pkg_name in PKGs:
        try:
            data = pkgutil.get_data(pkg_name, "__init__.pyi")
            if data:
                with open(f"{SRC_DIR}/__init__.pyi", "a") as f:
                    f.write(data.decode("utf-8"))
        except FileNotFoundError:
            print(f"WARNING: No typing information found for {pkg_name}")
