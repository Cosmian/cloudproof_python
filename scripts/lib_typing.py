# -*- coding: utf-8 -*-
# Copy py interface files from PyO3 libs inside our projects

import pkgutil

if __name__ == "__main__":
    SRC_DIR = "src/cloudproof_py"
    PKGs_dir = {
        "cosmian_cover_crypt": f"{SRC_DIR}/cover_crypt",
        "cosmian_findex": f"{SRC_DIR}/findex",
    }

    print(f"LOG lib_typing: copying function signature from {', '.join(PKGs_dir)}")

    # Marker file for PEP 561
    with open(f"{SRC_DIR}/py.typed", "w", encoding="utf-8") as f:
        pass

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
