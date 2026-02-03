"""Android Parser Plugin for Azul3.

Extract Android metadata as features
"""

from azul_runner import (
    FV,
    BinaryPlugin,
    Feature,
    FeatureType,
    Job,
    State,
    add_settings,
    cmdline_run,
)

from azul_plugin_android_parser import apk_parse


class AzulPluginAndroidParser(BinaryPlugin):
    """Android Parser."""

    CONTACT = "ASD's ACSC"
    VERSION = "2025.07.16"
    SETTINGS = add_settings(
        filter_data_types={
            "content": [
                "android/",
            ]
        }
    )

    FEATURES = [
        Feature("apk_app_name", "The name of the application, as seen by the user", type=FeatureType.String),
        Feature("apk_package_name", "How Android refers to the application", type=FeatureType.String),
        Feature("apk_main_activity", "The main activity of the application", type=FeatureType.String),
        Feature("apk_permissions", "The literal permissions as declared in the manifest", type=FeatureType.String),
        Feature(
            "apk_libraries",
            "The declared shared libraries that the application must be linked against",
            type=FeatureType.String,
        ),
        Feature("apk_file_types", "The file types within the apk", type=FeatureType.String),
        Feature("apk_file_count", "The number of occurrences of a given file type", type=FeatureType.String),
        Feature("apk_sdk_target", "API level this application targets", type=FeatureType.Integer),
        Feature(
            "apk_sdk_min", "Minimum API level on which the application is designed to run", type=FeatureType.Integer
        ),
        Feature(
            "apk_sdk_max",
            "Maximum API level on which the application is designed to run"
            "(a value of 0 means there is no specified API level)",
            type=FeatureType.Integer,
        ),
        Feature("apk_version_name", "Release version of application code as shown to users", type=FeatureType.String),
        Feature(
            "apk_version_code", "Version of the application code, relative to other versions", type=FeatureType.Integer
        ),
        Feature(
            "apk_default_icon",
            "Sha256 hash of the first icon file name as determined by the manifest",
            type=FeatureType.String,
        ),
        Feature("apk_icon_path", "Path to the default icon", type=FeatureType.String),
        Feature("apk_dex_count", "Indicates weather the APK is multi-dex", type=FeatureType.Integer),
        Feature(
            "apk_intent_filters",
            "All of the intent filters in an application(not separated by type)",
            type=FeatureType.String,
        ),
        Feature(
            "apk_signature_hashes",
            "SHA256 hashes of all of the signatures applied to the certificate",
            type=FeatureType.String,
        ),
        Feature(
            "apk_signature_types",
            "3 bit value indicating the version of the signature(s). Bits 0, 1 and 2 correspond to v1, v2 and v3",
            type=FeatureType.Integer,
        ),
        Feature(
            "apk_cert_fingerprint",
            "The SHA256 fingerprint of the certificate(s) issued to the APK",
            type=FeatureType.String,
        ),
        Feature("apk_cert_issuer", "The issuer of the certificate", type=FeatureType.String),
        Feature("apk_cert_subject", "The subject of the certificate", type=FeatureType.String),
    ]

    def execute(self, job: Job) -> dict:
        """Run android parser on suspected android apk files."""
        data = job.get_data()
        binary = data.readall()
        apk_file = apk_parse.ApkParse(binary)
        if not apk_file.load_apk():
            return State(State.Label.OPT_OUT, message="Can't load APK file.")
        meta = apk_file.process_apk_meta()

        # getting the properties
        file_type_summary = dict()
        png_count = 0

        for key, value in meta.file_details.items():
            if key.startswith("gzip compressed data"):
                key = "gzip"
            if key.startswith("PNG image data"):
                png_count += len(value)
            else:
                file_type_summary[key] = str(len(value))
        file_type_summary["PNG image data"] = str(png_count)
        file_types = list(file_type_summary.keys())
        file_count = [FV(key, label=val) for key, val in file_type_summary.items()]

        intent_filters: list[str] = list()

        def append_values_from_filter(dest_filter: list[str], src_filter: list):
            for i in src_filter:
                for j in i.values():
                    for k in j.values():
                        if isinstance(k, list):
                            # Filter out mime_types which can be in here.
                            for val in k:
                                if isinstance(val, str):
                                    dest_filter.append(val)

        append_values_from_filter(intent_filters, meta.activity_intent_filter)
        append_values_from_filter(intent_filters, meta.receiver_intent_filters)
        append_values_from_filter(intent_filters, meta.service_intent_filter)

        signature_hashes = meta.signatures
        signature_types = meta.signature_version

        # cert_fingerprint  # Not used
        cert_issuer = list()
        cert_subject = list()
        for key, value in meta.certs.items():
            cert_issuer.append(FV(key, label=value.issuer))
            cert_subject.append(FV(key, label=value.subject))

        # format for the output
        features = {
            "apk_app_name": meta.app_name,
            "apk_package_name": meta.package_name,
            "apk_permissions": meta.permissions_literal,
            "apk_main_activity": meta.main_activity,
            "apk_libraries": meta.libraries,
            "apk_file_types": file_types,
            "apk_file_count": file_count,
            "apk_sdk_target": meta.sdk_build_info.target,
            "apk_sdk_min": meta.sdk_build_info.min,
            "apk_sdk_max": meta.sdk_build_info.max,
            "apk_version_name": meta.sdk_version.name,
            "apk_version_code": meta.sdk_version.version_code,
            "apk_default_icon": meta.icon.sha256 if meta.icon and hasattr(meta.icon, "sha256") else None,
            "apk_icon_path": meta.icon.path if meta.icon and hasattr(meta.icon, "path") else None,
            "apk_dex_count": len(meta.dex_files),
            "apk_intent_filters": intent_filters,
            "apk_signature_hashes": signature_hashes,
            "apk_signature_types": signature_types,
            "apk_cert_issuer": cert_issuer,
            "apk_cert_subject": cert_subject,
        }

        # Remove all features that have a None value.
        for feat in list(features.keys()):
            if features[feat] is None:
                del features[feat]

        self.add_many_feature_values(features)


def main():
    """Command line entry."""
    cmdline_run(plugin=AzulPluginAndroidParser)
