"""APK Parser.

Extract generic information about an apk that can be used for further analysis.
"""

import hashlib
import io
import logging
import re
import struct
import zipfile
from collections import defaultdict
from typing import Annotated
from zipfile import ZipFile

import magic
from androguard.core import androconf, apk, axml
from asn1crypto.x509 import Certificate as x509Cert
from pydantic import BaseModel, BeforeValidator, ConfigDict

# Annotations to allow for processing of None's as an empty/default value instead.
StrNeverNone = Annotated[str, BeforeValidator(lambda v: "" if v is None else v)]
IntNeverNone = Annotated[int, BeforeValidator(lambda v: 0 if v is None else v)]


class CustomBaseModel(BaseModel):
    """Base model for ApkParse objects."""

    model_config = ConfigDict(extra="allow")


class ApkPermission(CustomBaseModel):
    """Android detailed permissions."""

    level: StrNeverNone = ""
    label: StrNeverNone = ""
    description: StrNeverNone = ""


class SdkBuildInfo(CustomBaseModel):
    """Sdk build tolerance information."""

    target: IntNeverNone = 0
    min: IntNeverNone = 0
    max: IntNeverNone = 0


class SdkVersion(CustomBaseModel):
    """Version information about an android sdk."""

    version_code: IntNeverNone = 0
    name: StrNeverNone = ""


class SdkIcon(CustomBaseModel):
    """Icon used by an android sdk."""

    path: StrNeverNone = ""
    sha256: StrNeverNone = ""


class SdkCertificate(CustomBaseModel):
    """Certificates stored within an android sdk."""

    issuer: StrNeverNone = ""
    subject: StrNeverNone = ""


class AdminStrings(CustomBaseModel):
    """Admin strings used by an android sdk."""

    name: StrNeverNone = ""
    description: StrNeverNone = ""


class ApkMeta(CustomBaseModel):
    """All metadata provided by the output of ApkParse processing an android apk."""

    app_name: str | None
    package_name: str | None
    permissions: dict[str, ApkPermission] = dict()
    permissions_literal: list[str] = []
    main_activity: str | None
    activities: list[str] = []
    services: list[str] = []
    receivers: list[str] = []
    providers: list[str] = []
    libraries: list[str] = []
    file_details: dict[str, list[str]] = dict()
    sdk_build_info: SdkBuildInfo
    sdk_version: SdkVersion
    icon: SdkIcon | None
    dex_files: list[str] = []
    receiver_intent_filters: list[dict] = []
    activity_intent_filter: list[dict] = []
    service_intent_filter: list[dict] = []
    signatures: list[str] = []
    signature_version: IntNeverNone = 0
    certs: dict[str, SdkCertificate] = dict()


class ApkParse:
    """Parse an android APK file."""

    def __init__(self, binary, log_level=logging.CRITICAL):
        # Prevent androguard printing out it's large number of logs
        androconf.logger.disable("")
        logging.basicConfig(level=log_level)
        self.log = logging.getLogger()
        self.binary = binary
        self.archive = None
        self.apk = None

    def load_apk(self):
        """Load APK and have Androguard check if it is a valid apk.

        (determined by parsing the manifest).
        """
        try:
            loaded_apk = apk.APK(self.binary, True)
        except (zipfile.BadZipfile, TypeError, ValueError) as error:
            self.log.debug("Zip or Androguard error: " + str(error))
            # raise
            return False
        if loaded_apk.is_valid_APK():
            self.archive = ZipFile(io.BytesIO(self.binary), "r")
            # Check if there is a classes.dex file (androguard doesn't seem to do this).
            try:
                dex = self.archive.read("classes.dex")
            except (KeyError, zipfile.BadZipfile) as error:
                self.log.debug("Missing or corrupt classes.dex file: " + str(error))
                # raise
                return False
            # python filemagic is too old to parse magic correctly.
            # expected 8 byte dex magic: b"dex\n<ascii version>\0"
            magic_re = b"dex\n[0-9]{3}\x00"
            dex_file_magic = dex[:8]
            self.log.debug(f"{dex_file_magic=}")
            if re.match(magic_re, dex[:8]):
                self.apk = loaded_apk
                self.log.debug("APK loaded")
                return True
        self.log.debug(f"{loaded_apk.is_valid_APK()=}")
        return False

    def process_apk_meta(self) -> ApkMeta:
        """Process the apk metadata."""
        permissions: dict[str, ApkPermission] = dict()
        for perm, perm_details in self.apk.get_details_permissions().items():
            permissions[perm] = ApkPermission(level=perm_details[0], label=perm_details[1], detail=perm_details[2])

        permissions_literal = self.apk.get_permissions()
        sdk_build_info = SdkBuildInfo(
            target=self.apk.get_target_sdk_version(),
            min=self.apk.get_min_sdk_version(),
            max=self.apk.get_max_sdk_version(),
        )
        version = SdkVersion(version_code=self.apk.get_androidversion_code(), name=self.apk.get_androidversion_name())

        icon_path: str | None = ""
        icon_sha256 = ""
        try:
            icon_path = self.apk.get_app_icon()
            if icon_path is not None:
                icon_sha256 = hashlib.sha256(self.archive.read(icon_path), usedforsecurity=False).hexdigest()
        except ValueError as error:
            self.log.debug("Androguard error getting icon: " + str(error))
            icon_path = ""
        icon = None
        if icon_path is not None and icon_sha256 is not None:
            icon = SdkIcon(path=icon_path, sha256=icon_sha256)

        try:
            receiver_if = [{i: self.apk.get_intent_filters("receiver", i)} for i in self.apk.get_receivers()]
            activity_if = [{i: self.apk.get_intent_filters("activity", i)} for i in self.apk.get_activities()]
            service_if = [{i: self.apk.get_intent_filters("service", i)} for i in self.apk.get_services()]
        except TypeError as error:
            self.log.debug("Androguard error getting receiver, activity or service: " + str(error))
            receiver_if = []
            activity_if = []
            service_if = []

        signatures = [hashlib.sha256(i).hexdigest() for i in self.apk.get_signatures()]

        certs: dict[str, SdkCertificate] = dict()
        try:
            temp_apk_certs: list[x509Cert] = self.apk.get_certificates()
            for cert in temp_apk_certs:
                issuer = cert.issuer.human_friendly
                subject = cert.subject.human_friendly
                long_words = (
                    "Common Name: ",
                    "Organizational Unit: ",
                    "Organization: ",
                    "Locality: ",
                    "State/Province: ",
                    "Country: ",
                )
                short_words = ("CN=", "OU=", "O=", "L=", "ST=", "C=")
                for l_word, s_word in zip(long_words, short_words):
                    issuer = issuer.replace(l_word, s_word)
                    subject = subject.replace(l_word, s_word)
                certs[str(cert.sha256_fingerprint.replace(" ", "").lower())] = SdkCertificate(
                    issuer=issuer, subject=subject
                )
            signature_version = str(
                (int(self.apk.is_signed_v3()) << 2)
                ^ (int(self.apk.is_signed_v2()) << 1)
                ^ (int(self.apk.is_signed_v1()))
            )
        except apk.BrokenAPKError:
            signature_version = None

        return ApkMeta(
            app_name=self.apk.get_app_name(),
            package_name=self.apk.get_package(),
            permissions=permissions,
            permissions_literal=permissions_literal,
            main_activity=self.apk.get_main_activity(),
            activities=self.apk.get_activities(),
            services=self.apk.get_services(),
            receivers=self.apk.get_receivers(),
            providers=self.apk.get_providers(),
            libraries=self.apk.get_libraries(),
            file_details=self.zip_child_file_types(),
            sdk_build_info=sdk_build_info,
            sdk_version=version,
            icon=icon,
            dex_files=self.apk.get_dex_names(),
            receiver_intent_filters=receiver_if,
            activity_intent_filter=activity_if,
            service_intent_filter=service_if,
            signatures=signatures,
            signature_version=signature_version,
            certs=certs,
        )

    def zip_child_file_types(self) -> dict[str, list[str]]:
        """From a zip, get all of the file types and the file names.

        Returns: dictionary containing dict[file_type] = ["file1_name", "file2_name"]
        """
        zip_files: dict[str, tuple[str, str]] = defaultdict(list)
        for item in self.archive.infolist():
            try:
                file_type = magic.from_buffer(self.archive.read(item))
            # Even though we've determined that the zip file is valid, this catches files with a bad CRC.
            except zipfile.BadZipfile:
                continue

            zip_files[file_type].append(item.filename)
        return zip_files

    def strings_print(self):
        """Print strings for the loaded APK."""
        res = self.apk.get_android_resources().get_strings_resources()
        print(str(res))
        return True

    def manifest_print(self):
        """Print the XML manifest for the loaded apk."""
        manifest = self.apk.get_android_manifest_axml()
        print(manifest.get_xml())
        return True

    def resource_by_id(self, id):
        """Get a resource from an APK by it's id."""
        resolver = axml.ARSCParser.ResourceResolver(self.apk.get_android_resources())
        return resolver.resolve(id)


class DexParse(object):
    """Parse a Dex file for analysis."""

    def __init__(self, binary, log_level=logging.CRITICAL):
        logging.basicConfig(level=log_level)
        self.log = logging.getLogger()
        self.binary = binary
        self.dex_type_list = False
        self.dex_func_list = False
        self.type_list = list()
        self.method_list = list()
        self.user_strings = list()
        self.proto_list = list()
        self.field_list = list()
        self.class_list = list()
        self.source_list = list()
        self.header = dict()

    def load_dex(self):
        """Load the supplied file setting the object attributes as a dex file."""
        m = magic.from_buffer(self.binary)
        if not re.search("Dalvik dex file", m):
            return None
        # Filter out optimised dex files which are currently unsupported.
        if self.binary[:3] == "dey":
            return None
        self.header["strings"] = (
            struct.unpack("<I", self.binary[60:64])[0],
            struct.unpack("<I", self.binary[56:60])[0],
        )
        self.header["types"] = (struct.unpack("<I", self.binary[68:72])[0], struct.unpack("<I", self.binary[64:68])[0])
        self.header["protos"] = (
            struct.unpack("<I", self.binary[76:80])[0],
            struct.unpack("<I", self.binary[72:76])[0],
        )
        self.header["fields"] = (
            struct.unpack("<I", self.binary[84:88])[0],
            struct.unpack("<I", self.binary[80:84])[0],
        )
        self.header["methods"] = (
            struct.unpack("<I", self.binary[92:96])[0],
            struct.unpack("<I", self.binary[88:92])[0],
        )
        self.header["classes"] = (
            struct.unpack("<I", self.binary[100:104])[0],
            struct.unpack("<I", self.binary[96:100])[0],
        )
        for i in range(self.header["types"][1]):
            self.type_list.append(self._get_by_index("types", 4, 0, i)[0])
        return True

    def get_strings(self):
        """Get strings from the dex file."""
        for i in range(self.header["strings"][1]):
            try:
                yield self._get_by_index("strings", 4, 0, i)[0].decode("utf-8")
            except UnicodeDecodeError:
                continue

    def load_strings(self):
        """Load strings into class parameters."""
        for i in range(self.header["methods"][1]):
            self.method_list.append(self._get_by_index("methods", 8, 4, i)[0])
        for i in range(self.header["protos"][1]):
            self.proto_list.append(self._get_by_index("protos", 12, 0, i)[0])
        for i in range(self.header["fields"][1]):
            self.field_list.append(self._get_by_index("fields", 8, 4, i)[0])
        for i in range(self.header["classes"][1]):
            self.class_list.append(self._get_by_index("classes", 32, 0, i)[0])
            class_type = self._get_by_index("classes", 32, 8, i)[0]
            if class_type is not None:
                self.class_list.append(class_type)
            source_name = self._get_by_index("classes", 32, 16, i)[0]
            if source_name is not None:
                self.source_list.append(source_name)
        temp = list(set(self.class_list))
        self.class_list = temp
        temp = list(set(self.source_list))
        self.source_list = temp
        self.user_strings = [
            x
            for x in self.get_strings()
            if x not in self.type_list
            and x not in self.method_list
            and x not in self.field_list
            and x not in self.class_list
            and x not in self.proto_list
            and x not in self.source_list
        ]
        return True

    def _get_by_index(self, obj_type: str, obj_size: int, obj_pos: int, index: int) -> tuple[str, int]:
        """Internal method to get object from dex by index."""
        strings = self.header["strings"]
        if obj_type == "types":
            obj = self.header["types"]
        elif obj_type == "classes":
            obj = self.header["classes"]
        elif obj_type == "methods":
            obj = self.header["methods"]
        elif obj_type == "protos":
            obj = self.header["protos"]
        elif obj_type == "fields":
            obj = self.header["fields"]
        elif obj_type == "strings":
            obj = self.header["strings"]
        else:
            return None, None
        offset = obj[0] + index * obj_size
        if obj_type == "strings":
            the_string = self._read_string(offset)
            return the_string, index
        string_index = struct.unpack_from("I", self.binary[offset + obj_pos : offset + obj_pos + 4])[0]
        if obj_type == "classes":
            if string_index == 4294967295:
                return None, None
            if obj_pos == 0 or obj_pos == 8:
                the_string = self._get_by_index("types", 4, 0, string_index)
            elif obj_pos == 16:
                string_ptr_offset = string_index * 4 + strings[0]
                the_string = self._read_string(string_ptr_offset)
            return the_string, string_index
        string_ptr_offset = string_index * 4 + strings[0]
        the_string = self._read_string(string_ptr_offset)
        return the_string, string_index

    def get_string(self, index):
        """Get the strings by index."""
        return self._get_by_index("strings", 4, 0, index)[0]

    def _read_string(self, offset):
        """Read string when getting a string by index."""
        string_ptr = struct.unpack_from("I", self.binary[offset : offset + 4])[0]
        size = struct.unpack_from("B", self.binary[string_ptr : string_ptr + 1])[0]
        type_string = self.binary[string_ptr + 1 : string_ptr + 1 + size]
        return type_string

    def type_index_by_type(self, type_string):
        """Get the index of a type string."""
        for i, a_type in enumerate(self.type_list):
            if type_string == a_type:
                return i
        return -1

    def string_index_by_string(self, a_string):
        """Get the string index of a string by providing the."""
        strings = self.header["strings"]
        for i in range(0, strings[1]):
            test_string = self._get_by_index("strings", 4, 0, i)
            if test_string == a_string:
                return i
        return -1
