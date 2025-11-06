"""Test the Android Parser plugin"""

import os

from azul_runner import FV, Event, JobResult, State, test_template

from azul_plugin_android_parser import AzulPluginAndroidParser

DATAPATH = os.path.join(os.path.dirname(__file__), "data")


class TestAndroidParser(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginAndroidParser

    def test_expected_output(self):
        res = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "7c33a3c691d9e0648f1a10e0f518ba208cab1430b1bf80c06bc1ca26971b973d",
                        "Gustuff android malware file.",
                    ),
                )
            ]
        )

        self.assertJobResult(
            res,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="7c33a3c691d9e0648f1a10e0f518ba208cab1430b1bf80c06bc1ca26971b973d",
                        features={
                            "apk_app_name": [FV("Instagram Shared")],
                            "apk_cert_issuer": [
                                FV(
                                    "a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc",
                                    label="Email Address: android@android.com, CN=Android, OU=Android, O=Android, L=Mountain View, ST=California, C=US",
                                )
                            ],
                            "apk_cert_subject": [
                                FV(
                                    "a40da80a59d170caa950cf15c18c454d47a39b26989d8b640ecd745ba71bf5dc",
                                    label="Email Address: android@android.com, CN=Android, OU=Android, O=Android, L=Mountain View, ST=California, C=US",
                                )
                            ],
                            "apk_default_icon": [
                                FV("843a1273a07c32f9f2a2086ba30a23e6edb32b1f07eb3e5a3cf3ac8b87dc9433")
                            ],
                            "apk_dex_count": [FV("1")],
                            "apk_file_count": [
                                FV("ASCII text", label="1"),
                                FV("ASCII text, with no line terminators", label="11"),
                                FV("Android binary XML", label="16"),
                                FV("Android package resource table (ARSC), 1398 string(s), utf8", label="1"),
                                FV("DER Encoded PKCS#7 Signed Data", label="1"),
                                FV("Dalvik dex file version 035", label="1"),
                                FV("JAR Manifest, ASCII text, with CRLF line terminators", label="1"),
                                FV("JAR Signature File, ASCII text, with CRLF line terminators", label="1"),
                                FV("PNG image data", label="96"),
                                FV('Targa image data - RLE 284 x 65536 x 8 +1 +28 ""', label="4"),
                                FV('Targa image data - RLE 380 x 65536 x 15 +1 +28 ""', label="4"),
                                FV('Targa image data - RLE 484 x 65536 x 24 +1 +28 ""', label="1"),
                                FV("data", label="1"),
                                FV("exported SGML document, ASCII text", label="1"),
                                FV("gzip", label="1"),
                            ],
                            "apk_file_types": [
                                FV("ASCII text"),
                                FV("ASCII text, with no line terminators"),
                                FV("Android binary XML"),
                                FV("Android package resource table (ARSC), 1398 string(s), utf8"),
                                FV("DER Encoded PKCS#7 Signed Data"),
                                FV("Dalvik dex file version 035"),
                                FV("JAR Manifest, ASCII text, with CRLF line terminators"),
                                FV("JAR Signature File, ASCII text, with CRLF line terminators"),
                                FV("PNG image data"),
                                FV('Targa image data - RLE 284 x 65536 x 8 +1 +28 ""'),
                                FV('Targa image data - RLE 380 x 65536 x 15 +1 +28 ""'),
                                FV('Targa image data - RLE 484 x 65536 x 24 +1 +28 ""'),
                                FV("data"),
                                FV("exported SGML document, ASCII text"),
                                FV("gzip"),
                            ],
                            "apk_icon_path": [FV("res/mipmap-xxhdpi-v4/oiyzuvkunudn.png")],
                            "apk_intent_filters": [
                                FV("MainActivity.AlarmAction"),
                                FV("android.accessibilityservice.AccessibilityService"),
                                FV("android.intent.action.BOOT_COMPLETED"),
                                FV("android.intent.action.MAIN"),
                                FV("android.intent.action.QUICKBOOT_POWERON"),
                                FV("android.intent.category.DEFAULT"),
                                FV("android.intent.category.LAUNCHER"),
                                FV("android.net.conn.CONNECTIVITY_CHANGE"),
                                FV("android.provider.Telephony.SMS_RECEIVED"),
                                FV("com.facebook.events"),
                                FV("com.facebook.main"),
                                FV("com.google.android.gms.gcm.ACTION_TASK_READY"),
                            ],
                            "apk_main_activity": [FV("com.ziwjvg.jmibnmd.didkgdmh.xLJFzuweTOlA")],
                            "apk_package_name": [FV("com.ziwjvg.jmibnmd")],
                            "apk_permissions": [
                                FV("android.permission.ACCESS_NETWORK_STATE"),
                                FV("android.permission.DISABLE_KEYGUARD"),
                                FV("android.permission.GET_ACCOUNTS"),
                                FV("android.permission.INTERNET"),
                                FV("android.permission.READ_CONTACTS"),
                                FV("android.permission.READ_SMS"),
                                FV("android.permission.RECEIVE_BOOT_COMPLETED"),
                                FV("android.permission.RECEIVE_SMS"),
                                FV("android.permission.SEND_SMS"),
                                FV("android.permission.SYSTEM_ALERT_WINDOW"),
                                FV("android.permission.USES_POLICY_FORCE_LOCK"),
                                FV("android.permission.VIBRATE"),
                                FV("android.permission.WAKE_LOCK"),
                                FV("android.permission.WRITE_EXTERNAL_STORAGE"),
                                FV("android.permission.WRITE_SETTINGS"),
                                FV("andstartScreenroid.permission.READ_EXTERNAL_STORAGE"),
                                FV("com.google.android.c2dm.permission.RECEIVE"),
                            ],
                            "apk_sdk_max": [FV("0")],
                            "apk_sdk_min": [FV("19")],
                            "apk_sdk_target": [FV("22")],
                            "apk_signature_hashes": [
                                FV("681d79b47fb917a752c63f3f681df1d47f73ca562422b8f16d938dc1cbfc3896")
                            ],
                            "apk_signature_types": [FV("3")],
                            "apk_version_code": [FV("36")],
                            "apk_version_name": [FV("0.3.6")],
                        },
                    )
                ],
            ),
        )
        expected_file_types = {
            "ASCII text": "1",
            "ASCII text, with no line terminators": "11",
            "PNG image data": "96",
            "gzip": "1",
            "Dalvik dex file version 035": "1",
            "exported SGML document, ASCII text": "1",
        }

        file_types = [fv.value for fv in res.events[0].features.pop("apk_file_types")]
        file_type_counts = dict()
        for fv in res.events[0].features.pop("apk_file_count"):
            file_type_counts[fv.value] = fv.label

        for expected_val, expected_label in expected_file_types.items():
            self.assertIn(expected_val, file_types)
            self.assertIn(expected_val, file_type_counts.keys())
            self.assertEqual(
                expected_label,
                file_type_counts[expected_val],
                f"{expected_label} != {file_type_counts.get(expected_val, None)} for val {expected_val}",
            )

        # Expected values for file_count is this (Different depending on debian vs ubuntu):
        #     FV("ASCII text", label="1"),
        #     FV("Dalvik dex file version 035", label="1"),
        #     FV('Targa image data - RLE 484 x 65536 x 24 +1 +28 ""', label="1"),
        #     FV("exported SGML document, ASCII text", label="1"),
        #     FV("gzip", label="1"),
        #     FV("ASCII text, with no line terminators", label="11"),
        #     FV("ASCII text, with CRLF line terminators", label="2"),
        #     FV("Android binary XML", label="24"),
        #     FV("data", label="3"),
        #     FV("PNG image data", label="96"),

    def test_expected_output_file_manager_app(self):
        res = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "9a4afdae28076e2b725259f10ee78dca0ebb1bcf64ff3f0f9e8688ab9de333e5",
                        "Begnin FileManager APK downloaded from the android app store.",
                    ),
                )
            ]
        )

        self.assertJobResult(
            res,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="9a4afdae28076e2b725259f10ee78dca0ebb1bcf64ff3f0f9e8688ab9de333e5",
                        features={
                            "apk_app_name": [FV("File Manager +")],
                            "apk_cert_issuer": [
                                FV(
                                    "95cc44ed264818e2ac6c883f61496fa4c83d32a1c8fa59cae324b25868afc8c2",
                                    label="O=AlphaInventor, C=KR",
                                )
                            ],
                            "apk_cert_subject": [
                                FV(
                                    "95cc44ed264818e2ac6c883f61496fa4c83d32a1c8fa59cae324b25868afc8c2",
                                    label="O=AlphaInventor, C=KR",
                                )
                            ],
                            "apk_default_icon": [
                                FV("b2af4578af1d428ce264d1005207f74027f426a965fb3acfc0c429d1d1f18a8c")
                            ],
                            "apk_dex_count": [FV("2")],
                            "apk_file_count": [
                                FV("ASCII text", label="83"),
                                FV("ASCII text, with no line terminators", label="3"),
                                FV("ASCII text, with very long lines (533)", label="1"),
                                FV(
                                    "Adobe Photoshop Color swatch, version 0, 3 colors; 1st RGB space (0), w 0x1, x 0, y 0, z 0; 2nd Lab space (7), w 0xa66, x 0xa06, y 0x6b6f, z 0x746c",
                                    label="1",
                                ),
                                FV(
                                    "Adobe Photoshop Color swatch, version 0, 3 colors; 1st RGB space (0), w 0x1, x 0, y 0, z 0; 2nd Lab space (7), w 0xa9e, x 0x30a, y 0x66b, z 0x6f74",
                                    label="1",
                                ),
                                FV(
                                    "Adobe Photoshop Color swatch, version 0, 3 colors; 1st RGB space (0), w 0x1, x 0, y 0, z 0; 2nd Lab space (7), w 0xaa3, x 0x40a, y 0x66b, z 0x6f74",
                                    label="1",
                                ),
                                FV(
                                    "Adobe Photoshop Color swatch, version 0, 3 colors; 1st RGB space (0), w 0x1, x 0, y 0, z 0; 2nd Lab space (7), w 0xabc, x 0x20a, y 0x66b, z 0x6f74",
                                    label="1",
                                ),
                                FV(
                                    "Adobe Photoshop Color swatch, version 0, 3 colors; 1st RGB space (0), w 0x1, x 0, y 0, z 0; 2nd Lab space (7), w 0xacd, x 0x70a, y 0x66b, z 0x6f74",
                                    label="1",
                                ),
                                FV(
                                    "Adobe Photoshop Color swatch, version 0, 3 colors; 1st RGB space (0), w 0x1, x 0, y 0, z 0; 2nd Lab space (7), w 0xad8, x 0x50a, y 0x66b, z 0x6f74",
                                    label="1",
                                ),
                                FV(
                                    "Adobe Photoshop Color swatch, version 0, 3 colors; 1st RGB space (0), w 0x1, x 0, y 0, z 0; 2nd Lab space (7), w 0xaf0, x 0x120a, y 0x66b, z 0x6f74",
                                    label="1",
                                ),
                                FV("Android binary XML", label="714"),
                                FV(
                                    "Android package resource table (ARSC), 17108 string(s), 19 style(s), utf8",
                                    label="1",
                                ),
                                FV("Certificate, Version=3", label="1"),
                                FV("DER Encoded PKCS#7 Signed Data", label="1"),
                                FV("Dalvik dex file version 035", label="2"),
                                FV("GIF image data, version 89a, 22 x 17", label="1"),
                                FV("GIF image data, version 89a, 38 x 26", label="1"),
                                FV("HTML document, ASCII text", label="1"),
                                FV("ISO-8859 text, with very long lines (376)", label="1"),
                                FV("JAR Manifest, ASCII text, with CRLF line terminators", label="1"),
                                FV("JAR Signature File, ASCII text, with CRLF line terminators", label="1"),
                                FV("JSON text data", label="1"),
                                FV("Java KeyStore", label="1"),
                                FV("PNG image data", label="600"),
                                FV('Targa image data - RLE 1368 x 65536 x 15 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 1392 x 65536 x 15 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 160 x 65536 x 8 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 164 x 65536 x 8 +1 +28 ""', label="2"),
                                FV('Targa image data - RLE 1664 x 65536 x 15 +1 +28 ""', label="2"),
                                FV('Targa image data - RLE 168 x 65536 x 8 +1 +28 ""', label="6"),
                                FV('Targa image data - RLE 176 x 65536 x 8 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 1788 x 65536 x 15 +1 +28 ""', label="2"),
                                FV('Targa image data - RLE 184 x 65536 x 8 +1 +28 ""', label="7"),
                                FV('Targa image data - RLE 192 x 65536 x 8 +1 +28 ""', label="5"),
                                FV('Targa image data - RLE 196 x 65536 x 8 +1 +28 ""', label="7"),
                                FV('Targa image data - RLE 208 x 65536 x 8 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 224 x 65536 x 8 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 228 x 65536 x 8 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 252 x 65536 x 15 +1 +28 ""', label="2"),
                                FV('Targa image data - RLE 264 x 65536 x 16 +1 +28 ""', label="3"),
                                FV('Targa image data - RLE 268 x 65536 x 16 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 276 x 65536 x 16 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 304 x 65536 x 16 +1 +28 ""', label="2"),
                                FV('Targa image data - RLE 308 x 65536 x 15 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 308 x 65536 x 16 +1 +28 ""', label="2"),
                                FV('Targa image data - RLE 312 x 65536 x 15 +1 +28 ""', label="2"),
                                FV('Targa image data - RLE 316 x 65536 x 15 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 324 x 65536 x 16 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 332 x 65536 x 15 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 336 x 65536 x 15 +1 +28 ""', label="3"),
                                FV('Targa image data - RLE 336 x 65536 x 16 +1 +28 ""', label="2"),
                                FV('Targa image data - RLE 340 x 65536 x 16 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 356 x 65536 x 15 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 36 x 65536 x 1 +1 +28 ""', label="124"),
                                FV('Targa image data - RLE 360 x 65536 x 15 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 360 x 65536 x 16 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 376 x 65536 x 15 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 384 x 65536 x 16 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 400 x 65536 x 15 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 44 x 65536 x 1 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 476 x 65536 x 24 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 508 x 65536 x 24 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 524 x 65536 x 24 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 548 x 65536 x 24 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 580 x 65536 x 24 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 592 x 65536 x 24 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 664 x 65536 x 32 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 684 x 65536 x 32 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 700 x 65536 x 32 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 832 x 65536 x 32 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 848 x 65536 x 24 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 852 x 65536 x 32 +1 +28 ""', label="1"),
                                FV('Targa image data - RLE 952 x 65536 x 32 +1 +28 ""', label="1"),
                                FV(
                                    'TrueType Font data, 14 tables, 1st "GSUB", 17 names, Microsoft, language 0x409, Copyright 2015 The Roboto Mono Project Authors (https://github.com/googlefonts/robotomono)Roboto',
                                    label="1",
                                ),
                                FV("XML 1.0 document, ASCII text", label="1"),
                                FV("data", label="5"),
                                FV("gzip", label="1"),
                            ],
                            "apk_file_types": [
                                FV("ASCII text"),
                                FV("ASCII text, with no line terminators"),
                                FV("ASCII text, with very long lines (533)"),
                                FV(
                                    "Adobe Photoshop Color swatch, version 0, 3 colors; 1st RGB space (0), w 0x1, x 0, y 0, z 0; 2nd Lab space (7), w 0xa66, x 0xa06, y 0x6b6f, z 0x746c"
                                ),
                                FV(
                                    "Adobe Photoshop Color swatch, version 0, 3 colors; 1st RGB space (0), w 0x1, x 0, y 0, z 0; 2nd Lab space (7), w 0xa9e, x 0x30a, y 0x66b, z 0x6f74"
                                ),
                                FV(
                                    "Adobe Photoshop Color swatch, version 0, 3 colors; 1st RGB space (0), w 0x1, x 0, y 0, z 0; 2nd Lab space (7), w 0xaa3, x 0x40a, y 0x66b, z 0x6f74"
                                ),
                                FV(
                                    "Adobe Photoshop Color swatch, version 0, 3 colors; 1st RGB space (0), w 0x1, x 0, y 0, z 0; 2nd Lab space (7), w 0xabc, x 0x20a, y 0x66b, z 0x6f74"
                                ),
                                FV(
                                    "Adobe Photoshop Color swatch, version 0, 3 colors; 1st RGB space (0), w 0x1, x 0, y 0, z 0; 2nd Lab space (7), w 0xacd, x 0x70a, y 0x66b, z 0x6f74"
                                ),
                                FV(
                                    "Adobe Photoshop Color swatch, version 0, 3 colors; 1st RGB space (0), w 0x1, x 0, y 0, z 0; 2nd Lab space (7), w 0xad8, x 0x50a, y 0x66b, z 0x6f74"
                                ),
                                FV(
                                    "Adobe Photoshop Color swatch, version 0, 3 colors; 1st RGB space (0), w 0x1, x 0, y 0, z 0; 2nd Lab space (7), w 0xaf0, x 0x120a, y 0x66b, z 0x6f74"
                                ),
                                FV("Android binary XML"),
                                FV("Android package resource table (ARSC), 17108 string(s), 19 style(s), utf8"),
                                FV("Certificate, Version=3"),
                                FV("DER Encoded PKCS#7 Signed Data"),
                                FV("Dalvik dex file version 035"),
                                FV("GIF image data, version 89a, 22 x 17"),
                                FV("GIF image data, version 89a, 38 x 26"),
                                FV("HTML document, ASCII text"),
                                FV("ISO-8859 text, with very long lines (376)"),
                                FV("JAR Manifest, ASCII text, with CRLF line terminators"),
                                FV("JAR Signature File, ASCII text, with CRLF line terminators"),
                                FV("JSON text data"),
                                FV("Java KeyStore"),
                                FV("PNG image data"),
                                FV('Targa image data - RLE 1368 x 65536 x 15 +1 +28 ""'),
                                FV('Targa image data - RLE 1392 x 65536 x 15 +1 +28 ""'),
                                FV('Targa image data - RLE 160 x 65536 x 8 +1 +28 ""'),
                                FV('Targa image data - RLE 164 x 65536 x 8 +1 +28 ""'),
                                FV('Targa image data - RLE 1664 x 65536 x 15 +1 +28 ""'),
                                FV('Targa image data - RLE 168 x 65536 x 8 +1 +28 ""'),
                                FV('Targa image data - RLE 176 x 65536 x 8 +1 +28 ""'),
                                FV('Targa image data - RLE 1788 x 65536 x 15 +1 +28 ""'),
                                FV('Targa image data - RLE 184 x 65536 x 8 +1 +28 ""'),
                                FV('Targa image data - RLE 192 x 65536 x 8 +1 +28 ""'),
                                FV('Targa image data - RLE 196 x 65536 x 8 +1 +28 ""'),
                                FV('Targa image data - RLE 208 x 65536 x 8 +1 +28 ""'),
                                FV('Targa image data - RLE 224 x 65536 x 8 +1 +28 ""'),
                                FV('Targa image data - RLE 228 x 65536 x 8 +1 +28 ""'),
                                FV('Targa image data - RLE 252 x 65536 x 15 +1 +28 ""'),
                                FV('Targa image data - RLE 264 x 65536 x 16 +1 +28 ""'),
                                FV('Targa image data - RLE 268 x 65536 x 16 +1 +28 ""'),
                                FV('Targa image data - RLE 276 x 65536 x 16 +1 +28 ""'),
                                FV('Targa image data - RLE 304 x 65536 x 16 +1 +28 ""'),
                                FV('Targa image data - RLE 308 x 65536 x 15 +1 +28 ""'),
                                FV('Targa image data - RLE 308 x 65536 x 16 +1 +28 ""'),
                                FV('Targa image data - RLE 312 x 65536 x 15 +1 +28 ""'),
                                FV('Targa image data - RLE 316 x 65536 x 15 +1 +28 ""'),
                                FV('Targa image data - RLE 324 x 65536 x 16 +1 +28 ""'),
                                FV('Targa image data - RLE 332 x 65536 x 15 +1 +28 ""'),
                                FV('Targa image data - RLE 336 x 65536 x 15 +1 +28 ""'),
                                FV('Targa image data - RLE 336 x 65536 x 16 +1 +28 ""'),
                                FV('Targa image data - RLE 340 x 65536 x 16 +1 +28 ""'),
                                FV('Targa image data - RLE 356 x 65536 x 15 +1 +28 ""'),
                                FV('Targa image data - RLE 36 x 65536 x 1 +1 +28 ""'),
                                FV('Targa image data - RLE 360 x 65536 x 15 +1 +28 ""'),
                                FV('Targa image data - RLE 360 x 65536 x 16 +1 +28 ""'),
                                FV('Targa image data - RLE 376 x 65536 x 15 +1 +28 ""'),
                                FV('Targa image data - RLE 384 x 65536 x 16 +1 +28 ""'),
                                FV('Targa image data - RLE 400 x 65536 x 15 +1 +28 ""'),
                                FV('Targa image data - RLE 44 x 65536 x 1 +1 +28 ""'),
                                FV('Targa image data - RLE 476 x 65536 x 24 +1 +28 ""'),
                                FV('Targa image data - RLE 508 x 65536 x 24 +1 +28 ""'),
                                FV('Targa image data - RLE 524 x 65536 x 24 +1 +28 ""'),
                                FV('Targa image data - RLE 548 x 65536 x 24 +1 +28 ""'),
                                FV('Targa image data - RLE 580 x 65536 x 24 +1 +28 ""'),
                                FV('Targa image data - RLE 592 x 65536 x 24 +1 +28 ""'),
                                FV('Targa image data - RLE 664 x 65536 x 32 +1 +28 ""'),
                                FV('Targa image data - RLE 684 x 65536 x 32 +1 +28 ""'),
                                FV('Targa image data - RLE 700 x 65536 x 32 +1 +28 ""'),
                                FV('Targa image data - RLE 832 x 65536 x 32 +1 +28 ""'),
                                FV('Targa image data - RLE 848 x 65536 x 24 +1 +28 ""'),
                                FV('Targa image data - RLE 852 x 65536 x 32 +1 +28 ""'),
                                FV('Targa image data - RLE 952 x 65536 x 32 +1 +28 ""'),
                                FV(
                                    'TrueType Font data, 14 tables, 1st "GSUB", 17 names, Microsoft, language 0x409, Copyright 2015 The Roboto Mono Project Authors (https://github.com/googlefonts/robotomono)Roboto'
                                ),
                                FV("XML 1.0 document, ASCII text"),
                                FV("data"),
                                FV("gzip"),
                            ],
                            "apk_icon_path": [FV("res/mipmap-anydpi-v26/app_icon.xml")],
                            "apk_intent_filters": [
                                FV("android.hardware.usb.action.USB_DEVICE_ATTACHED"),
                                FV("android.intent.action.ACTION_POWER_CONNECTED"),
                                FV("android.intent.action.ACTION_POWER_DISCONNECTED"),
                                FV("android.intent.action.APPLICATION_PREFERENCES"),
                                FV("android.intent.action.BATTERY_LOW"),
                                FV("android.intent.action.BATTERY_OKAY"),
                                FV("android.intent.action.BOOT_COMPLETED"),
                                FV("android.intent.action.DEVICE_STORAGE_LOW"),
                                FV("android.intent.action.DEVICE_STORAGE_OK"),
                                FV("android.intent.action.GET_CONTENT"),
                                FV("android.intent.action.MAIN"),
                                FV("android.intent.action.MEDIA_BUTTON"),
                                FV("android.intent.action.OPEN_DOCUMENT"),
                                FV("android.intent.action.PICK"),
                                FV("android.intent.action.SEND"),
                                FV("android.intent.action.SEND_MULTIPLE"),
                                FV("android.intent.action.TIMEZONE_CHANGED"),
                                FV("android.intent.action.TIME_SET"),
                                FV("android.intent.action.VIEW"),
                                FV("android.intent.category.BROWSABLE"),
                                FV("android.intent.category.DEFAULT"),
                                FV("android.intent.category.LAUNCHER"),
                                FV("android.intent.category.LEANBACK_LAUNCHER"),
                                FV("android.intent.category.MONKEY"),
                                FV("android.intent.category.OPENABLE"),
                                FV("android.media.browse.MediaBrowserService"),
                                FV("android.net.conn.CONNECTIVITY_CHANGE"),
                                FV("androidx.work.diagnostics.REQUEST_DIAGNOSTICS"),
                                FV("androidx.work.impl.background.systemalarm.UpdateProxies"),
                                FV("com.alphainventor.filemanager.OPEN_SHORTCUT"),
                                FV("com.alphainventor.service.FILEPROGRESSSERVICE"),
                                FV("com.example.android.uamp.open_ui"),
                                FV("filemanager.intent.action.STORAGE_CHECK"),
                                FV("filemanager.intent.videoplayer.action.VIEW_LIST"),
                            ],
                            "apk_libraries": [FV("org.apache.http.legacy")],
                            "apk_main_activity": [FV("com.alphainventor.filemanager.activity.MainActivity")],
                            "apk_package_name": [FV("com.alphainventor.filemanager")],
                            "apk_permissions": [
                                FV("android.permission.ACCESS_NETWORK_STATE"),
                                FV("android.permission.ACCESS_WIFI_STATE"),
                                FV("android.permission.CHANGE_NETWORK_STATE"),
                                FV("android.permission.CHANGE_WIFI_STATE"),
                                FV("android.permission.FOREGROUND_SERVICE"),
                                FV("android.permission.GET_ACCOUNTS"),
                                FV("android.permission.INTERNET"),
                                FV("android.permission.READ_EXTERNAL_STORAGE"),
                                FV("android.permission.RECEIVE_BOOT_COMPLETED"),
                                FV("android.permission.REQUEST_INSTALL_PACKAGES"),
                                FV("android.permission.VIBRATE"),
                                FV("android.permission.WAKE_LOCK"),
                                FV("android.permission.WRITE_EXTERNAL_STORAGE"),
                                FV("com.android.launcher.permission.INSTALL_SHORTCUT"),
                                FV("com.android.vending.BILLING"),
                                FV("com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE"),
                                FV("com.google.android.gms.permission.AD_ID"),
                            ],
                            "apk_sdk_max": [FV("0")],
                            "apk_sdk_min": [FV("21")],
                            "apk_sdk_target": [FV("33")],
                            "apk_signature_hashes": [
                                FV("5df2de091ec62f8ee5502150380665345ada0ffdd608d57c98fab9061dc7b977")
                            ],
                            "apk_signature_types": [FV("7")],
                            "apk_version_code": [FV("2103022")],
                            "apk_version_name": [FV("3.2.2")],
                        },
                    )
                ],
            ),
        )
        expected_file_types = {
            "ASCII text": "83",
            "ASCII text, with no line terminators": "3",
            "Certificate, Version=3": "1",
            "Dalvik dex file version 035": "2",
            "HTML document, ASCII text": "1",
            "PNG image data": "600",
            "gzip": "1",
        }

        file_types = [fv.value for fv in res.events[0].features.pop("apk_file_types")]
        file_type_counts = dict()
        for fv in res.events[0].features.pop("apk_file_count"):
            file_type_counts[fv.value] = fv.label

        for expected_val, expected_label in expected_file_types.items():
            self.assertIn(expected_val, file_types)
            self.assertIn(expected_val, file_type_counts.keys())
            self.assertEqual(
                expected_label,
                file_type_counts[expected_val],
                f"{expected_label} != {file_type_counts.get(expected_val, None)} for val {expected_val}",
            )
