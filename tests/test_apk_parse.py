import unittest

from azul_runner.test_utils import FileManager

from azul_plugin_android_parser.apk_parse import ApkParse, SdkBuildInfo


class TestApkParse(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.file_manager = FileManager()

    def test_apk_load(self):
        """Validate apks can be loaded."""
        # Gustuff android malware file.
        unwrapped = self.file_manager.download_file_bytes(
            "7c33a3c691d9e0648f1a10e0f518ba208cab1430b1bf80c06bc1ca26971b973d"
        )
        data = unwrapped
        self.assertTrue(isinstance(data, bytes))

        apk_object = ApkParse(data)
        self.assertTrue(apk_object.load_apk())

    def test_apk_process_meta(self):
        """Regression test to validate meta can be processed."""
        # APK Trojan malware file
        data = self.file_manager.download_file_bytes(
            "4d599226cbc3e0d61a311bf368d5088221f5c62bbfc03516dfdba93b92a04a22"
        )
        apk_object = ApkParse(data)
        apk_object.load_apk()
        apk_meta = apk_object.process_apk_meta()
        # Check a subset of the result is equal to keep it smaller.
        self.assertEqual(apk_meta.app_name, "Google Protect")
        self.assertEqual(apk_meta.package_name, "com.jmsrmxkjgz.rvkenjpe")
        self.assertEqual(apk_meta.main_activity, "com.hytxiegabfs.ymgbjnu.fopehx.iDZBIzoIqo")
        self.assertCountEqual(
            apk_meta.permissions_literal,
            [
                "android.permission.ACCESS_NETWORK_STATE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.RECORD_AUDIO",
                "android.permission.CALL_PHONE",
                "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.GET_TASKS",
                "android.permission.READ_PHONE_STATE",
                "android.permission.WRITE_SMS",
                "android.permission.PACKAGE_USAGE_STATS",
                "android.permission.RECEIVE_SMS",
                "android.permission.INTERNET",
                "android.permission.READ_CONTACTS",
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.WAKE_LOCK",
            ],
        )
        self.assertEqual(apk_meta.sdk_build_info, SdkBuildInfo(target=27, min=15, max=0))
        self.assertEqual(apk_meta.signature_version, 3)
