import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("prepare_fusion", HERE / "prepare_fusion.py")
fusion = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fusion)
import package_ova


class FusionCompanion(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.manager = self.root / "vmware-vdiskmanager"
        self.manager.write_text("unit-test tool placeholder")
        self.bundle = self.root / "Standalone-ARM64.vmwarevm"
        disk = self.root / "source.vmdk"
        header = bytearray(512)
        struct.pack_into("<IIIQ", header, 0, 0x564D444B, 3, 0x10000, 2048)
        struct.pack_into("<QQ", header, 28, 1, 1)
        descriptor = b'createType="streamOptimized"\nRW 2048 SPARSE "source.vmdk"\nddb.adapterType="lsilogic"\n'
        disk.write_bytes(header + descriptor + bytes(512 - len(descriptor)))
        manifest = self.root / "guest.json"
        manifest.write_text(json.dumps({"architecture": "arm64", "appliance_type": "standalone-overlay",
            "guest_architecture_evidence": {"dpkg_architecture": "arm64", "python_elf_machine": 183,
                "efi_fallback": {"pe_machine": 0xaa64, "path": "/boot/efi/EFI/BOOT/BOOTAA64.EFI", "sha256": "a" * 64}}}))
        result = package_ova.package(disk, self.root, "0.1.6", manifest,
                                     family="standalone-overlay", architecture="arm64")
        self.ova = self.root / result["ova"]

    def tearDown(self):
        self.temp.cleanup()

    def tool_contract(self, command):
        if command[0] == str(self.manager):
            self.assertEqual(command[1:2], ["-r"])
            self.assertEqual(command[3:5], ["-t", "0"])
            Path(command[-1]).write_bytes(b"converted sparse VMDK fixture")
            return "conversion complete"
        self.assertEqual(command[0], "qemu-img-test")
        if command[1] == "info":
            return json.dumps({"virtual-size": 1024 ** 2})
        self.assertEqual(command[1:6], ["compare", "-f", "vmdk", "-F", "vmdk"])
        return "Images are identical."

    def test_verified_conversion_contract_publishes_bound_pristine_vmx(self):
        with mock.patch.object(fusion, "run", side_effect=self.tool_contract) as tool:
            result = fusion.prepare(self.ova, self.bundle, self.manager, "qemu-img-test")
        self.assertEqual(tool.call_count, 4)
        self.assertEqual(result["source_ova_sha256"], package_ova.sha256(self.ova))
        self.assertEqual(result["source_disk_sha256"], package_ova.sha256(self.root / "source.vmdk"))
        self.assertEqual(result["disk_sha256"], package_ova.sha256(self.bundle / "boot.vmdk"))
        self.assertEqual(result["conversion"]["qemu_img_sector_compare"], "passed")
        self.assertIn("pending", result["hypervisor_acceptance"])
        vmx = (self.bundle / "appliance.vmx").read_text()
        self.assertIn('guestOS = "arm-other5xlinux-64"', vmx)
        self.assertIn('firmware = "efi"', vmx)
        self.assertIn('nvme0:0.fileName = "boot.vmdk"', vmx)
        for slot in range(3):
            self.assertIn(f'ethernet{slot}.virtualDev = "vmxnet3"', vmx)
            self.assertIn(f'ethernet{slot}.startConnected = "FALSE"', vmx)
        self.assertNotIn("ethernet3.", vmx)
        self.assertNotIn("uuid.bios", vmx)
        self.assertNotIn("generatedAddress =", vmx)
        self.assertEqual(list(self.root.glob("standalone-fusion-disk-*")), [])

    def test_wrong_capacity_or_failed_sector_comparison_never_publishes_vmx(self):
        for failure in ("capacity", "sectors"):
            with self.subTest(failure=failure):
                bundle = self.root / f"Failure-{failure}.vmwarevm"
                def fail(command):
                    if failure == "capacity" and command[1] == "info":
                        return json.dumps({"virtual-size": 512})
                    if failure == "sectors" and command[1] == "compare":
                        raise RuntimeError("Images differ")
                    return self.tool_contract(command)
                with mock.patch.object(fusion, "run", side_effect=fail):
                    with self.assertRaises((ValueError, RuntimeError)):
                        fusion.prepare(self.ova, bundle, self.manager, "qemu-img-test")
                self.assertFalse((bundle / "appliance.vmx").exists())
                self.assertFalse((bundle / "fusion-provenance.json").exists())

    def test_existing_bundle_is_preserved_without_running_a_tool(self):
        self.bundle.mkdir()
        original = self.bundle / "personal-data.txt"
        original.write_text("preserve me")
        with mock.patch.object(fusion, "run") as tool:
            with self.assertRaisesRegex(ValueError, "already exists"):
                fusion.prepare(self.ova, self.bundle, self.manager)
        tool.assert_not_called()
        self.assertEqual(original.read_text(), "preserve me")

    def test_tampered_archive_is_rejected_before_conversion(self):
        data = self.ova.read_bytes().replace(b'ddb.adapterType="lsilogic"', b'ddb.adapterType="badtype!"')
        self.ova.write_bytes(data)
        with mock.patch.object(fusion, "run") as tool:
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                fusion.prepare(self.ova, self.bundle, self.manager)
        tool.assert_not_called()
        self.assertFalse(self.bundle.exists())

    def test_source_change_after_validation_is_rejected(self):
        original = fusion.validate
        def changing(path, expected_architecture):
            result = original(path, expected_architecture)
            result["member_sha256"]["source.vmdk"] = "0" * 64
            return result
        with mock.patch.object(fusion, "validate", side_effect=changing), mock.patch.object(fusion, "run") as tool:
            with self.assertRaisesRegex(ValueError, "changed after archive validation"):
                fusion.prepare(self.ova, self.bundle, self.manager)
        tool.assert_not_called()
        self.assertFalse((self.bundle / "appliance.vmx").exists())

    def test_container_verification_has_no_network_and_read_only_mounts(self):
        with mock.patch.object(fusion.shutil, "which", side_effect=lambda name: "/usr/local/bin/docker" if name == "docker" else None):
            command = fusion.qemu_command(["compare", str(self.root / "source.vmdk"), str(self.bundle / "boot.vmdk")],
                                           self.root, self.bundle)
        self.assertEqual(command[:8], ["/usr/local/bin/docker", "run", "--rm", "--pull", "never", "--network", "none", "--entrypoint"])
        self.assertIn(f"{self.root}:/input:ro", command)
        self.assertIn(f"{self.bundle}:/bundle:ro", command)
        self.assertEqual(command[-2:], ["/input/source.vmdk", "/bundle/boot.vmdk"])

    def test_vmx_name_cannot_inject_configuration(self):
        with self.assertRaisesRegex(ValueError, "bundle name"):
            fusion.vmx_bytes('name"\nfirmware = "bios')

    def test_native_fusion_gui_monitor_defaults_are_explicit(self):
        # The live Fusion 13.6.2 GUI rejected VMCLI's omitted one-display
        # defaults even while headless screenshots worked. Literal numDisplays
        # and disabled autodetect together made the wizard receive GUI input.
        vmx = fusion.vmx_bytes("Native-GUI-Regression").decode()
        settings = dict(line.split(" = ", 1) for line in vmx.splitlines())
        self.assertEqual(settings["svga.numDisplays"], '"1"')
        self.assertEqual(settings["svga.autodetect"], '"FALSE"')
        self.assertEqual(settings["svga.present"], '"TRUE"')


if __name__ == "__main__":
    unittest.main()
