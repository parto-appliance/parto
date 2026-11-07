import hashlib
import importlib.util
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('repackage_vmware', Path(__file__).resolve().parents[1] / 'repackage_vmware.py')
pkg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pkg)


class Repackage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / 'parto-0.10.14-amd64.ova'
        self.output = self.root / 'parto-0.10.14-amd64-vmware-r1.ova'
        self.disk = self.root / 'native.vmdk'
        self.disk.write_bytes(self.vmdk_bytes(self.output.stem + '-disk.vmdk'))
        self.descriptor = ('<ovf:Envelope xmlns:ovf="' + pkg.OVF + '"><ovf:References><ovf:File ovf:href="source.vmdk" ovf:size="1024"/></ovf:References><ovf:VirtualSystem><ovf:Name>Parto 0.10.14</ovf:Name></ovf:VirtualSystem></ovf:Envelope>').encode()
        self.make_source()

    @staticmethod
    def vmdk_bytes(name):
        header = bytearray(512)
        struct.pack_into('<IIIQ', header, 0, 0x564d444b, 3, 0x30001, 2048)
        struct.pack_into('<QQ', header, 28, 1, 1)
        descriptor = ('RW 2048 SPARSE "' + name + '"\n').encode()
        return header + descriptor.ljust(512, b'\x00')

    def tearDown(self):
        self.temp.cleanup()

    def make_source(self, bad_hash=False, extra=None):
        files = {'source.ovf': self.descriptor, 'source.vmdk': self.vmdk_bytes('source.vmdk')}
        files['source.mf'] = ''.join('SHA256(' + n + ')= ' + ('0' * 64 if bad_hash else hashlib.sha256(b).hexdigest()) + '\n' for n, b in files.items()).encode()
        with tarfile.open(self.source, 'w') as archive:
            for name, data in files.items():
                import io
                member = tarfile.TarInfo(name); member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            if extra:
                archive.addfile(tarfile.TarInfo(extra))

    def test_new_package_has_verified_manifest_and_preserves_source(self):
        original = pkg.digest(self.source)
        with mock.patch.object(pkg, 'compare', return_value='Images are identical.'):
            result = pkg.repackage(self.source, self.output, self.disk)
        self.assertEqual(pkg.digest(self.source), original)
        self.assertEqual(result['guest_version'], '0.10.14')
        self.assertEqual(result['guest_sector_comparison'], 'Images are identical.')
        with tarfile.open(self.output) as archive:
            descriptor = archive.extractfile(self.output.stem + '.ovf').read()
            expected = self.descriptor.replace(b'source.vmdk', (self.output.stem + '-disk.vmdk').encode())
            self.assertEqual(descriptor, expected)
        self.assertTrue(self.output.with_suffix('.ova.sha256').read_text().startswith(pkg.digest(self.output)))

    def test_mismatched_source_hash_prevents_publication(self):
        self.make_source(bad_hash=True)
        with mock.patch.object(pkg, 'compare') as compare:
            with self.assertRaisesRegex(ValueError, 'manifest mismatch'):
                pkg.repackage(self.source, self.output, self.disk)
        compare.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_extra_or_traversal_member_is_rejected(self):
        self.make_source(extra='../escape')
        with self.assertRaisesRegex(ValueError, 'three unique regular'):
            pkg.repackage(self.source, self.output, self.disk)
        self.assertFalse((self.root.parent / 'escape').exists())

    def test_changed_guest_sectors_prevent_publication(self):
        with mock.patch.object(pkg, 'compare', side_effect=RuntimeError('Images differ')):
            with self.assertRaisesRegex(RuntimeError, 'Images differ'):
                pkg.repackage(self.source, self.output, self.disk)
        self.assertFalse(self.output.exists())

    def test_embedded_extent_name_must_match_packaged_disk(self):
        self.disk.write_bytes(self.vmdk_bytes('wrong-name.vmdk'))
        with self.assertRaisesRegex(ValueError, 'extent must match'):
            pkg.repackage(self.source, self.output, self.disk)
        self.assertFalse(self.output.exists())

    def test_existing_artifact_is_never_overwritten(self):
        self.output.write_bytes(b'existing immutable artifact')
        with self.assertRaises(ValueError):
            pkg.repackage(self.source, self.output, self.disk)
        self.assertEqual(self.output.read_bytes(), b'existing immutable artifact')


if __name__ == '__main__':
    unittest.main()
