#!/usr/bin/env python3
import sys, argparse, subprocess, tempfile, shutil, uuid, os.path

# This is a minimal somewhat-valid xclbin file
# It was created by taking a real xclbin file and using xclbinutil to remove
# all but the BITSTREAM and CLOCK_FREQ_TOPOLOGY sections. The BITSTREAM was
# then further extracted, truncated and hand-munged with a hex editor to make
# it shorter, and re-embedded.
# None of this was strictly necessary, but it makes everybody's life simpler
# if we don't have a multi-megabyte template file full of cruft.
template = b'xclbin2\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\n\xa0\xe5]\x00\x00\x00\x00\xc2\x08\x00\x00\x00\x00\x00\x00\n\xa0\xe5]\x00\x00\x00\x00\xc3\xdd\xd3]\x00\x00\x00\x00m\x08\x02\x02\x01\x00\x00\x00]\x19u\xff\xafqI\xd0\xa6\x91\xcb,d\x82;\xaaxilinx_poc1465_snic-sf_201910_15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x9a)\xca\x1a\xe5D\xd3\xac3\xc9>\xff\xeb\xf5<\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00bar2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x02\x00\x00\x00\x00\x00\x00\xfd\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00echo_xml\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x18\x03\x00\x00\x00\x00\x00\x00\x8a\x00\x00\x00\x00\x00\x00\x00\x00\t\x0f\xf0\x0f\xf0\x0f\xf0\x0f\xf0\x00\x00\x01a\x00Vsmartnic_platform_wrapper;COMPRESS=TRUE;PARTIAL=TRUE;UserID=0XFFFFFFFF;Version=2019.1\x00b\x00\x15xcvu9p-flgc2104-2L-e\x00c\x00\x0b2019/12/02\x00d\x00\t15:35:58\x00e\x00\x00\x00`Fake! This is bogus data, solely to make the file look valid to the xclbin parser in firmware.\x00\x00\x00\x00\x00\x01\x00\xfa\x00\x01\x00\x00\x00\x00\x00DATA_CLK\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00XCLBIN_MIRROR_DATA_START{"schema_version":{"major":"1","minor":"0","patch":"0"},"header":{"Magic":"xclbin2","Cipher":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","KeyBlock":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","UniqueID":"0aa0e55d00000000","TimeStamp":"1575329802","FeatureRomTimeStamp":"1574165955","Version":"2.2.2157","Mode":"1","FeatureRomUUID":"5d1975ffaf7149d0a691cb2c64823baa","PlatformVBNV":"xilinx_poc1465_snic-sf_201910_15","XclBinUUID":"089a29ca1ae544d3ac33c93effebf53c","DebugBin":""},"section_header":{"Kind":"0","Name":"bar2","Offset":"0x218","Size":"0xfd"},"section_header":{"Kind":"11","Name":"echo_xml","Offset":"0x318","Size":"0x8a","payload":{"clock_freq_topology":{"m_count":"1","m_clock_freq":{"clock_freq":{"m_freq_Mhz":"250","m_type":"DATA","m_name":"DATA_CLK"}}}}}}\nXCLBIN_MIRROR_DATA_END'
template_uuid = uuid.UUID('5d1975ff-af71-49d0-a691-cb2c64823baa')

parser = argparse.ArgumentParser(description='Create a xclbin suitable for '
                                 'the rhsim C model from DTB metadata')
parser.add_argument('--uuid', type=uuid.UUID,
                    default='00112233-4455-6677-8899-aabbccddeeff',
                    help='UUID of the shell, to match rhsim --uuid')
parser.add_argument('input_dtb')
parser.add_argument('output_xclbin')
args = parser.parse_args()

xclbinutil = shutil.which('xclbinutil')
if xclbinutil is None:
    xclbinutil = '/tools/xilinx/SDx/2019.1/bin/xclbinutil'
    if not os.path.isfile(xclbinutil):
        xclbinutil = '/proj/xbuilds/2020.1.1_released/installs/lin64/Vitis/2020.1/bin/xclbinutil'
        if not os.path.isfile(xclbinutil):
            print('Cannot locate xclbinutil on the PATH', file=sys.stderr)
            sys.exit(1)

if open(args.input_dtb, 'rb').read(4) != b'\xd0\x0d\xfe\xed':
    print('Input file does not appear to be a DTB', file=sys.stderr)
    sys.exit(1)

tmp = tempfile.mkdtemp()
try:
    template = template.replace(template_uuid.bytes, args.uuid.bytes)
    template_file = tmp + '/tmp.xclbin'
    open(tmp + '/tmp.xclbin', 'wb').write(template)
    rc = subprocess.call((xclbinutil, '--add-section',
                          'USER_METADATA:RAW:' + args.input_dtb, '-q',
                          '--force', '-i', template_file, '-o',
                          args.output_xclbin),
                         env={'LC_ALL':'C'})
finally:
    shutil.rmtree(tmp, ignore_errors=True)
sys.exit(rc)
