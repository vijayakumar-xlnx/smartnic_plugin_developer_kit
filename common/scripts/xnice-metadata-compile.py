#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2021 Xilinx, Inc.

import sys, argparse, re, json, os, os.path, uuid, collections, subprocess
import array, shutil, struct, tempfile, binascii

MAX_RESOURCE_CLASSES = 1024

def warning(txt):
    print('Warning:', txt.decode(), file=sys.stderr)

def fatal(txt):
    print(txt.decode(), file=sys.stderr)
    sys.exit(1)

_next_unique_id = 1
def unique_id():
    global _next_unique_id
    id = _next_unique_id
    _next_unique_id += 1
    return id

def which(app):
    r = shutil.which(app)
    if not r:
        fatal(b'Cannot find "%s" on PATH' % app.encode())
    return r.encode()

class EbpfFile(object):
    __slots__ = ('ident', 'base_name', 'handler', 'optional', 'cams')
    def __init__(self, base_name, handler, optional=False, cams=[]):
        self.base_name = base_name
        self.handler = handler
        self.optional = optional
        self.cams = cams

def get_ebpf_insns(filename, cams):
    if filename.endswith(b'.c'):
        cflags = os.environ.get('CFLAGS', '').encode()
        try:
            bpf = subprocess.check_output((which('clang'),
                                           b'-target', b'bpf', b'-Wall',
                                           b'-O3') + tuple(cflags.split())
                                           + (b'-o', b'-', b'-c', filename),
                                          universal_newlines=False)
        except subprocess.CalledProcessError:
            sys.exit(1)
    else:
        bpf = open(filename, 'rb').read()
    if bpf.startswith(b'\x7fELF'):
        elf = bpf
        with tempfile.NamedTemporaryFile("rb") as tmp:
            p = subprocess.Popen((which('llvm-objcopy'),
                                   b'--output-target=binary',
                                   b'-j', b'.text', b'-', tmp.name.encode()),
                                  universal_newlines=False,
                                  stdin=subprocess.PIPE)
            p.communicate(bpf)
            # llvm-objcopy clobbered the file, so we need to re-open it in
            # order to read it.
            with open(tmp.name, "rb") as tmp2:
                bpf = tmp2.read()
        if p.returncode:
            fatal(b'%s: llvm-objcopy failed (%d)' % (filename, p.returncode))
        if not bpf:
            fatal(b'%s: Missing "text" section?' % filename)

        if cams:
            p = subprocess.Popen((which('llvm-objdump'),
                                    b'-r', b'-'), universal_newlines=False,
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE)
            out,_ = p.communicate(elf)
            if p.returncode:
                fatal(b'%s: llvm-objdump failed (%d)' %
                      (filename, p.returncode))
            relocs = []
            for line in out.splitlines():
                m = re.match(b'^([0-9a-f]+) R_BPF_64_64 (\w+)$',
                             line, flags=re.I)
                if m is not None:
                    relocs.append((int(m.group(1), 16), m.group(2)))
            for addr,ident in relocs:
                c = [c for c in cams if c.ident == ident]
                if not c:
                    fatal(b'Unknown relocation CAM "%s"' % ident)
                assert (struct.unpack('<Q', bpf[addr:addr+8])[0] & ~0xf00) \
                       == 0x18, \
                       "Relocation should modify a 64-bit load instruction"
                # Apply the relocation itself (ignore the top 32 bits - an
                # ebpf_id will never be that big) and change the src_reg field
                # in the instruction to be 1. This marks the load as special
                # to the eBPF verifier and corresponds to the first 'pseudo
                # load' type implemented in the mcfw. Grep for
                # xbpf_pseudo_load.
                bpf = (bpf[:addr] +
                       struct.pack('<BBHI', 0x18, bpf[addr + 1] | 0x10,
                                   0, c[0].ebpf_id) +
                       bpf[addr+8:])

    if len(bpf) % 8:
        fatal(b'%s: Bad eBPF' % filename)
    return bpf

def get_ebpf_symbol_size(base_src, symname):
        cflags = os.environ.get('CFLAGS', '').encode()
        proc = subprocess.Popen((which('clang'), b'-target', b'bpf', b'-O3')
                                 + tuple(cflags.split())
                                 + (b'-o', b'-', b'-include', base_src,
                                    b'-x', b'c', b'-c', b'-'),
                                universal_newlines=False,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        magic_symbol = b'_712871d973b94ce587daeae5b160df07'   # random
        bpf,_ = proc.communicate(symname + b' ' + magic_symbol + b';')
        if proc.wait():
            fatal(b"Failed to get size of symbol '%s' (%d)"
                  % (symname, proc.returncode))
        proc = subprocess.Popen((which('llvm-nm'), b'-S', b'-g',
                                 b'--defined-only', b'-'),
                                universal_newlines=False,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        out,_ = proc.communicate(bpf)
        if proc.wait():
            fatal(b"llvm-nm failed for symbol '%s' (%d)"
                  % (symname, proc.returncode))
        for line in out.splitlines():
            _,size,typ,name = line.split(maxsplit=3)
            if name == magic_symbol:
                return int(size, 16)
        fatal(b"Internal error getting size of symbol '%s'" % symname)

def gen_ebpf_prog_init(ident, insns):
    if insns is None:
        return b'{.insn = NULL, .ninsn = 0}'
    return b'{.insn = (const struct ebpf_insn*)ebpf_%s, .ninsn = %d}' \
           % (ident, len(insns) // 8)

def gen_ebpf_prog_code(ident, insns):
    if insns is None:
        return b''
    data = array.array('Q', insns)
    if array.array('H', b'\x12\x34')[0] == 0x1234:
        data.byteswap()
    r = b'static const uint64_t ebpf_%s[] = {\n' % ident
    r += b''.join(b'  0x%016x,\n' % v for v in data)
    r += b'};\n\n'
    return r

def for_contained_files(root, handlers, ebpf_files=[]):
    files = set(os.listdir(root))
    done = set()
    for k,v in handlers.items():
        if k in files:
            done.add(k)
            files.remove(k)
            v(os.path.join(root, k))

    for f in ebpf_files:
        names = set(f.base_name + suf for suf in (b'.c', b'.o', b'.ebpf'))
        match = names & files
        files -= names
        if len(match) > 1:
            fatal(b'%s: multiple possibilities for eBPF %s'
                    % (root, f.base_name))
        if match:
            f.handler(get_ebpf_insns(os.path.join(root, match.pop()), f.cams))
        else:
            if not f.optional:
                fatal(b'%s: missing eBPF %s' % (root, f.base_name))
            f.handler(None)

    # Allow people to write notes to themselves:
    files -= set(f for f in files if f.endswith(b'.md'))
    # And use C header files:
    files -= set(f for f in files if f.endswith(b'.h'))
    # And also use CAM configuration blobs made by SDNet:
    files -= set(f for f in files if f.endswith(b'.bin'))
    if files:
        warning(b'%s: Ignored unknown file(s) %s' % (root, b', '.join(files)))
    for k in set(handlers.keys()) - done:
        handlers[k](None)

def opt_dt_int(name, value, default_value=0, format='>I'):
    if value == default_value:
        return []
    return [(name, struct.pack(format, value))]

def opt_cbor_int(dictionary, name, value, default_value=0):
    """Put a field in a dict iff it's not the default_value. For space-saving
    in the output."""
    if value != default_value:
        dictionary[name] = value

class SimpleMetaField(object):
    __slots__ = ('name', 'type', 'default', 'check', 'xlate')
    def __init__(self, name, type, default=None, minval=None, maxval=None,
                 check=None, xlate=None):
        def do_check(val):
            if minval is not None and val < minval:
                return False
            if maxval is not None and val > maxval:
                return False
            return not check or check(val)
        self.name = name
        self.type = type
        self.check = do_check
        self.default = default
        self.xlate = xlate

def load_json_metadata(filename, dest, extra={}):
    """Read and parse the JSON file 'filename'. The JSON document is expected
    to contain just a single dictionary whose keys (and their values' parsing
    rules) is described by dest.simple_fields (a Sequence[SimpleMetaField]).
    Additionally, 'extra' is Dict[str, Callable] and if any JSON keys are
    found with one of those strs then the whole JSON subtree is passed to the
    callable."""
    fields = {f.name:f for f in dest.simple_fields}
    todo = set()
    for f in fields.values():
        if f.default is not None:
            setattr(dest, f.name, f.default)
        else:
            todo.add(f.name)
    if filename is None:
        if any(f.default is None for f in fields.values()):
            fatal(b'%s: not found' % filename)
        return
    data = json.load(open(filename, 'rt'))
    if not isinstance(data, dict):
        fatal(b'%s: must be a JSON dictionary' % filename)
    unknown = set()
    for k,v in data.items():
        if k in extra:
            extra[k](v, filename)
            continue
        f = fields.get(k, None)
        if not f:
            unknown.add(k)
            continue
        if isinstance(v, str):
            v = v.encode()
        if f.xlate:
            v = f.xlate(filename, v)
        if not isinstance(v, f.type):
            fatal(b'%s: %s must be of %r'
                  % (filename, k.encode(), f.type))
        if not f.check(v):
            fatal(b'%s: %s is out of range' % (filename, k))
        setattr(dest, f.name, v)
        todo.discard(f.name)
    if todo:
        fatal(b'%s: missing fields %s' % (filename, ', '.join(todo).encode()))
    if unknown:
        warning(b'%s: ignored unknown fields %s'
                % (filename, ', '.join(unknown).encode()))

def c_escape(s):
    def sub(m):
        return b'0x%02x' % ord(m.group(0))
    return re.sub(b'[^ -\x7f]', sub, s)

class ResourceClass(object):
    simple_fields = [
        SimpleMetaField('mc_extra', int, default=0, minval=0, maxval=256),
        SimpleMetaField('max', int, minval=1, maxval=65536),
    ]
    __slots__ = ('ident', 'dtor_ebpf') \
                + tuple(f.name for f in simple_fields)
    def __init__(self):
        self.ident = unique_id()
        self.max = 0
        self.mc_extra = 0
        self.dtor_ebpf = None
    def load(self, root, cams):
        for_contained_files(root, {
            b'meta.json': lambda root: load_json_metadata(root, self),
        }, [
            EbpfFile(b'dtor',
                     lambda bpf: setattr(self, 'dtor_ebpf', bpf), cams=cams),
        ])

    def gen_c(self):
        return b'''  {
    .max = %(max)d,
    .mc_extra = %(mc_extra)d,
    .dtor = %(dtor_ebpf)s,
  },
''' % {
            b'max': self.max,
            b'mc_extra': self.mc_extra,
            b'dtor_ebpf': gen_ebpf_prog_init(b'%d_dtor' % self.ident,
                                             self.dtor_ebpf),
        }

    def gen_c_static(self):
        return gen_ebpf_prog_code(b'%d_dtor' % self.ident, self.dtor_ebpf)

    def gen_dt(self):
        return (
            opt_dt_int(b'max', self.max)
          + opt_dt_int(b'mc_extra', self.mc_extra)
          + ([(b'dtor', self.dtor_ebpf)] if self.dtor_ebpf else [])
        )

    def gen_cbor(self):
        ret = {}
        opt_cbor_int(ret, 'max_count', self.max)
        opt_cbor_int(ret, 'memory_size_bytes', self.mc_extra)
        if self.dtor_ebpf:
            ret['dtor'] = self.dtor_ebpf
        return ret

def _msg_param_size_xlate(meta_json_path, v):
    if not isinstance(v, bytes):
        return v
    mc_handler = os.path.join(os.path.dirname(meta_json_path),
                              b'mc_handler.c')
    if not os.path.exists(mc_handler):
        fatal(b'mcdi_param_size can only be a symbol when the MC handler is '
              b'provided as C source')
    return get_ebpf_symbol_size(mc_handler, v)

class Message(object):
    simple_fields = [
        SimpleMetaField('name', bytes),
        SimpleMetaField('mcdi_param_size', int, minval=0, maxval=1008,
                        xlate=_msg_param_size_xlate),
    ]
    __slots__ = ('ident', 'id', 'mc_handler') \
                + tuple(f.name for f in simple_fields)
    def __init__(self, id):
        self.ident = unique_id()
        self.id = id
    def load(self, root, cams):
        for_contained_files(root, {
            b'meta.json': lambda root: load_json_metadata(root, self),
        }, [
            EbpfFile(b'mc_handler',
                     lambda bpf: setattr(self, 'mc_handler', bpf), cams=cams),
        ])

    def gen_c(self):
        return b'''  {
    .id = %(id)d,
    .name = "%(name)s",
    .mcdi_param_size = %(mcdi_param_size)d,
    .mc_handler = %(mc_handler)s,
  },
''' % {
            b'id': self.id,
            b'name': c_escape(self.name),
            b'mcdi_param_size': self.mcdi_param_size,
            b'mc_handler': gen_ebpf_prog_init(b'%d_mc' % self.ident,
                                              self.mc_handler),
        }

    def gen_c_static(self):
        return gen_ebpf_prog_code(b'%d_mc' % self.ident, self.mc_handler)

    def gen_dt(self):
        return [
            (b'id', struct.pack('>I', self.id)),
            (b'identifier', self.name),
            (b'mcdi_param_size', struct.pack('>I', self.mcdi_param_size)),
            (b'mc_handler', self.mc_handler),
        ]

    def gen_cbor(self):
        return {
            'id': self.id,
            'name': self.name.decode(),
            'param_size_bytes': self.mcdi_param_size,
            'ebpf': self.mc_handler,
        }

_cam_type_names = {
    "direct": 3,
    "d": 3,
    "dcam": 3,
    "b": 0,
    "bcam": 0,
    "exact": 0,
    "st": 1,
    "stcam": 1,
    "t": 2,
    "tcam": 2,
}

def _cam_type_new_to_old(type):
    return (type + 1) % 4

class Cam(object):
    __slots__ = ('ebpf_id', 'ident', 'type', 'base_address', 'old_config',
                 'config')
    def load(self, data, root):
        if 'base_addr' not in data:
            fatal(b'CAM requires a "base_addr"')
        self.base_address = data['base_addr']

        # If we've only been given base_addr and ident, look for a config blob
        if data.keys() == {'base_addr', 'ident'}:
            self.ident = data.pop('ident').encode()
            configfile = os.path.join(root, self.ident + b'.bin')
            self.config = open(configfile, 'rb').read()
            if len(self.config) == 0:
                fatal(b"CAM config blob provided for %s is empty" % self.ident)
            # Prevent use of this mechanism when DTB output is selected since
            # the blobs will not be compatible
            self.old_config = None
            return

        if 'type' not in data:
            fatal(b'CAM requires a "type"')
        self.type = data['type']
        if isinstance(self.type, str):
            self.type = self.type.lower()
            if self.type not in _cam_type_names:
                fatal(b'Unknown CAM "type" %r' % self.type)
            self.type = _cam_type_names[self.type]
            data['type'] = self.type
        if not isinstance(self.type, int) or not (0 <= self.type < 4):
            fatal(b'Invalid CAM "type" %r' % self.type)

        self.ebpf_id = None
        self.ident = b''
        if 'ebpf_id' in data:
            self.ebpf_id = data.pop('ebpf_id')
        if 'ident' in data:
            self.ident = data.pop('ident').encode()
        if not self.ident and self.ebpf_id is None:
            warning(b'CAM has neither "ident" (recommended) nor "ebpf_id" - it will not be usable from eBPF')

        """
        This is the C structure we're populating, copied from plugin_loader.c:
        typedef struct XilSdnetCamConfigBlobHeader {
          uint32_t Version;   // =1
          uint16_t KeySizeBits;
          uint16_t ResponseSizeBits;
          uint64_t BaseAddr;
          uint32_t NumEntries;
          uint32_t RamFrequencyHz;
          uint32_t LookupFrequencyHz;
          uint32_t LookupsPerSec;
          uint8_t PrioritySizeBits;
          uint8_t NumMasks;
          uint8_t Endian;
          uint8_t MemType;
          uint8_t OptimizationType;
          char FormatString[];
        } XilSdnetCamConfigBlobHeader;

        This format is all very temporary, pending proper SDNet CAM library
        support.
        """
        """
        ...then the type changed again at the same time as we switched to CBOR
        (the change is unrelated, but it makes everyone's lives easier if we
        do all the breaking changes in one go rather than dribbling them out
        (and new-vs-old is easy to distinguish)). This format is documented in
        XN-200372-PS:
        typedef struct __attribute__((packed)) __attribute__((big_endian))
        XilSdnetCamConfigBlobHeader {
          uint32_t config_version;
          uint64_t flags;
          uint8_t mode;
          uint32_t num_entries;
          uint8_t num_masks;
          uint16_t key_size_bits;
          uint16_t response_size_bits;
          uint8_t endian;
          uint8_t mem_type;
          uint8_t optimization_type;
          uint8_t priority_size_bits;
          uint32_t ram_size_kbytes;
          uint32_t ram_frequency_hz;
          uint32_t lookup_frequency_hz;
          uint32_t lookups_per_sec;
          uint16_t format_string_length;
          char format_string[];
        } XilSdnetCamConfigBlobHeader;
        """

        if 'config' in data:
            self.config = binascii.unhexlify(data['config'])
            self.old_config = self.config
            if len(data) > 1:
                warning(b'CAM has extraneous fields beyond "config"')
            if len(self.config) < 37:
                fatal(b'CAM config is too short')
            return

        # The 'old' struct above, used for DTB output
        old_fields = [
            ['version', 'I', 1],
            ['key_size', 'H', None],
            ['response_size', 'H', None],
            ['base_addr', 'Q', None],
            ['num_entries', 'I', None],
            ['ram_hz', 'I', 300000000],
            ['lookup_hz', 'I', 300000000],
            ['lookups_per_sec', 'I', 300000000],
            ['priority_bits', 'B', 255],
            ['num_masks', 'B', 0],
            ['endian', 'B', 1],  # big
            ['mem_type', 'B', 1], # BRAM
            ['optimization_type', 'B', 0], # none
            ['key_fmt', 's', None],
        ]
        # The 'new' struct above, used for CBOR output
        fields = [
            ['version', 'I', (2 << 24) | (0 << 16)],
            ['flags', 'Q', 0],
            ['type', 'B', None],
            ['num_entries', 'I', None],
            ['num_masks', 'B', 0],
            ['key_size', 'H', None],
            ['response_size', 'H', None],
            ['endian', 'B', 1],  # big
            ['mem_type', 'B', 1],  # BRAM
            ['optimization_type', 'B', 0],  # none
            ['priority_bits', 'B', 255],
            ['ram_size_kbytes', 'I', 0],
            ['ram_hz', 'I', 300000000],
            ['lookup_hz', 'I', 300000000],
            ['lookups_per_sec', 'I', 300000000],
            ['key_fmt_len', 'H', None],
            ['key_fmt', 's', None],
        ]
        def get_field_val(name, list=fields):
            for k,t,v in list:
                if k == name:
                    return v
            assert False, "Bad name"
        def set_field_val(name, val, list=fields):
            for f in list:
                if f[0] == name:
                    if f[1] == 's':
                        val = val.encode()
                    elif not isinstance(val, int) or val < 0:
                        fatal(b'CAM field "%s" is invalid' % k.encode())
                    f[2] = val
                    return True
            return False
        def pack(endianness, list):
            def lenof(f):
                if f[1] == 's':
                    return str(len(f[2]))
                return ''
            return struct.pack(endianness +
                                 ''.join(lenof(f) + f[1] for f in list),
                               *(f[2] for f in list))

        for k,v in data.items():
            set_field_val(k, v, list=old_fields)
            if not set_field_val(k, v) and k != 'base_addr':
                warning(b'Ignoring unknown CAM field "%s"' % k.encode())

        key_fmt = get_field_val('key_fmt')
        if get_field_val('key_fmt_len') is None:
            set_field_val('key_fmt_len', len(key_fmt or b'') + 1)

        if any(f[2] is None for f in old_fields + fields):
            fatal(b'CAM is missing field(s) %s' %
                  ','.join(set(f[0] for f in old_fields + fields if f[2] is None)))
        if key_fmt is None:
            fatal(b'CAM missing key_fmt')
        key_fmt_bits = sum(int(x) for x in re.findall(rb'\b(\d+)', key_fmt))
        if get_field_val('key_size') != key_fmt_bits:
            warning(b'CAM key_fmt and key_size do not appear to match (%d != %d)' %
                    key_fmt_bits, get_field_val('key_size'))
        if self.type == 0 and get_field_val('key_size') != 32:
            warning(b'DCAM should have key_size=32')
        warning(b'CAM was specified by individual fields, not by config blob: '
                b'backward compatibility is not at all guaranteed')
        # There's a decent chance that the format of this config blob will
        # change again in the future
        self.old_config = pack('<', old_fields) + b'\0'
        self.config = pack('>', fields) + b'\0'

    def base_addr(self):
        return self.base_address

    def gen_dt(self):
        if self.old_config is None:
            fatal(b"Cannot use CAM config blob when DTB output is selected")
        return [
            (b'ebpf_id', struct.pack('>I', self.ebpf_id)),
            (b'type', struct.pack('>I', _cam_type_new_to_old(self.type))),
            (b'cfg', self.old_config),
        ]

    def gen_cbor(self):
        return {
            'id': self.ebpf_id,
            'base_address': self.base_address,
            'config': self.config,
        }

def _check_mapped_csr_size(n):
    return n == 0 or ((n & (n - 1)) == 0 and 4096 <= n <= 32768)

class Service(object):
    simple_fields = [
        SimpleMetaField('minor_ver', int, minval=0, maxval=0xffff),
        SimpleMetaField('patch_ver', int, minval=0, maxval=0xffff),
        SimpleMetaField('reg_win_size', int, minval=0, maxval=8*1024*1024),
        SimpleMetaField('mc_extra', int, default=0, minval=0, maxval=4096),
        SimpleMetaField('handle_extra', int, default=0, minval=0, maxval=256),
        SimpleMetaField('mapped_csr_base', int, default=0,
                                           minval=0, maxval=0xffffffff),
        SimpleMetaField('mapped_csr_size', int, default=0,
                                           check=_check_mapped_csr_size),
        SimpleMetaField('mapped_csr_flags', int, default=0,
                                            minval=0, maxval=7),
    ]
    __slots__ = (('ident', 'uuid', 'messages', 'resource_classes', 'cams',
                  'init_ebpf')
                 + tuple(f.name for f in simple_fields))
    def __init__(self, id):
        assert isinstance(id, uuid.UUID)
        self.ident = unique_id()
        self.uuid = id

    def _load_messages(self, root):
        if root is None:
            return
        dups = collections.defaultdict(int)
        for f in os.listdir(root):
            try:
                id = int(f, 0)
            except ValueError:
                fatal(b'All messages must have an int-like name ("%s")' % f)
            if id < 0 or id > 0xffffffff:
                fatal(b'Message ID %d out of range' % id)
            dups[id] += 1
            msg = Message(id)
            msg.load(os.path.join(root, f), self.cams)
            self.messages.append(msg)

        for k,v in dups.items():
            if v > 1:
                fatal(b'Duplicate message ID %d' % k)
        
        self.messages.sort(key=lambda m: m.id)

    def _load_resource_classes(self, root):
        if root is None:
            return
        rcs = [None] * MAX_RESOURCE_CLASSES
        dups = collections.defaultdict(int)
        for f in os.listdir(root):
            try:
                id = int(f, 0)
            except ValueError:
                fatal(b'All resource classes must have an int-like name ("%s")'
                      % f)
            if id < 0 or id >= MAX_RESOURCE_CLASSES:
                fatal(b'resource class ID %d out of range' % id)
            dups[id] += 1
            rc = ResourceClass()
            rc.load(os.path.join(root, f), self.cams)
            rcs[id] = rc

        for k,v in dups.items():
            if v > 1:
                fatal(b'Duplicate resource class ID %d' % k)
        
        while rcs and rcs[-1] is None:
            rcs.pop()
        if any(rc is None for rc in rcs):
            warning(b'Gaps in resource class numbering: '
                    % b', '.join(str(i).encode()
                                 for i,v in enumerate(rcs) if v is None))
        for i in range(len(rcs)):
            if rcs[i] is None:
                rcs[i] = ResourceClass()
        self.resource_classes = rcs

    def _load_cams(self, data, filename):
        if not isinstance(data, list):
            fatal(b'"cams" subelement must be an array')
        CAM_CSR_SIZE = 8192   # Embedded in SDNet implementation
        ids = set()
        for v in data:
            c = Cam()
            c.load(v, os.path.dirname(filename))
            id = getattr(c, 'ebpf_id', None)
            if id is not None:
                if id in ids:
                    fatal(b'Duplicate CAM ebpf_id %d' % id)
                ids.add(id)
            if any(c.base_addr() + CAM_CSR_SIZE > c2.base_addr() and
                   c.base_addr() < c2.base_addr() + CAM_CSR_SIZE
                   for c2 in self.cams):
                fatal(b'CAMs have overlapping CSR windows')
            self.cams.append(c)

        # Sequentially allocate an ebpf_id to any CAMs which didn't specify
        # their own
        ebpf_id = 0
        for c in self.cams:
            id = getattr(c, 'ebpf_id', None)
            if id is None:
                while ebpf_id in ids:
                    ebpf_id += 1
                c.ebpf_id = ebpf_id
                ebpf_id += 1

    def load(self, root):
        self.messages = []
        self.resource_classes = []
        self.cams = []
        for_contained_files(root, collections.OrderedDict([
            (b'meta.json', lambda root: load_json_metadata(root, self,
                                            extra={'cams': self._load_cams})),
            (b'messages', lambda root: self._load_messages(root)),
            (b'resource_classes', lambda root:
                                  self._load_resource_classes(root)),
        ]), [
            EbpfFile(b'init', lambda bpf: setattr(self, 'init_ebpf', bpf),
                     optional=True, cams=self.cams),
        ])
        if self.mapped_csr_size:
            if self.mapped_csr_base < self.reg_win_size:
                warning('Mapped CSR window overlaps configuration CSR window. '
                        + 'This is likely a security vulnerability')
            if (self.mapped_csr_flags & 3) == 0:
                warning('CSR window mapping declared but neither read nor '
                        + 'write permission flags are set')
            if (self.mapped_csr_base + self.mapped_csr_size > 65536 and
                self.mapped_csr_base < 65536*1024):
                warning('Mapped CSR window has bits in common with qid; '
                        + 'this will likely make the plugin see incorrect '
                        + 'information')
            if self.mapped_csr_base > 7 << 26:
                warning('Mapped CSR window will overflow HAH bar_id')

    def gen_c(self):
        return b'''  {
    .uuid = {%(uuid)s},
    .minor_ver = %(minor_ver)d,
    .patch_ver = %(patch_ver)d,
    .nmsgs = sizeof(%(msgs)s) / sizeof(%(msgs)s[0]),
    .nrsrc_classes = sizeof(%(rcs)s) / sizeof(%(rcs)s[0]),
    .msgs = %(msgs)s,
    .rsrc_classes = %(rcs)s,
    .reg_win_size = %(reg_win_size)d,
    .mc_extra = %(mc_extra)d,
    .handle_extra = %(handle_extra)d,
    .init = %(init)s,
  },
''' % {
            b'uuid': b', '.join(b'0x%02x' % b for b in self.uuid.bytes),
            b'minor_ver': self.minor_ver,
            b'patch_ver': self.patch_ver,
            b'msgs': b'msgs_%d' % self.ident,
            b'rcs': b'rcs_%d' % self.ident,
            b'reg_win_size': self.reg_win_size,
            b'mc_extra': self.mc_extra,
            b'handle_extra': self.handle_extra,
            b'init': gen_ebpf_prog_init(b'%d_init' % self.ident,
                                        self.init_ebpf),
        }

    def gen_c_static(self):
        r = b''
        for m in self.messages:
            r += m.gen_c_static()
        for rc in self.resource_classes:
            r += rc.gen_c_static()

        r += b'static sp_msg_t msgs_%d[] = {\n' % self.ident
        r += b'\n'.join(m.gen_c() for m in self.messages)
        r += b'};\n\n'

        r += b'static sp_rsrc_class_t rcs_%d[] = {\n' % self.ident
        r += b'\n'.join(rc.gen_c() for rc in self.resource_classes)
        r += b'};\n\n'

        r += gen_ebpf_prog_code(b'%d_init' % self.ident, self.init_ebpf)
        return r

    def gen_dt(self):
        return ([
            (b'uuid', self.uuid.bytes),
            (b'minor_ver', struct.pack('>H', self.minor_ver)),
            (b'patch_ver', struct.pack('>H', self.patch_ver)),
        ] + opt_dt_int(b'reg_win_size', self.reg_win_size)
          + opt_dt_int(b'mc_extra', self.mc_extra)
          + opt_dt_int(b'handle_extra', self.handle_extra)
          + opt_dt_int(b'mapped_csr_base', self.mapped_csr_base)
          + opt_dt_int(b'mapped_csr_size', self.mapped_csr_size)
          + opt_dt_int(b'mapped_csr_flags', self.mapped_csr_flags, format='>B')
          + ([(b'init', self.init_ebpf)] if self.init_ebpf else []) + [
            (b'msg', [m.gen_dt() for m in self.messages])]
          + ([(b'rc', [c.gen_dt() for c in self.resource_classes])]
                                             if self.resource_classes else [])
          + ([(b'cam', [c.gen_dt() for c in self.cams])] if self.cams else [])
        )

    def gen_cbor(self):
        ret = {
            'version_info': {
                'uuid': self.uuid.bytes,
                'minor': self.minor_ver,
                'patch': self.patch_ver,
            },
            'address_mapping': {
                'offset': 0,
                'aperture_size_bytes': self.reg_win_size,
            },
        }
        opt_cbor_int(ret, 'global_memory_size_bytes', self.mc_extra)
        opt_cbor_int(ret, 'per_handle_memory_size_bytes', self.handle_extra)
        if self.init_ebpf:
            ret['setup'] = {'ebpf':self.init_ebpf}
        if self.messages:
            ret['messages'] = [m.gen_cbor() for m in self.messages]
        if self.resource_classes:
            ret['resource_classes'] = [c.gen_cbor()
                                     for c in self.resource_classes]
        if self.cams:
            ret['cam_instances'] = [c.gen_cbor() for c in self.cams]
        return ret


class Metadata(object):
    __slots__ = ('services')
    def _load_services(self, root):
        if root is None:
            fatal(b'Require an "extensions" subdirectory')
        dups = collections.defaultdict(int)
        for f in os.listdir(root):
            try:
                id = uuid.UUID(f.decode())
            except ValueError:
                fatal(b'All services must have a UUID-like name ("%s")' % f)
            dups[id] += 1
            svc = Service(id)
            svc.load(os.path.join(root, f))
            self.services.append(svc)

        for k,v in dups.items():
            if v > 1:
                fatal(b'Duplicate service ID %s' % str(k).encode())

        self.services.sort(key=lambda s:s.uuid)

    def load(self, root):
        self.services = []
        old_name = os.path.exists(os.path.join(root, b'services'))
        new_name = os.path.exists(os.path.join(root, b'extensions'))
        if old_name and new_name:
            fatal(b'Mixture of old and new "extensions" directories')
        dir_name = b'services' if old_name else b'extensions'
        for_contained_files(root, {
            dir_name: lambda root: self._load_services(root),
        })

    def gen_c(self):
        r = b''
        for s in self.services:
            r += s.gen_c_static()

        r += b'static sp_svc_t plugin_svcs[] = {\n'
        r += b'\n'.join(s.gen_c() for s in self.services)
        return r + b'''
};

sp_meta_t current_plugin_metadata = {
    .svcs = plugin_svcs,
    .nsvcs = sizeof(plugin_svcs) / sizeof(plugin_svcs[0]),
};

'''
    def gen_dt(self):
        return [(b'svc', [s.gen_dt() for s in self.services])]

    def gen_cbor(self):
        # The spec requires that schema_version is at the top
        return collections.OrderedDict([
            ('schema_version', {
                'major':1,
                'minor':0,
                'patch':0,
            }),
            ('extensions', [s.gen_cbor() for s in self.services]),
        ])


def pad_align(data, align):
    align -= 1
    return (data + b'\0' * align)[:(len(data) + align) & ~align]

def dt2dtb(dt):
    # Use "dtc -I dtb -O dts <filename>" to view the output
    str_ids = {}
    strs = bytearray()
    props = bytearray()
    def gen_strs(root):
        for k,v in root:
            if isinstance(v, list):
                for x in v:
                    gen_strs(x)
            if k not in str_ids:
                str_ids[k] = len(strs)
                strs.extend(k + b'\0')
    def gen(root, name):
        props.extend(struct.pack('>I', 1)) # FDT_BEGIN_NODE
        props.extend(pad_align(name, 4))
        for k,v in root:
            if isinstance(v, list):
                props.extend(struct.pack('>I', 1)) # FDT_BEGIN_NODE
                props.extend(pad_align(k + b'\0', 4))
                for i,x in enumerate(v):
                    gen(x, str(i).encode())
                props.extend(struct.pack('>I', 2))  # FDT_END_NODE
            else:
                props.extend(struct.pack('>III', 3, len(v), str_ids[k]))
                props.extend(pad_align(v, 4))
        props.extend(struct.pack('>I', 2))  # FDT_END_NODE
    gen_strs(dt)
    strs = pad_align(strs, 4)
    gen(dt, b'xilinx-smartnic-plugin')
    props.extend(struct.pack('>I', 9))  # FDT_END
    hdr_len = 40 + 16
    hdr = struct.pack('>10IQQ', 0xd00dfeed, hdr_len + len(props) + len(strs),
                      hdr_len, hdr_len + len(props), 40, 17, 16, 0, len(strs),
                      len(props), 0, 0)
    return hdr + props + strs

def cbor_encode(root):
    # There are several perfectly fine CBOR libraries available for Python. We
    # use none of them, since this script is going to get published and thus
    # writing 50 easy lines is significantly preferable to dealing with
    # an additional dependency
    data = bytearray()
    def gen_item(type, n):
        nonlocal data
        type <<= 5
        if n < 24:
            data.append(type | n)
        elif n < 256:
            data.append(type | 24)
            data.append(n)
        elif n < 65536:
            data.append(type | 25)
            data += struct.pack('>H', n)
        elif n < 2**32:
            data.append(type | 26)
            data += struct.pack('>I', n)
        elif n < 2**64:
            data.append(type | 27)
            data += struct.pack('>Q', n)
        else:
            assert False, "not supported"

    def gen(root):
        nonlocal data
        if isinstance(root, int):
            if root >= 0:
                gen_item(0, root)
            else:
                gen_item(1, -1 - root)
        elif isinstance(root, bytes):
            gen_item(2, len(root))
            data += root
        elif isinstance(root, str):
            root = root.encode()
            gen_item(3, len(root))
            data += root
        elif isinstance(root, list):
            gen_item(4, len(root))
            for v in root:
                gen(v)
        elif isinstance(root, dict):
            gen_item(5, len(root))
            for k,v in root.items():
                gen(k)
                gen(v)
        else:
            assert False, "unsupported type " + repr(root)

    gen(root)
    return data

def json_encode(root):
    def hexlify(root):
        if isinstance(root, list):
            for i in range(len(root)):
                if isinstance(root[i], bytes):
                    root[i] = root[i].hex()
                else:
                    hexlify(root[i])
        elif isinstance(root, dict):
            for k in root:
                v = root[k]
                if isinstance(v, bytes):
                    root[k] = v.hex()
                else:
                    hexlify(v)
    hexlify(root)
    return json.dumps(root).encode()

def compile(root, fmt):
    data = Metadata()
    data.load(root)
    if fmt == 'c':
        hdr = b'''/* Automatically generated. Do not edit. */
/*#include "slice_plugin.h"*/

'''
        return hdr + data.gen_c()
    if fmt == 'dtb':
        return dt2dtb(data.gen_dt())
    if fmt == 'cbor':
        return cbor_encode(data.gen_cbor())
    if fmt == 'json':
        return json_encode(data.gen_cbor())

parser = argparse.ArgumentParser()
parser.add_argument('--format', '-f', choices=('c','dtb','cbor', 'json'),
                    default='dtb')
parser.add_argument('--output', '-o')
parser.add_argument('root')
args = parser.parse_args()

if __name__ == '__main__':
    data = compile(args.root.encode(), args.format)
    if args.output:
        open(args.output, 'wb').write(data)
    else:
        sys.stdout.buffer.write(data)
